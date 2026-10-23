use crate::Parameters;
use crate::additiveFFT::AdditiveFFT;
use crate::galoisField::GaloisField;
use alloc::vec::Vec;

/// The shortened Reed-Solomon code over GF(2^8) of one parameter set, `reed_solomon.c` of the
/// reference code: a message of `k` bytes and `2 delta` parity bytes, `n1` bytes in all.
///
/// The decoder has no branch and no table index that depends on the received word, as in the C
/// code, and decodes every word of the right length, also one with more errors than it can
/// correct.
pub(crate) struct ReedSolomon<'parameters> {
    parameters: &'parameters Parameters,
}

/// The largest correction capacity `delta` of the parameter sets, 29 for HQC-5.
const largestCorrectionCapacity: usize = 29;

/// The coefficients of the error locator polynomial that the FFT takes, `2^PARAM_FFT` at most.
const locatorSlots: usize = 32;

impl<'parameters> ReedSolomon<'parameters> {
    /// Makes the code of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        ReedSolomon { parameters }
    }

    /// The number of parity bytes, `2 delta`.
    fn parityLength(&self) -> usize {
        2 * self.parameters.correctionCapacity
    }

    /// The systematic codeword of a message of `k` bytes, `reed_solomon_encode`: the parity bytes
    /// of a shift register with the feedback of the generator polynomial, then the message.
    pub(crate) fn encoded(&self, message: &[u8]) -> Vec<u8> {
        let parityLength = self.parityLength();
        let generator = self.parameters.generatorPolynomial;
        let mut codeword = alloc::vec![0u8; self.parameters.reedSolomonLength];
        for byte in message.iter().rev() {
            let gate = byte ^ codeword[parityLength - 1];
            for position in (1..parityLength).rev() {
                codeword[position] =
                    codeword[position - 1] ^ GaloisField::product(gate, generator[position]);
            }
            codeword[0] = GaloisField::product(gate, generator[0]);
        }
        codeword[parityLength..].copy_from_slice(message);
        codeword
    }

    /// The message of a received word of `n1` bytes, `reed_solomon_decode`.
    pub(crate) fn decoded(&self, received: &[u8]) -> Vec<u8> {
        let syndromes = self.syndromes(received);
        let (locator, degree) = self.errorLocator(&syndromes);
        let exponent = self.parameters.fftExponent;
        let values = AdditiveFFT::evaluations(
            &locator[..1 << exponent],
            self.parameters.correctionCapacity + 1,
            exponent,
        );
        let positions = AdditiveFFT::errorPositions(&values);
        let evaluator = self.errorEvaluator(&locator, degree, &syndromes);
        let errorValues = self.errorValues(&evaluator, &positions);
        received[self.parityLength()..]
            .iter()
            .zip(&errorValues[self.parityLength()..])
            .map(|(byte, error)| byte ^ error)
            .collect()
    }

    /// The `2 delta` syndromes, `compute_syndromes`: the values of the received word at
    /// `alpha^i` for `i` from 1 to `2 delta`.
    fn syndromes(&self, received: &[u8]) -> Vec<u8> {
        (1..=self.parityLength())
            .map(|exponent| {
                let sum = received
                    .iter()
                    .enumerate()
                    .skip(1)
                    .fold(0u8, |sum, (position, byte)| {
                        sum ^ GaloisField::product(*byte, GaloisField::power(exponent * position))
                    });
                sum ^ received[0]
            })
            .collect()
    }

    /// The error locator polynomial `sigma` and its degree, `compute_elp`: the Berlekamp
    /// algorithm with masks in place of branches.
    ///
    /// `sigma` keeps `delta + 1` coefficients. The degree can grow above `delta` when the word
    /// has too many errors, as in the C code.
    fn errorLocator(&self, syndromes: &[u8]) -> ([u8; locatorSlots], u16) {
        let delta = self.parameters.correctionCapacity;
        let mut sigma = [0u8; locatorSlots];
        let mut savedSigma = [0u8; largestCorrectionCapacity + 1];
        // `X^(mu - rho) sigma_rho(X)`, the polynomial of the last step that changed the degree.
        let mut shifted = [0u8; largestCorrectionCapacity + 1];
        shifted[1] = 1;
        let mut degree: u16 = 0;
        let mut shiftedDegree: u16 = 0;
        // `2 rho`, which starts at -1.
        let mut lastStep: u16 = u16::MAX;
        let mut lastDiscrepancy: u8 = 1;
        let mut discrepancy: u8 = syndromes[0];
        sigma[0] = 1;
        for step in 0..2 * delta {
            savedSigma[..delta].copy_from_slice(&sigma[..delta]);
            let savedDegree = degree;
            let factor = GaloisField::product(discrepancy, GaloisField::inverse(lastDiscrepancy));
            let updated = delta.min(step + 1);
            for (coefficient, shiftedCoefficient) in
                sigma[1..=updated].iter_mut().zip(&shifted[1..=updated])
            {
                *coefficient ^= GaloisField::product(factor, *shiftedCoefficient);
            }
            let stepNumber = step as u16;
            let candidateDegree = stepNumber
                .wrapping_sub(lastStep)
                .wrapping_add(shiftedDegree);
            // All ones when the discrepancy is not zero.
            let discrepancyMask = 0u16.wrapping_sub(u16::from(discrepancy).wrapping_neg() >> 15);
            // All ones when the candidate degree is above the degree.
            let growthMask = 0u16.wrapping_sub(degree.wrapping_sub(candidateDegree) >> 15);
            let updateMask = discrepancyMask & growthMask;
            degree ^= updateMask & (candidateDegree ^ degree);
            if step == 2 * delta - 1 {
                break;
            }
            lastStep ^= updateMask & (stepNumber ^ lastStep);
            let byteMask = updateMask as u8;
            lastDiscrepancy ^= byteMask & (discrepancy ^ lastDiscrepancy);
            for index in (1..=delta).rev() {
                shifted[index] =
                    shifted[index - 1] ^ (byteMask & (savedSigma[index - 1] ^ shifted[index - 1]));
            }
            shiftedDegree ^= updateMask & (savedDegree ^ shiftedDegree);
            discrepancy = syndromes[step + 1];
            for index in 1..=updated {
                discrepancy ^= GaloisField::product(sigma[index], syndromes[step + 1 - index]);
            }
        }
        (sigma, degree)
    }

    /// The error evaluator polynomial `z`, `compute_z_poly`, of `delta + 1` coefficients.
    fn errorEvaluator(
        &self,
        sigma: &[u8; locatorSlots],
        degree: u16,
        syndromes: &[u8],
    ) -> [u8; largestCorrectionCapacity + 1] {
        let delta = self.parameters.correctionCapacity;
        // All ones when `index` is at most the degree, as `-((uint16_t)(i - degree - 1) >> 15)`.
        let maskUpTo = |index: usize| {
            let difference = (index as u16).wrapping_sub(degree).wrapping_sub(1);
            0u16.wrapping_sub(difference >> 15) as u8
        };
        let mut evaluator = [0u8; largestCorrectionCapacity + 1];
        evaluator[0] = 1;
        for index in 1..=delta {
            evaluator[index] = maskUpTo(index) & sigma[index];
        }
        evaluator[1] ^= syndromes[0];
        for index in 2..=delta {
            let mask = maskUpTo(index);
            evaluator[index] ^= mask & syndromes[index - 1];
            for term in 1..index {
                evaluator[index] ^=
                    mask & GaloisField::product(sigma[term], syndromes[index - term - 1]);
            }
        }
        evaluator
    }

    /// The error value at each position of the word, `compute_error_values`, by the formula of
    /// Forney for the first `delta` error positions.
    fn errorValues(
        &self,
        evaluator: &[u8; largestCorrectionCapacity + 1],
        positions: &[u8; 256],
    ) -> Vec<u8> {
        let delta = self.parameters.correctionCapacity;
        let length = self.parameters.reedSolomonLength;
        // `beta_j`, the error locator numbers `alpha^i` of the first `delta` error positions.
        let mut locatorNumbers = [0u8; largestCorrectionCapacity];
        let mut errorCount: u16 = 0;
        for (position, isError) in positions[..length].iter().enumerate() {
            let mut found: u16 = 0;
            for (slot, number) in locatorNumbers[..delta].iter_mut().enumerate() {
                let mask = matchMask(*isError, slot, errorCount);
                *number += mask as u8 & GaloisField::power(position);
                found += mask & 1;
            }
            errorCount += found;
        }
        let locatedCount = i32::from(errorCount);
        let mut values = [0u8; largestCorrectionCapacity];
        for (slot, value) in values[..delta].iter_mut().enumerate() {
            let inverse = GaloisField::inverse(locatorNumbers[slot]);
            let mut numerator = 1u8;
            let mut inversePower = 1u8;
            for coefficient in &evaluator[1..=delta] {
                inversePower = GaloisField::product(inversePower, inverse);
                numerator ^= GaloisField::product(inversePower, *coefficient);
            }
            let mut denominator = 1u8;
            for offset in 1..delta {
                let other = locatorNumbers[(slot + offset) % delta];
                denominator =
                    GaloisField::product(denominator, 1 ^ GaloisField::product(inverse, other));
            }
            // All ones for a slot below the number of located errors, as in the C code. The
            // placement below reads only those slots, so the mask never changes the result.
            let mask = ((slot as i32 - locatedCount) >> 15) as u8;
            *value = mask & GaloisField::product(numerator, GaloisField::inverse(denominator));
        }
        let mut errorValues = alloc::vec![0u8; length];
        let mut errorCount: u16 = 0;
        for (errorValue, isError) in errorValues.iter_mut().zip(&positions[..length]) {
            let mut found: u16 = 0;
            for (slot, value) in values[..delta].iter().enumerate() {
                let mask = matchMask(*isError, slot, errorCount);
                *errorValue += mask as u8 & value;
                found += mask & 1;
            }
            errorCount += found;
        }
        errorValues
    }
}

/// All ones when a position is an error and the slot is the count of the errors before it, as
/// the two masks of `compute_error_values`.
fn matchMask(isError: u8, slot: usize, errorCount: u16) -> u16 {
    let errorMask = ((-i32::from(isError)) >> 31) as u16;
    let slotMask = !(((-((slot as i32) ^ i32::from(errorCount))) >> 31) as u16);
    errorMask & slotMask
}

#[cfg(test)]
mod tests {
    use super::ReedSolomon;
    use crate::galoisField::GaloisField;
    use crate::parameters::{hqc1, hqc3, hqc5};

    /// A seeded message of a length.
    fn messageFrom(seed: u32, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (state >> 16) as u8
            })
            .collect()
    }

    /// The value of a word, as a polynomial with the first byte as the constant term, at a point.
    fn value(word: &[u8], point: u8) -> u8 {
        word.iter().rev().fold(0u8, |total, coefficient| {
            GaloisField::product(total, point) ^ coefficient
        })
    }

    #[test]
    fn codewordsAreSystematicAndHaveTheRootsOfTheGenerator() {
        for parameters in [&hqc1, &hqc3, &hqc5] {
            let code = ReedSolomon::new(parameters);
            for seed in 0..10 {
                let message = messageFrom(seed, parameters.messageLength);
                let codeword = code.encoded(&message);
                assert_eq!(codeword.len(), parameters.reedSolomonLength);
                assert_eq!(&codeword[2 * parameters.correctionCapacity..], &message[..]);
                for exponent in 1..=2 * parameters.correctionCapacity {
                    assert_eq!(value(&codeword, GaloisField::power(exponent)), 0);
                }
                assert!(
                    code.syndromes(&codeword)
                        .iter()
                        .all(|syndrome| *syndrome == 0)
                );
            }
        }
    }

    #[test]
    fn decodingCorrectsUpToDeltaErrorsAnywhere() {
        for parameters in [&hqc1, &hqc3, &hqc5] {
            let code = ReedSolomon::new(parameters);
            let delta = parameters.correctionCapacity;
            for seed in 0..12 {
                let message = messageFrom(seed, parameters.messageLength);
                let mut received = code.encoded(&message);
                let errorCount = [0, 1, delta / 2, delta][seed as usize % 4];
                // Distinct positions in a seeded order, each with a change that is not zero.
                let order = messageFrom(seed + 1000, parameters.reedSolomonLength);
                let mut positions: Vec<usize> = (0..parameters.reedSolomonLength).collect();
                positions.sort_by_key(|position| (order[*position], *position));
                let changes = messageFrom(seed + 2000, errorCount);
                for (position, change) in positions.iter().zip(changes) {
                    received[*position] ^= change | 1;
                }
                assert_eq!(
                    code.decoded(&received),
                    message,
                    "{}, {errorCount} errors, seed {seed}",
                    parameters.description.name
                );
            }
        }
    }

    #[test]
    fn decodingOfAnErrorInTheFirstAndTheLastByteGivesTheMessage() {
        let code = ReedSolomon::new(&hqc1);
        let message = messageFrom(5, hqc1.messageLength);
        let mut received = code.encoded(&message);
        received[0] ^= 0x80;
        received[hqc1.reedSolomonLength - 1] ^= 0x01;
        assert_eq!(code.decoded(&received), message);
    }

    #[test]
    fn decodingOfTooManyErrorsGivesAnotherMessageWithoutAPanic() {
        for parameters in [&hqc1, &hqc3, &hqc5] {
            let code = ReedSolomon::new(parameters);
            let message = messageFrom(9, parameters.messageLength);
            let mut received = code.encoded(&message);
            // One error more than the capacity, at every other byte from the second.
            for byte in received
                .iter_mut()
                .skip(1)
                .step_by(2)
                .take(parameters.correctionCapacity + 1)
            {
                *byte ^= 0x5A;
            }
            let decoded = code.decoded(&received);
            assert_eq!(decoded.len(), parameters.messageLength);
            assert_ne!(decoded, message);
            let noise = messageFrom(10, parameters.reedSolomonLength);
            assert_eq!(code.decoded(&noise).len(), parameters.messageLength);
        }
    }

    #[test]
    fn locatorOfAWordWithoutErrorsIsOne() {
        let code = ReedSolomon::new(&hqc3);
        let codeword = code.encoded(&messageFrom(3, hqc3.messageLength));
        let syndromes = code.syndromes(&codeword);
        let (locator, degree) = code.errorLocator(&syndromes);
        assert_eq!(degree, 0);
        assert_eq!(locator[0], 1);
        assert!(locator[1..].iter().all(|coefficient| *coefficient == 0));
    }
}
