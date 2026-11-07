use crate::{Parameters, PolynomialRing, Variant};
use OQSNativeSortingNetwork::SortingNetwork;
use alloc::vec;
use alloc::vec::Vec;

/// The polynomials of the uniform random bytes of a key pair or an encapsulation, `sample.c`
/// and `sample_iid.c`.
///
/// NTRU-HPS samples `f` and `r` with independent coefficients, and `g` and `m` of a fixed
/// type. NTRU-HRSS samples `f` and `g` with independent coefficients of a nonnegative
/// correlation, and `r` and `m` with independent coefficients. Each polynomial has the
/// coefficients 0, 1 and 2, where 2 stands for -1, and its last coefficient is 0.
pub(crate) struct Sampler<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> Sampler<'parameters> {
    /// Makes the sampler of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Sampler { parameters }
    }

    /// `f` and `g` of the bytes of a key pair, `sample_fg`.
    pub(crate) fn keyPolynomials(&self, bytes: &[u8]) -> (Vec<u16>, Vec<u16>) {
        let (first, second) = bytes.split_at(self.parameters.independentSampleLength());
        match self.parameters.variant {
            Variant::hps => (
                self.independentPolynomial(first),
                self.fixedTypePolynomial(second),
            ),
            Variant::hrss => (
                self.correlatedPolynomial(first),
                self.correlatedPolynomial(second),
            ),
        }
    }

    /// The blinding polynomial `r` and the message `m` of the bytes of an encapsulation,
    /// `sample_rm`.
    pub(crate) fn messagePolynomials(&self, bytes: &[u8]) -> (Vec<u16>, Vec<u16>) {
        let (first, second) = bytes.split_at(self.parameters.independentSampleLength());
        let message = match self.parameters.variant {
            Variant::hps => self.fixedTypePolynomial(second),
            Variant::hrss => self.independentPolynomial(second),
        };
        (self.independentPolynomial(first), message)
    }

    /// The polynomial with the coefficients of `n - 1` bytes modulo 3, `sample_iid`. A byte
    /// gives 0 with the probability 86 / 256 and 1 or 2 with 85 / 256 each.
    pub(crate) fn independentPolynomial(&self, bytes: &[u8]) -> Vec<u16> {
        let mut polynomial = vec![0u16; self.parameters.coefficientCount];
        for (coefficient, byte) in polynomial.iter_mut().zip(bytes) {
            *coefficient = PolynomialRing::residueModuloThree(u16::from(*byte));
        }
        polynomial
    }

    /// The polynomial of a fixed type of `30 (n - 1)` bits, `sample_fixed_type`: `q / 16 - 1`
    /// coefficients 1 and as many coefficients 2, at places that a sort of 30-bit random keys
    /// decides.
    pub(crate) fn fixedTypePolynomial(&self, bytes: &[u8]) -> Vec<u16> {
        let parameters = self.parameters;
        let count = parameters.coefficientCount - 1;
        // Each group of 15 bytes gives four keys of 30 bits, in the bits 2 to 31 of a word.
        let mut keys: Vec<i32> = Vec::with_capacity(count);
        for group in bytes.chunks_exact(15).take(count / 4) {
            let byte = |index: usize| u32::from(group[index]);
            keys.push(
                ((byte(0) << 2) + (byte(1) << 10) + (byte(2) << 18) + (byte(3) << 26)) as i32,
            );
            keys.push(
                (((byte(3) & 0xC0) >> 4)
                    + (byte(4) << 4)
                    + (byte(5) << 12)
                    + (byte(6) << 20)
                    + (byte(7) << 28)) as i32,
            );
            keys.push(
                (((byte(7) & 0xF0) >> 2)
                    + (byte(8) << 6)
                    + (byte(9) << 14)
                    + (byte(10) << 22)
                    + (byte(11) << 30)) as i32,
            );
            keys.push(
                ((byte(11) & 0xFC) + (byte(12) << 8) + (byte(13) << 16) + (byte(14) << 24)) as i32,
            );
        }
        // The two low bits of a key are free: the first half of the weight gets 1, the
        // second half gets 2, and every other key keeps 0.
        let weight = usize::from(parameters.weight());
        for key in &mut keys[..weight / 2] {
            *key |= 1;
        }
        for key in &mut keys[weight / 2..weight] {
            *key |= 2;
        }
        SortingNetwork::sort(&mut keys);
        let mut polynomial = vec![0u16; parameters.coefficientCount];
        for (coefficient, key) in polynomial.iter_mut().zip(&keys) {
            *coefficient = (key & 3) as u16;
        }
        polynomial
    }

    /// The polynomial with independent coefficients whose even coefficients change sign so
    /// that `<x r, r> >= 0`, `sample_iid_plus`.
    pub(crate) fn correlatedPolynomial(&self, bytes: &[u8]) -> Vec<u16> {
        let mut polynomial = self.independentPolynomial(bytes);
        let count = polynomial.len();
        // The coefficients 0, 1 and 2 become 0, 1 and 2^16 - 1, so the products are signed.
        for coefficient in &mut polynomial[..count - 1] {
            *coefficient |= 0u16.wrapping_sub(*coefficient >> 1);
        }
        let mut correlation = 0u16;
        for index in 0..count - 1 {
            correlation =
                correlation.wrapping_add(polynomial[index + 1].wrapping_mul(polynomial[index]));
        }
        // 1 for a correlation from 0 up, and -1 below.
        let sign = 1 | 0u16.wrapping_sub(correlation >> 15);
        for coefficient in polynomial.iter_mut().step_by(2) {
            *coefficient = sign.wrapping_mul(*coefficient);
        }
        for coefficient in polynomial.iter_mut() {
            *coefficient = 3 & (*coefficient ^ (*coefficient >> 15));
        }
        polynomial
    }
}

#[cfg(test)]
mod tests {
    use super::Sampler;
    use crate::parameters::{ntruHPS2048509, ntruHPS4096821, ntruHRSS701};
    use crate::testInputs::{cAnswer, everySet, sequenceBytes, valuesDigest};

    #[test]
    fn independentCoefficientsAreTheBytesModuloThreeAndTheLastIsZero() {
        let sampler = Sampler::new(&ntruHPS2048509);
        let bytes: Vec<u8> = (0..508).map(|index| (index * 37 % 256) as u8).collect();
        let polynomial = sampler.independentPolynomial(&bytes);
        assert_eq!(polynomial.len(), 509);
        for (coefficient, byte) in polynomial.iter().zip(&bytes) {
            assert_eq!(*coefficient, u16::from(*byte) % 3);
        }
        assert_eq!(polynomial[508], 0);
    }

    #[test]
    fn aFixedTypeHasTheWeightOfTheSetAndPlacesThatFollowTheKeys() {
        for parameters in [&ntruHPS2048509, &ntruHPS4096821] {
            let sampler = Sampler::new(parameters);
            let bytes = sequenceBytes(parameters.fixedTypeSampleLength(), 17);
            let polynomial = sampler.fixedTypePolynomial(&bytes);
            let half = usize::from(parameters.weight() / 2);
            assert_eq!(polynomial.iter().filter(|value| **value == 1).count(), half);
            assert_eq!(polynomial.iter().filter(|value| **value == 2).count(), half);
            assert_eq!(polynomial[parameters.coefficientCount - 1], 0);
            // The keys are the 30-bit fields of the stream, low bit first, in the bits 2 to
            // 31 of a signed word. The place of each key in the sorted list takes its mark.
            let count = parameters.coefficientCount - 1;
            let mut marked: Vec<(i32, u16)> = (0..count)
                .map(|index| {
                    let mut field = 0u32;
                    for bit in 0..30 {
                        let position = 30 * index + bit;
                        field |= u32::from((bytes[position / 8] >> (position % 8)) & 1) << bit;
                    }
                    let mark = if index < half {
                        1
                    } else if index < 2 * half {
                        2
                    } else {
                        0
                    };
                    (((field << 2) | u32::from(mark)) as i32, mark)
                })
                .collect();
            marked.sort_unstable();
            let expected: Vec<u16> = marked.iter().map(|(_, mark)| *mark).collect();
            assert_eq!(&polynomial[..count], expected.as_slice());
        }
    }

    #[test]
    fn aCorrelatedPolynomialHasANonnegativeCorrelationAfterTheSignChange() {
        let sampler = Sampler::new(&ntruHRSS701);
        let mut flipped = 0;
        for seed in 0..8 {
            let bytes = sequenceBytes(700, 50 + seed);
            let plain = sampler.independentPolynomial(&bytes);
            let correlated = sampler.correlatedPolynomial(&bytes);
            let signed = |value: u16| match value {
                1 => 1i32,
                2 => -1,
                _ => 0,
            };
            let correlation = |polynomial: &[u16]| -> i32 {
                polynomial
                    .windows(2)
                    .map(|pair| signed(pair[0]) * signed(pair[1]))
                    .sum()
            };
            assert!(correlation(&correlated) >= 0, "seed {seed}");
            // The odd coefficients stay, and the even ones change sign together or not at all.
            let isFlipped = correlation(&plain) < 0;
            for (index, (before, after)) in plain.iter().zip(&correlated).enumerate() {
                let expected = if isFlipped && index % 2 == 0 {
                    -signed(*before)
                } else {
                    signed(*before)
                };
                assert_eq!(signed(*after), expected, "seed {seed}, coefficient {index}");
            }
            flipped += usize::from(isFlipped);
        }
        // About half of the samples change sign, so both cases ran.
        assert!((1..8).contains(&flipped), "{flipped}");
    }

    #[test]
    fn eachSampleHasTheCoefficientsOfTheCFunctions() {
        // sample_fg and sample_rm of liboqs 0.16.0 on the same bytes.
        for parameters in everySet() {
            let sampler = Sampler::new(parameters);
            let name = parameters.description.name;
            let length = parameters.sampleLength();
            let (f, g) = sampler.keyPolynomials(&sequenceBytes(length, 10));
            assert_eq!(valuesDigest(&f), cAnswer(name, "keyPolynomialF"), "{name}");
            assert_eq!(valuesDigest(&g), cAnswer(name, "keyPolynomialG"), "{name}");
            let (r, m) = sampler.messagePolynomials(&sequenceBytes(length, 11));
            assert_eq!(
                valuesDigest(&r),
                cAnswer(name, "blindingPolynomial"),
                "{name}"
            );
            assert_eq!(
                valuesDigest(&m),
                cAnswer(name, "messagePolynomial"),
                "{name}"
            );
        }
    }
}
