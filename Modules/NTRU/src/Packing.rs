use crate::{Parameters, PolynomialRing};
use alloc::vec;
use alloc::vec::Vec;

/// The byte forms of NTRU polynomials, `pack3.c` and `packq.c`.
///
/// A polynomial modulo 3 packs five coefficients into each byte as the digits of a number in
/// base 3, the first coefficient in the lowest digit. A polynomial modulo `q` packs `logq`
/// bits of each coefficient into one bit stream, the low bit first, and fills each byte from
/// its low bit. Both forms hold the coefficients below `n - 1`.
pub(crate) struct Packing<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> Packing<'parameters> {
    /// Makes the packing of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Packing { parameters }
    }

    /// The bytes of a polynomial modulo 3, `poly_S3_tobytes`.
    pub(crate) fn ternaryBytes(&self, polynomial: &[u16]) -> Vec<u8> {
        let count = self.parameters.packedCoefficientCount();
        let mut bytes = vec![0u8; self.parameters.ternaryLength()];
        for (index, byte) in bytes.iter_mut().enumerate() {
            // The C code reads the last group only up to the coefficient n - 2.
            let end = (5 * index + 5).min(count);
            let mut value = 0u8;
            for coefficient in polynomial[5 * index..end].iter().rev() {
                value = (3 * u32::from(value) + u32::from(*coefficient)) as u8;
            }
            *byte = value;
        }
        bytes
    }

    /// The polynomial modulo 3 and `Phi_n` of its bytes, `poly_S3_frombytes`. A byte above
    /// `3^5 - 1` gives digits that the reduction modulo 3 keeps as the C code does.
    pub(crate) fn ternaryPolynomial(&self, bytes: &[u8]) -> Vec<u16> {
        let count = self.parameters.packedCoefficientCount();
        let mut polynomial = vec![0u16; self.parameters.coefficientCount];
        let fullGroups = count / 5;
        for (index, byte) in bytes[..fullGroups].iter().enumerate() {
            let value = u32::from(*byte);
            // Multiplications and shifts that divide a byte by 3, 9, 27 and 81.
            polynomial[5 * index] = value as u16;
            polynomial[5 * index + 1] = ((value * 171) >> 9) as u16;
            polynomial[5 * index + 2] = ((value * 57) >> 9) as u16;
            polynomial[5 * index + 3] = ((value * 19) >> 9) as u16;
            polynomial[5 * index + 4] = ((value * 203) >> 14) as u16;
        }
        if !count.is_multiple_of(5) {
            let mut value = bytes[fullGroups];
            for coefficient in &mut polynomial[5 * fullGroups..count] {
                *coefficient = u16::from(value);
                value = ((u32::from(value) * 171) >> 9) as u8;
            }
        }
        PolynomialRing::reduceModuloThreeAndPhi(&mut polynomial);
        polynomial
    }

    /// The bytes of a polynomial modulo `q`, each coefficient reduced modulo `q`,
    /// `poly_Sq_tobytes` and `poly_Rq_sum_zero_tobytes`.
    pub(crate) fn modulusBytes(&self, polynomial: &[u16]) -> Vec<u8> {
        let ring = PolynomialRing::new(self.parameters);
        let bits = self.parameters.modulusBits;
        let mut bytes = vec![0u8; self.parameters.packedLength()];
        // The bits that wait for a byte, fewer than 8 between two coefficients.
        let mut pending = 0u32;
        let mut pendingCount = 0u32;
        let mut position = 0;
        for coefficient in &polynomial[..self.parameters.packedCoefficientCount()] {
            pending += u32::from(ring.residueModuloModulus(*coefficient)) << pendingCount;
            pendingCount += bits;
            while pendingCount >= 8 {
                bytes[position] = pending as u8;
                position += 1;
                pending >>= 8;
                pendingCount -= 8;
            }
        }
        if pendingCount > 0 {
            bytes[position] = pending as u8;
        }
        bytes
    }

    /// The polynomial of the bytes of a polynomial modulo `q`, with the last coefficient 0,
    /// `poly_Sq_frombytes`. The bits of the last byte past the last coefficient are not read.
    pub(crate) fn modulusPolynomial(&self, bytes: &[u8]) -> Vec<u16> {
        let bits = self.parameters.modulusBits;
        let mask = (1u32 << bits) - 1;
        let mut polynomial = vec![0u16; self.parameters.coefficientCount];
        let mut pending = 0u32;
        let mut pendingCount = 0u32;
        let mut position = 0;
        for coefficient in &mut polynomial[..self.parameters.packedCoefficientCount()] {
            while pendingCount < bits {
                pending += u32::from(bytes[position]) << pendingCount;
                position += 1;
                pendingCount += 8;
            }
            *coefficient = (pending & mask) as u16;
            pending >>= bits;
            pendingCount -= bits;
        }
        polynomial
    }

    /// The polynomial of the bytes of a polynomial modulo `q` whose coefficients sum to 0,
    /// such as a public key or a ciphertext, `poly_Rq_sum_zero_frombytes`: the last
    /// coefficient is minus the sum of the others.
    pub(crate) fn sumZeroPolynomial(&self, bytes: &[u8]) -> Vec<u16> {
        let mut polynomial = self.modulusPolynomial(bytes);
        let count = polynomial.len();
        polynomial[count - 1] = polynomial[..count - 1]
            .iter()
            .fold(0u16, |last, coefficient| last.wrapping_sub(*coefficient));
        polynomial
    }
}

#[cfg(test)]
mod tests {
    use super::Packing;
    use crate::parameters::{
        ntruHPS2048509, ntruHPS4096821, ntruHPS40961229, ntruHRSS701, ntruHRSS1373,
    };
    use crate::testInputs::{
        cAnswer, digest, everySet, sequence, sequenceBytes, ternarySequence, valuesDigest,
    };

    #[test]
    fn ternaryBytesAreDigitsInBaseThreeWithTheFirstCoefficientLowest() {
        let packing = Packing::new(&ntruHPS2048509);
        let mut polynomial = vec![0u16; 509];
        // 1 + 2 * 3 + 0 * 9 + 1 * 27 + 2 * 81 = 196.
        polynomial[..5].copy_from_slice(&[1, 2, 0, 1, 2]);
        // The last group holds the coefficients 505, 506 and 507: 2 + 1 * 3 + 1 * 9 = 14.
        polynomial[505..508].copy_from_slice(&[2, 1, 1]);
        // The coefficient n - 1 is not packed.
        polynomial[508] = 2;
        let bytes = packing.ternaryBytes(&polynomial);
        assert_eq!(bytes.len(), 102);
        assert_eq!(bytes[0], 196);
        assert_eq!(bytes[101], 14);
        assert!(bytes[1..101].iter().all(|byte| *byte == 0));
        polynomial[508] = 0;
        assert_eq!(packing.ternaryPolynomial(&bytes), polynomial);
    }

    #[test]
    fn ternaryPackingHasNoPartialGroupWhenFiveDividesNMinusOne() {
        // NTRU-HPS-4096-821 packs 820 coefficients in 164 full bytes.
        let packing = Packing::new(&ntruHPS4096821);
        let polynomial: Vec<u16> = (0..821)
            .map(|index| if index == 820 { 0 } else { (index % 3) as u16 })
            .collect();
        let bytes = packing.ternaryBytes(&polynomial);
        assert_eq!(bytes.len(), 164);
        assert_eq!(packing.ternaryPolynomial(&bytes), polynomial);
    }

    #[test]
    fn eachByteUnpacksToItsDigitsModuloThree() {
        // The multiplications divide exactly for every byte, so each coefficient is a digit
        // of the byte in base 3, and a digit 3 of a byte from 243 up becomes 0.
        let packing = Packing::new(&ntruHPS2048509);
        for value in 0..=255u8 {
            let mut bytes = vec![0u8; 102];
            bytes[0] = value;
            bytes[101] = value;
            let polynomial = packing.ternaryPolynomial(&bytes);
            let digits: Vec<u16> = (0..5)
                .map(|digit| (u16::from(value) / 3u16.pow(digit)) % 3)
                .collect();
            assert_eq!(&polynomial[..5], digits.as_slice(), "{value}");
            assert_eq!(&polynomial[505..508], &digits[..3], "{value}");
        }
    }

    #[test]
    fn modulusBytesAreALowBitFirstStreamOfLogQBits() {
        // Coefficient 0 is 0x7FF and coefficient 1 is 0x001 for q = 2^11: the stream starts
        // with eleven ones and then a one.
        let packing = Packing::new(&ntruHPS2048509);
        let mut polynomial = vec![0u16; 509];
        polynomial[0] = 0x7FF;
        polynomial[1] = 0x801;
        // The last packed coefficient, 507, takes the bits 5577 to 5587: the bits 1 to 7 of
        // byte 697 and the low four bits of byte 698.
        polynomial[507] = 0x7FF;
        let bytes = packing.modulusBytes(&polynomial);
        assert_eq!(bytes.len(), 699);
        assert_eq!(&bytes[..3], &[0xFF, 0x0F, 0x00]);
        assert_eq!(&bytes[697..], &[0xFE, 0x0F]);
        let decoded = packing.modulusPolynomial(&bytes);
        assert_eq!(decoded[0], 0x7FF);
        assert_eq!(decoded[1], 1);
        assert_eq!(decoded[507], 0x7FF);
        assert_eq!(decoded[508], 0);
    }

    #[test]
    fn modulusPackingRoundTripsForEveryWidth() {
        for parameters in [
            &ntruHPS2048509,
            &ntruHPS40961229,
            &ntruHRSS701,
            &ntruHRSS1373,
        ] {
            let packing = Packing::new(parameters);
            let count = parameters.coefficientCount;
            let mut polynomial = sequence(count, 3);
            let bytes = packing.modulusBytes(&polynomial);
            assert_eq!(bytes.len(), parameters.packedLength());
            for coefficient in polynomial.iter_mut() {
                *coefficient &= parameters.modulus() - 1;
            }
            polynomial[count - 1] = 0;
            assert_eq!(packing.modulusPolynomial(&bytes), polynomial);
            // The last coefficient of a sum-zero polynomial is minus the sum of the others.
            let summed = packing.sumZeroPolynomial(&bytes);
            let total = summed
                .iter()
                .fold(0u16, |sum, coefficient| sum.wrapping_add(*coefficient));
            assert_eq!(total, 0);
            assert_eq!(&summed[..count - 1], &polynomial[..count - 1]);
        }
    }

    #[test]
    fn theUnusedBitsOfTheLastByteAreNotRead() {
        // NTRU-HPS-2048-509 packs 508 * 11 = 5588 bits, so the high four bits of the last
        // byte are not part of a coefficient.
        let packing = Packing::new(&ntruHPS2048509);
        let mut bytes = packing.modulusBytes(&sequence(509, 9));
        let polynomial = packing.modulusPolynomial(&bytes);
        bytes[698] |= 0xF0;
        assert_eq!(packing.modulusPolynomial(&bytes), polynomial);
        bytes[698] ^= 0x01;
        assert_ne!(packing.modulusPolynomial(&bytes), polynomial);
    }

    #[test]
    fn eachFormHasTheBytesOfTheCFunctions() {
        // poly_S3_tobytes, poly_S3_frombytes, poly_Sq_tobytes and poly_Rq_sum_zero_frombytes
        // of liboqs 0.16.0 on the same inputs.
        for parameters in everySet() {
            let packing = Packing::new(parameters);
            let count = parameters.coefficientCount;
            let name = parameters.description.name;
            let bytes = packing.ternaryBytes(&ternarySequence(count, 6));
            assert_eq!(digest(&bytes), cAnswer(name, "ternaryBytes"), "{name}");
            let polynomial =
                packing.ternaryPolynomial(&sequenceBytes(parameters.ternaryLength(), 7));
            assert_eq!(
                valuesDigest(&polynomial),
                cAnswer(name, "ternaryPolynomial"),
                "{name}"
            );
            let bytes = packing.modulusBytes(&sequence(count, 8));
            assert_eq!(digest(&bytes), cAnswer(name, "modulusBytes"), "{name}");
            let polynomial =
                packing.sumZeroPolynomial(&sequenceBytes(parameters.packedLength(), 9));
            assert_eq!(
                valuesDigest(&polynomial),
                cAnswer(name, "sumZeroPolynomial"),
                "{name}"
            );
        }
    }
}
