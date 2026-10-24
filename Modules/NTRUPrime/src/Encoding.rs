use crate::{Parameters, RadixEncoding};
use alloc::vec;
use alloc::vec::Vec;

/// The byte forms of the polynomials of `sntrup761.c`: `Small_encode` and `Small_decode`,
/// `Rq_encode` and `Rq_decode`, and `Rounded_encode` and `Rounded_decode`.
pub(crate) struct Encoding<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> Encoding<'parameters> {
    /// Makes the encoding of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Encoding { parameters }
    }

    /// The bytes of a small polynomial, four coefficients plus 1 in each byte, the first in
    /// the low two bits, `Small_encode`. The last byte holds the last coefficient alone.
    pub(crate) fn smallBytes(&self, small: &[i8]) -> Vec<u8> {
        let p = self.parameters.degree;
        let mut bytes = Vec::with_capacity(self.parameters.smallLength());
        for group in small[..p / 4 * 4].chunks_exact(4) {
            let byte = group
                .iter()
                .enumerate()
                .fold(0i32, |byte, (index, coefficient)| {
                    byte + ((i32::from(*coefficient) + 1) << (2 * index))
                });
            bytes.push(byte as u8);
        }
        bytes.push((small[p / 4 * 4] + 1) as u8);
        bytes
    }

    /// The small polynomial of its bytes, `Small_decode`. Each pair of bits gives a value from
    /// -1 to 2, and the last byte gives the last coefficient from its low two bits.
    pub(crate) fn smallPolynomial(&self, bytes: &[u8]) -> Vec<i8> {
        let p = self.parameters.degree;
        let mut small = vec![0i8; p];
        for (group, byte) in small[..p / 4 * 4].chunks_exact_mut(4).zip(bytes) {
            for (index, coefficient) in group.iter_mut().enumerate() {
                *coefficient = ((byte >> (2 * index)) & 3) as i8 - 1;
            }
        }
        small[p / 4 * 4] = (bytes[p / 4] & 3) as i8 - 1;
        small
    }

    /// The bytes of a polynomial modulo `q`, each coefficient plus `(q - 1) / 2` below `q`,
    /// `Rq_encode`.
    pub(crate) fn modulusBytes(&self, polynomial: &[i16]) -> Vec<u8> {
        let half = self.parameters.halfModulus();
        let values: Vec<u16> = polynomial
            .iter()
            .map(|coefficient| (coefficient + half) as u16)
            .collect();
        let ranges = vec![self.parameters.modulus as u16; self.parameters.degree];
        RadixEncoding::encoded(&values, &ranges)
    }

    /// The polynomial modulo `q` of its bytes, `Rq_decode`.
    pub(crate) fn modulusPolynomial(&self, bytes: &[u8]) -> Vec<i16> {
        let half = self.parameters.halfModulus();
        let ranges = vec![self.parameters.modulus as u16; self.parameters.degree];
        RadixEncoding::decoded(bytes, &ranges)
            .iter()
            .map(|value| *value as i16 - half)
            .collect()
    }

    /// The bytes of a rounded polynomial, each coefficient a multiple of 3, as its third plus
    /// `(q - 1) / 6`, `Rounded_encode`.
    pub(crate) fn roundedBytes(&self, polynomial: &[i16]) -> Vec<u8> {
        let half = i32::from(self.parameters.halfModulus());
        let values: Vec<u16> = polynomial
            .iter()
            .map(|coefficient| (((i32::from(*coefficient) + half) * 10923) >> 15) as u16)
            .collect();
        let ranges = vec![self.parameters.roundedRange(); self.parameters.degree];
        RadixEncoding::encoded(&values, &ranges)
    }

    /// The rounded polynomial of its bytes, `Rounded_decode`.
    pub(crate) fn roundedPolynomial(&self, bytes: &[u8]) -> Vec<i16> {
        let half = i32::from(self.parameters.halfModulus());
        let ranges = vec![self.parameters.roundedRange(); self.parameters.degree];
        RadixEncoding::decoded(bytes, &ranges)
            .iter()
            .map(|value| (i32::from(*value) * 3 - half) as i16)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Encoding;
    use crate::PolynomialRing;
    use crate::parameters::sntrup761;
    use crate::testInputs::{
        byteSequence, cAnswer, modulusBytes, modulusSequence, sequence, smallBytes, smallSequence,
    };
    use OQSNativeAlgorithmTests::OutputDigest;

    #[test]
    fn smallBytesHoldFourCoefficientsPlusOneFromTheLowBits() {
        let encoding = Encoding::new(&sntrup761);
        let mut small = vec![0i8; 761];
        // (-1 + 1) + (0 + 1) 4 + (1 + 1) 16 + (1 + 1) 64 = 164.
        small[..4].copy_from_slice(&[-1, 0, 1, 1]);
        small[760] = -1;
        let bytes = encoding.smallBytes(&small);
        assert_eq!(bytes.len(), 191);
        assert_eq!(bytes[0], 164);
        assert!(bytes[1..190].iter().all(|byte| *byte == 0x55));
        assert_eq!(bytes[190], 0);
        assert_eq!(encoding.smallPolynomial(&bytes), small);
        // The pair of bits 3 decodes to 2, and the high bits of the last byte do not count.
        let mut bytes = vec![0xFFu8; 191];
        bytes[190] = 0xFE;
        let decoded = encoding.smallPolynomial(&bytes);
        assert!(decoded[..760].iter().all(|value| *value == 2));
        assert_eq!(decoded[760], 1);
    }

    #[test]
    fn modulusAndRoundedPolynomialsRoundTrip() {
        let encoding = Encoding::new(&sntrup761);
        let polynomial: Vec<i16> = sequence(761, 5)
            .iter()
            .map(|value| (i32::from(*value) % 4591 - 2295) as i16)
            .collect();
        let bytes = encoding.modulusBytes(&polynomial);
        assert_eq!(bytes.len(), 1158);
        assert_eq!(encoding.modulusPolynomial(&bytes), polynomial);
        let rounded: Vec<i16> = sequence(761, 6)
            .iter()
            .map(|value| (i32::from(*value) % 1531 * 3 - 2295) as i16)
            .collect();
        let bytes = encoding.roundedBytes(&rounded);
        assert_eq!(bytes.len(), 1007);
        assert_eq!(encoding.roundedPolynomial(&bytes), rounded);
        // The extremes: -2295 is the value 0, and 2295 the value q - 1 or (q + 2) / 3 - 1.
        let extremes = vec![-2295i16, 2295, 0];
        let mut polynomial = vec![0i16; 761];
        polynomial[..3].copy_from_slice(&extremes);
        let decoded = encoding.modulusPolynomial(&encoding.modulusBytes(&polynomial));
        assert_eq!(&decoded[..3], extremes.as_slice());
        let decoded = encoding.roundedPolynomial(&encoding.roundedBytes(&polynomial));
        assert_eq!(&decoded[..3], extremes.as_slice());
    }

    #[test]
    fn eachFormHasTheBytesOfTheCFunctions() {
        // Rq_encode, Rq_decode, Rounded_encode, Rounded_decode, Small_encode and Small_decode
        // of liboqs 0.16.0 on the same inputs, the decodings of seeded bytes.
        let encoding = Encoding::new(&sntrup761);
        let bytes = encoding.modulusBytes(&modulusSequence(7));
        assert_eq!(OutputDigest::of(&bytes), cAnswer("modulusBytes"));
        let polynomial = encoding.modulusPolynomial(&byteSequence(1158, 8));
        assert_eq!(
            OutputDigest::of(&modulusBytes(&polynomial)),
            cAnswer("modulusPolynomial")
        );
        let bytes = encoding.roundedBytes(&PolynomialRing::rounded(&modulusSequence(9)));
        assert_eq!(OutputDigest::of(&bytes), cAnswer("roundedBytes"));
        let polynomial = encoding.roundedPolynomial(&byteSequence(1007, 10));
        assert_eq!(
            OutputDigest::of(&modulusBytes(&polynomial)),
            cAnswer("roundedPolynomial")
        );
        let bytes = encoding.smallBytes(&smallSequence(11));
        assert_eq!(OutputDigest::of(&bytes), cAnswer("smallBytes"));
        let small = encoding.smallPolynomial(&byteSequence(191, 12));
        assert_eq!(
            OutputDigest::of(&smallBytes(&small)),
            cAnswer("smallPolynomial")
        );
    }
}
