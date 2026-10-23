use crate::FieldArithmetic;
use crate::fieldArithmetic::loadWord;
use core::marker::PhantomData;

/// The words of the longest entry of a block: 96 bytes, one element for each equation of OV-V.
const maximumWordCount: usize = 12;

/// A vector of up to 96 bytes times each power of the generator x below the element bits, so
/// that its product with a scalar is the sum of the powers whose bits the scalar sets.
///
/// A key pair multiplies each entry of a block by every element of a row of the oil matrix.
/// The powers of the entry serve each of those products, and each sum is the product that
/// `gf16v_madd` and `gf256v_madd` compute, bit for bit.
pub(crate) struct GeneratorPowers<F> {
    /// For each word of the vector, the word times x^0 to x^7. The powers above the element
    /// bits stay zero, so the sum of the eight terms serves both fields.
    powers: [[u64; 8]; maximumWordCount],
    field: PhantomData<F>,
}

impl<F: FieldArithmetic> GeneratorPowers<F> {
    /// The powers of a vector of up to 96 bytes.
    pub(crate) fn new(vector: &[u8]) -> Self {
        assert!(
            vector.len() <= 8 * maximumWordCount,
            "an entry of a block has at most 96 bytes"
        );
        let mut powers = [[0u64; 8]; maximumWordCount];
        for (wordPowers, chunk) in powers.iter_mut().zip(vector.chunks(8)) {
            let mut word = loadWord(chunk);
            wordPowers[0] = word;
            for power in &mut wordPowers[1..F::elementBits as usize] {
                word = F::timesGenerator(word);
                *power = word;
            }
        }
        GeneratorPowers {
            powers,
            field: PhantomData,
        }
    }

    /// Adds the vector times a scalar to the words of an entry of the length of the vector.
    #[inline(always)]
    pub(crate) fn addProduct(&self, accumulator: &mut [u64], scalar: u8) {
        let masks = F::scalarMasks(scalar);
        for (word, powers) in accumulator.iter_mut().zip(&self.powers) {
            *word ^= (powers[0] & masks[0])
                ^ (powers[1] & masks[1])
                ^ (powers[2] & masks[2])
                ^ (powers[3] & masks[3])
                ^ (powers[4] & masks[4])
                ^ (powers[5] & masks[5])
                ^ (powers[6] & masks[6])
                ^ (powers[7] & masks[7]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GeneratorPowers;
    use crate::FieldArithmetic;
    use crate::PaddedEntries;
    use crate::gf16::GF16;
    use crate::gf256::GF256;
    use crate::testInputs::sequence;

    /// Checks the sum of the powers against the product of each element by the scalar, which
    /// the field tests compare with the definition and with the C code.
    fn checkEveryScalar<F: FieldArithmetic>(length: usize, scalars: core::ops::Range<u16>) {
        let vector = sequence(length, length as u32);
        let powers = GeneratorPowers::<F>::new(&vector);
        let start = sequence(length, 7);
        for scalar in scalars {
            let scalar = scalar as u8;
            let mut accumulator = PaddedEntries::new(&start, length);
            powers.addProduct(accumulator.entryMut(0), scalar);
            let mut sum = vec![0u8; length];
            accumulator.writeBytes(&mut sum);
            for index in 0..length * F::elementsPerByte {
                let expected =
                    F::element(&start, index) ^ F::product(F::element(&vector, index), scalar);
                assert_eq!(
                    F::element(&sum, index),
                    expected,
                    "length {length}, scalar {scalar}, element {index}"
                );
            }
        }
    }

    #[test]
    fn theSumOfThePowersIsTheProductOfEachElement() {
        // The entry lengths of the four shapes, 44 with a tail of four bytes, and a vector of
        // one byte.
        for length in [32, 44, 72, 96, 1] {
            checkEveryScalar::<GF256>(length, 0..256);
            checkEveryScalar::<GF16>(length, 0..16);
        }
    }

    #[test]
    #[should_panic(expected = "an entry of a block has at most 96 bytes")]
    fn aVectorLongerThanTheLongestEntryIsRefused() {
        let _ = GeneratorPowers::<GF256>::new(&[0u8; 97]);
    }
}
