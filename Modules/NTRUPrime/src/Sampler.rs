use crate::Parameters;
use OQSNativeDomain::RandomGenerating;
use OQSNativeEntities::SecretBytes;
use OQSNativeSortingNetwork::SortingNetwork;
use alloc::vec::Vec;

/// The random small polynomials of `sntrup761.c`: `Small_random`, `Short_random` and
/// `Short_fromlist`.
///
/// Each polynomial takes `p` random 32-bit words in one request of `4 p` bytes, read in the
/// byte order of a little-endian processor, as the C code reads the words of its buffer on the
/// platforms of liboqs.
pub(crate) struct Sampler<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> Sampler<'parameters> {
    /// Makes the sampler of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Sampler { parameters }
    }

    /// The `p` words of one request of random bytes.
    fn randomWords(&self, random: &mut dyn RandomGenerating) -> Vec<u32> {
        let mut bytes = SecretBytes::zeroed(self.parameters.wordRequestLength());
        random.fillRandomBytes(bytes.mutableBytes());
        Self::words(bytes.bytes())
    }

    /// The little-endian 32-bit words of bytes.
    pub(crate) fn words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect()
    }

    /// A small polynomial with independent coefficients, `Small_random`: each word gives
    /// `floor(3 w / 2^30) - 1` of its low 30 bits.
    pub(crate) fn smallPolynomial(&self, random: &mut dyn RandomGenerating) -> Vec<i8> {
        Self::smallFromWords(&self.randomWords(random))
    }

    /// The coefficients of `Small_random` for its words.
    pub(crate) fn smallFromWords(words: &[u32]) -> Vec<i8> {
        words
            .iter()
            .map(|word| (((word & 0x3FFF_FFFF) * 3) >> 30) as i8 - 1)
            .collect()
    }

    /// A short polynomial of weight `w`, `Short_random`.
    pub(crate) fn shortPolynomial(&self, random: &mut dyn RandomGenerating) -> Vec<i8> {
        self.shortFromWords(&self.randomWords(random))
    }

    /// The short polynomial of a list of words, `Short_fromlist`: the first `w` words get an
    /// even mark, 1 or -1 after the shift, and the others the mark 0. A sort of the words
    /// moves the marks to random places.
    pub(crate) fn shortFromWords(&self, words: &[u32]) -> Vec<i8> {
        let weight = self.parameters.weight;
        let mut marked: Vec<u32> = words
            .iter()
            .enumerate()
            .map(|(index, word)| {
                if index < weight {
                    word & !1
                } else {
                    (word & !2) | 1
                }
            })
            .collect();
        SortingNetwork::sortUnsigned(&mut marked);
        marked.iter().map(|word| (word & 3) as i8 - 1).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Sampler;
    use crate::parameters::sntrup761;
    use crate::testInputs::{cAnswer, sequence, smallBytes, wordSequence};
    use OQSNativeAlgorithmTests::OutputDigest;

    fn words(seed: u32) -> Vec<u32> {
        sequence(2 * 761, seed)
            .chunks_exact(2)
            .map(|pair| (u32::from(pair[0]) << 16) + u32::from(pair[1]))
            .collect()
    }

    #[test]
    fn smallCoefficientsAreTheThirdsOfTheLowThirtyBits() {
        // 0 to 2^30 / 3 gives -1, then 0, then 1, and the two high bits do not count.
        let words = [
            0,
            0x1555_5555,
            0x1555_5556,
            0x2AAA_AAAA,
            0x2AAA_AAAB,
            0x3FFF_FFFF,
            0xC000_0000,
            0xFFFF_FFFF,
        ];
        assert_eq!(
            Sampler::smallFromWords(&words),
            vec![-1, -1, 0, 0, 1, 1, -1, 1]
        );
    }

    #[test]
    fn aShortPolynomialHasTheWeightAndThePlacesOfTheSortedWords() {
        let sampler = Sampler::new(&sntrup761);
        for seed in 0..4 {
            let words = words(seed);
            let short = sampler.shortFromWords(&words);
            assert_eq!(short.len(), 761);
            assert_eq!(short.iter().filter(|value| **value != 0).count(), 286);
            assert!(short.iter().all(|value| (-1..=1).contains(value)));
            // The marked words in sorted order give the coefficients.
            let mut marked: Vec<u32> = words
                .iter()
                .enumerate()
                .map(|(index, word)| {
                    if index < 286 {
                        word & !1
                    } else {
                        (word & !2) | 1
                    }
                })
                .collect();
            marked.sort_unstable();
            let expected: Vec<i8> = marked.iter().map(|word| (word & 3) as i8 - 1).collect();
            assert_eq!(short, expected, "seed {seed}");
        }
    }

    #[test]
    fn wordsAreLittleEndian() {
        assert_eq!(
            Sampler::words(&[1, 2, 3, 4, 0xFF, 0, 0, 0x80]),
            vec![0x0403_0201, 0x8000_00FF]
        );
    }

    #[test]
    fn theSamplesOfWordsHaveTheCoefficientsOfTheCFunctions() {
        // Short_fromlist and the formula of Small_random of liboqs 0.16.0 on the same words.
        let short = Sampler::new(&sntrup761).shortFromWords(&wordSequence(2));
        assert_eq!(
            OutputDigest::of(&smallBytes(&short)),
            cAnswer("shortFromWords")
        );
        let small = Sampler::smallFromWords(&wordSequence(13));
        assert_eq!(
            OutputDigest::of(&smallBytes(&small)),
            cAnswer("smallFromWords")
        );
    }
}
