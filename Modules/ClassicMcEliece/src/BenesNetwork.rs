use crate::Parameters;
use alloc::vec;
use alloc::vec::Vec;

/// The Benes network of a secret key, `benes.c` and `transpose.c` of the C code: the control
/// bits set the conditional swaps of the network, and the network permutes the field elements
/// into the support of the Goppa code.
///
/// The network acts on a row of `2^m` bits. The C code keeps the row as 64-bit words and
/// transposes 64 by 64 blocks, so that each swap is a masked exclusive or of two words. Every
/// setting of the control bits gives a permutation, so a secret key with any bytes gives a
/// support of distinct elements.
pub(crate) struct BenesNetwork<'parameters> {
    parameters: &'parameters Parameters,
}

/// The masks of the steps of `transpose_64x64`, from the swap of single bits to the swap of
/// halves.
const transposeMasks: [[u64; 2]; 6] = [
    [0x5555_5555_5555_5555, 0xAAAA_AAAA_AAAA_AAAA],
    [0x3333_3333_3333_3333, 0xCCCC_CCCC_CCCC_CCCC],
    [0x0F0F_0F0F_0F0F_0F0F, 0xF0F0_F0F0_F0F0_F0F0],
    [0x00FF_00FF_00FF_00FF, 0xFF00_FF00_FF00_FF00],
    [0x0000_FFFF_0000_FFFF, 0xFFFF_0000_FFFF_0000],
    [0x0000_0000_FFFF_FFFF, 0xFFFF_FFFF_0000_0000],
];

impl<'parameters> BenesNetwork<'parameters> {
    /// Makes the network of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        BenesNetwork { parameters }
    }

    /// The transpose of a 64 by 64 matrix of bits in place, `transpose_64x64`: word `i` is
    /// row `i`, and bit `j` of a word is column `j`.
    pub(crate) fn transpose(words: &mut [u64; 64]) {
        for (step, masks) in transposeMasks.iter().enumerate().rev() {
            let stride = 1 << step;
            for start in (0..64).step_by(2 * stride) {
                for index in start..start + stride {
                    let low =
                        (words[index] & masks[0]) | ((words[index + stride] & masks[0]) << stride);
                    let high =
                        ((words[index] & masks[1]) >> stride) | (words[index + stride] & masks[1]);
                    words[index] = low;
                    words[index + stride] = high;
                }
            }
        }
    }

    /// The little-endian word of eight bytes, `load8`.
    fn loadedWord(bytes: &[u8]) -> u64 {
        u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"))
    }

    /// The little-endian value of four bytes, `load4`.
    fn loadedHalfWord(bytes: &[u8]) -> u64 {
        u64::from(u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")))
    }

    /// One layer of conditional swaps of words at a stride of `2^strideLogarithm`, `layer` of
    /// the network of 4096 bits and `layer_ex` of the network of 8192 bits. Each pair takes the
    /// next word of conditions.
    fn swapLayer(words: &mut [u64], conditions: &[u64], strideLogarithm: usize) {
        let stride = 1 << strideLogarithm;
        let mut condition = conditions.iter();
        for start in (0..words.len()).step_by(2 * stride) {
            for index in start..start + stride {
                let difference =
                    (words[index] ^ words[index + stride]) & condition.next().expect("a condition");
                words[index] ^= difference;
                words[index + stride] ^= difference;
            }
        }
    }

    /// The middle layer `layer_in` of the network of 8192 bits: the swaps of the two halves at
    /// the same places, which take the words of conditions in turn.
    fn swapMiddleLayer(halves: &mut [[u64; 64]; 2], conditions: &[u64], strideLogarithm: usize) {
        let stride = 1 << strideLogarithm;
        let mut condition = conditions.iter();
        for start in (0..64).step_by(2 * stride) {
            for index in start..start + stride {
                for half in halves.iter_mut() {
                    let difference = (half[index] ^ half[index + stride])
                        & condition.next().expect("a condition");
                    half[index] ^= difference;
                    half[index + stride] ^= difference;
                }
            }
        }
    }

    /// The network of 4096 bits of the sets with m = 12, `apply_benes` with `rev = 0`.
    fn applied4096(row: &mut [u8], bits: &[u8]) {
        let mut words = [0u64; 64];
        for (word, bytes) in words.iter_mut().zip(row.chunks_exact(8)) {
            *word = Self::loadedWord(bytes);
        }
        let mut offset = 0;
        let transposedConditions = |offset: usize| {
            let mut conditions = [0u64; 64];
            for (condition, bytes) in conditions.iter_mut().zip(bits[offset..].chunks_exact(4)) {
                *condition = Self::loadedHalfWord(bytes);
            }
            Self::transpose(&mut conditions);
            conditions
        };
        let directConditions = |offset: usize| {
            let mut conditions = [0u64; 32];
            for (condition, bytes) in conditions.iter_mut().zip(bits[offset..].chunks_exact(8)) {
                *condition = Self::loadedWord(bytes);
            }
            conditions
        };
        Self::transpose(&mut words);
        for strideLogarithm in 0..=5 {
            Self::swapLayer(&mut words, &transposedConditions(offset), strideLogarithm);
            offset += 256;
        }
        Self::transpose(&mut words);
        for strideLogarithm in (0..=5).chain((0..=4).rev()) {
            Self::swapLayer(&mut words, &directConditions(offset), strideLogarithm);
            offset += 256;
        }
        Self::transpose(&mut words);
        for strideLogarithm in (0..=5).rev() {
            Self::swapLayer(&mut words, &transposedConditions(offset), strideLogarithm);
            offset += 256;
        }
        Self::transpose(&mut words);
        for (bytes, word) in row.chunks_exact_mut(8).zip(words) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
    }

    /// The network of 8192 bits of the sets with m = 13, `apply_benes` with `rev = 0`.
    fn applied8192(row: &mut [u8], bits: &[u8]) {
        // The two halves of `r_int_v` hold the bytes 0 to 7 and 8 to 15 of each 16 bytes.
        let mut vertical = [[0u64; 64]; 2];
        for (index, bytes) in row.chunks_exact(16).enumerate() {
            vertical[0][index] = Self::loadedWord(&bytes[..8]);
            vertical[1][index] = Self::loadedWord(&bytes[8..]);
        }
        let mut offset = 0;
        let conditions = |offset: usize| {
            let mut words = [0u64; 64];
            for (word, bytes) in words.iter_mut().zip(bits[offset..].chunks_exact(8)) {
                *word = Self::loadedWord(bytes);
            }
            words
        };
        let transposed = |halves: &[[u64; 64]; 2]| {
            let mut words = [0u64; 128];
            for (half, target) in halves.iter().zip(words.chunks_exact_mut(64)) {
                let mut block = *half;
                Self::transpose(&mut block);
                target.copy_from_slice(&block);
            }
            words
        };
        let untransposed = |words: &[u64; 128]| {
            let mut halves = [[0u64; 64]; 2];
            for (half, source) in halves.iter_mut().zip(words.chunks_exact(64)) {
                half.copy_from_slice(source);
                Self::transpose(half);
            }
            halves
        };
        let mut horizontal = transposed(&vertical);
        for strideLogarithm in 0..=6 {
            let mut block = conditions(offset);
            Self::transpose(&mut block);
            Self::swapLayer(&mut horizontal, &block, strideLogarithm);
            offset += 512;
        }
        vertical = untransposed(&horizontal);
        for strideLogarithm in (0..=5).chain((0..=4).rev()) {
            Self::swapMiddleLayer(&mut vertical, &conditions(offset), strideLogarithm);
            offset += 512;
        }
        horizontal = transposed(&vertical);
        for strideLogarithm in (0..=6).rev() {
            let mut block = conditions(offset);
            Self::transpose(&mut block);
            Self::swapLayer(&mut horizontal, &block, strideLogarithm);
            offset += 512;
        }
        vertical = untransposed(&horizontal);
        for (index, bytes) in row.chunks_exact_mut(16).enumerate() {
            bytes[..8].copy_from_slice(&vertical[0][index].to_le_bytes());
            bytes[8..].copy_from_slice(&vertical[1][index].to_le_bytes());
        }
    }

    /// Applies the network of the control bits to a row of `2^m` bits, `apply_benes` with
    /// `rev = 0`.
    pub(crate) fn apply(&self, row: &mut [u8], bits: &[u8]) {
        if self.parameters.fieldBits == 12 {
            Self::applied4096(row, bits);
        } else {
            Self::applied8192(row, bits);
        }
    }

    /// The support of the Goppa code, `support_gen`: the network of the control bits applied to
    /// the bit-reversed field elements in bit-sliced form, and the first `n` elements read back.
    pub(crate) fn support(&self, controlBits: &[u8]) -> Vec<u16> {
        let parameters = self.parameters;
        let field = parameters.field();
        let bits = parameters.fieldBits as usize;
        let size = parameters.fieldSize();
        let mut slices = vec![vec![0u8; size / 8]; bits];
        for element in 0..size {
            let reversed = field.reversed(element as u16);
            for (bit, slice) in slices.iter_mut().enumerate() {
                slice[element / 8] += (((reversed >> bit) & 1) as u8) << (element % 8);
            }
        }
        for slice in slices.iter_mut() {
            self.apply(slice, controlBits);
        }
        (0..parameters.codeLength)
            .map(|position| {
                slices.iter().rev().fold(0u16, |value, slice| {
                    (value << 1) + u16::from((slice[position / 8] >> (position % 8)) & 1)
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::BenesNetwork;
    use crate::controlBits::ControlBits;
    use crate::controlBits::tests::{routedIdentity, seededPermutation};
    use crate::parameters::{classicMcEliece348864, classicMcEliece460896, classicMcEliece8192128};
    use crate::testSupport::digest;
    use OQSNativeAlgorithmTests::FuzzRandom;

    #[test]
    fn transposeSwapsRowsAndColumns() {
        let mut words = FuzzRandom::seeded(64);
        let original: [u64; 64] = core::array::from_fn(|_| words.nextWord());
        let mut transposed = original;
        BenesNetwork::transpose(&mut transposed);
        for (row, transposedRow) in transposed.iter().enumerate() {
            for (column, originalRow) in original.iter().enumerate() {
                assert_eq!((transposedRow >> column) & 1, (originalRow >> row) & 1);
            }
        }
        BenesNetwork::transpose(&mut transposed);
        assert_eq!(transposed, original);
    }

    #[test]
    fn theNetworkOfThePermutationBitsMovesEachBitAsTheCheckOfTheCCode() {
        // The control bits of a permutation route the identity to the permutation, so the
        // network moves the bit at place pi[i] to place i.
        for (parameters, logarithm) in [(&classicMcEliece348864, 12), (&classicMcEliece460896, 13)]
        {
            let network = BenesNetwork::new(parameters);
            let permutation = seededPermutation(7, logarithm);
            let bits = ControlBits::ofPermutation(&permutation, logarithm);
            assert_eq!(routedIdentity(&bits, logarithm), permutation);
            let size = 1usize << logarithm;
            let mut words = FuzzRandom::seeded(8);
            let row: Vec<u8> = (0..size / 8).map(|_| words.nextWord() as u8).collect();
            let mut permuted = row.clone();
            network.apply(&mut permuted, &bits);
            for (place, source) in permutation.iter().enumerate() {
                let source = *source as usize;
                assert_eq!(
                    (permuted[place / 8] >> (place % 8)) & 1,
                    (row[source / 8] >> (source % 8)) & 1,
                    "{logarithm} bits, place {place}"
                );
            }
        }
    }

    #[test]
    fn theSupportOfThePermutationBitsIsTheReversedPermutation() {
        // `pk_gen` sets the support to bitrev(pi[i]), and the control bits of pi give the same
        // support back.
        for (parameters, logarithm) in [
            (&classicMcEliece348864, 12),
            (&classicMcEliece460896, 13),
            (&classicMcEliece8192128, 13),
        ] {
            let field = parameters.field();
            let permutation = seededPermutation(5, logarithm);
            let bits = ControlBits::ofPermutation(&permutation, logarithm);
            let support = BenesNetwork::new(parameters).support(&bits);
            assert_eq!(support.len(), parameters.codeLength);
            for (element, value) in support.iter().zip(&permutation) {
                assert_eq!(*element, field.reversed(*value as u16));
            }
        }
    }

    #[test]
    fn zeroControlBitsGiveTheReversedIdentity() {
        let parameters = &classicMcEliece460896;
        let support = BenesNetwork::new(parameters).support(&vec![0u8; 12_800]);
        for (position, element) in support.iter().enumerate() {
            assert_eq!(*element, parameters.field().reversed(position as u16));
        }
    }

    #[test]
    fn networksAndSupportsGiveTheKnownAnswersOfTheCFunctions() {
        // The SHA3-256 of the rows after `apply_benes` and of the supports of `support_gen` of
        // `pqclean_mceliece348864_clean`, `pqclean_mceliece460896_clean` and
        // `pqclean_mceliece8192128_clean` in liboqs 0.16.0, with control bits of any value from
        // SplitMix64 of the seed 21 and a row from the seed 22. The supports are little-endian
        // 16-bit values.
        let expected = [
            (
                &classicMcEliece348864,
                "2b2c31276e658a9c3a44d3783760e3a0267da1cc6c6776946a3595fbe1e3b698",
                "c4db8ebde6a7f1820a445cc01b1fe08a412682de9f240b7abe6410e246cd93be",
            ),
            (
                &classicMcEliece460896,
                "7309d6dab1c1ba87d789efbc82d8ec5668e90b0160b5c7b21f642375c736ee14",
                "1099ccbb4d36cda104a19aa33e3eb234400538135a5a49655a4c9eb1ef3c7603",
            ),
            (
                &classicMcEliece8192128,
                "7309d6dab1c1ba87d789efbc82d8ec5668e90b0160b5c7b21f642375c736ee14",
                "f99f89ff00c83a29991976b02e2d003e8620af799c9c672afcca1b280e320612",
            ),
        ];
        for (parameters, rowDigest, supportDigest) in expected {
            let network = BenesNetwork::new(parameters);
            let mut words = FuzzRandom::seeded(21);
            let bits: Vec<u8> = (0..parameters.controlBitsLength())
                .map(|_| words.nextWord() as u8)
                .collect();
            let mut words = FuzzRandom::seeded(22);
            let mut row: Vec<u8> = (0..parameters.fieldSize() / 8)
                .map(|_| words.nextWord() as u8)
                .collect();
            network.apply(&mut row, &bits);
            let support: Vec<u8> = network
                .support(&bits)
                .iter()
                .flat_map(|element| element.to_le_bytes())
                .collect();
            let name = parameters.description.name;
            assert_eq!(digest(&row), rowDigest, "{name}");
            assert_eq!(digest(&support), supportDigest, "{name}");
        }
    }
}
