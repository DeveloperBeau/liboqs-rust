use crate::Parameters;
use crate::carrylessMultiplication::CarrylessMultiplication;
use OQSNativeSHA3::SHAKEReader;
use alloc::vec::Vec;

/// A vector of HQC, which is also a polynomial of the ring `F2[X]/(X^n - 1)`, `vector.c` and
/// `gf2x.c` of the reference code.
///
/// The bits are in 64-bit words: bit `i` of the vector is bit `i % 64` of word `i / 64`. The
/// byte form is the words in little-endian order, as the C code copies its word arrays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BinaryVector {
    pub(crate) words: Vec<u64>,
}

impl BinaryVector {
    /// The vector of the bytes, in `wordCount` words. The bytes past the input are zero.
    pub(crate) fn fromBytes(bytes: &[u8], wordCount: usize) -> Self {
        let mut words = alloc::vec![0u64; wordCount];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
            let mut buffer = [0u8; 8];
            buffer[..chunk.len()].copy_from_slice(chunk);
            *word = u64::from_le_bytes(buffer);
        }
        BinaryVector { words }
    }

    /// The first `length` bytes of the byte form.
    pub(crate) fn bytes(&self, length: usize) -> Vec<u8> {
        self.words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(length)
            .collect()
    }

    /// The sum of two vectors, word by word over the shorter one, `vect_add`.
    pub(crate) fn plus(&self, other: &BinaryVector) -> BinaryVector {
        BinaryVector {
            words: self
                .words
                .iter()
                .zip(&other.words)
                .map(|(left, right)| left ^ right)
                .collect(),
        }
    }

    /// The first `wordCount` words, `vect_truncate` with the words that the caller reads.
    pub(crate) fn truncated(&self, wordCount: usize) -> BinaryVector {
        BinaryVector {
            words: self.words[..wordCount].to_vec(),
        }
    }

    /// The product of two vectors modulo `X^n - 1`, `vect_mul`.
    ///
    /// The reduction is the one of the C code: the bits from `n` to `2 n` fold back onto the
    /// bits from 0, and the bits of the last word at and above `n` are cleared. Valid vectors
    /// have no bit at or above `n`, so the product is exact. A vector of a hostile key or
    /// ciphertext can have the bits of its last byte above `n`, and then the product keeps the
    /// result of the C code.
    pub(crate) fn product(&self, other: &BinaryVector, parameters: &Parameters) -> BinaryVector {
        let wordCount = parameters.vectorWordCount();
        let unreduced = CarrylessMultiplication::product(&self.words, &other.words);
        let shift = parameters.vectorLength % 64;
        let mut words = alloc::vec![0u64; wordCount];
        for (index, word) in words.iter_mut().enumerate() {
            let folded = unreduced[index + wordCount - 1] >> shift;
            let carried = unreduced[index + wordCount] << (64 - shift);
            *word = unreduced[index] ^ folded ^ carried;
        }
        words[wordCount - 1] &= parameters.lastWordMask();
        BinaryVector { words }
    }

    /// A uniform vector of `n` bits from the stream of an expander, `vect_set_random`: the bytes
    /// of the encoded length, with the bits at and above `n` cleared.
    pub(crate) fn sampledUniform(expander: &mut SHAKEReader, parameters: &Parameters) -> Self {
        let mut bytes = alloc::vec![0u8; parameters.vectorByteCount()];
        expander.squeeze(&mut bytes);
        let mut vector = Self::fromBytes(&bytes, parameters.vectorWordCount());
        let last = vector.words.len() - 1;
        vector.words[last] &= parameters.lastWordMask();
        vector
    }

    /// A vector of a weight whose positions come by rejection sampling, `vect_sample_fixed_weight1`
    /// of key generation.
    ///
    /// Each candidate is three bytes of the stream, read as a little-endian 24-bit number. A
    /// candidate at or above the rejection threshold, or a position that is already taken, is
    /// skipped.
    pub(crate) fn sampledByRejection(
        expander: &mut SHAKEReader,
        weight: usize,
        parameters: &Parameters,
    ) -> Self {
        let nextCandidate = || {
            let mut bytes = [0u8; 4];
            expander.squeeze(&mut bytes[..3]);
            u32::from_le_bytes(bytes)
        };
        let support = rejectionSupport(nextCandidate, weight, parameters);
        Self::withSupport(&support, parameters.vectorWordCount())
    }

    /// A vector of a weight whose positions come from one block of the stream with no
    /// rejection, `vect_sample_fixed_weight2` of encryption, Algorithm 5 of ePrint 2021/1631.
    ///
    /// Position `i` is `i + floor(r_i (n - i) / 2^32)` for the little-endian 32-bit number
    /// `r_i`. From the second to last position down to the first, a position equal to a later
    /// one becomes `i`, which no later position can be.
    pub(crate) fn sampledWithoutRejection(
        expander: &mut SHAKEReader,
        weight: usize,
        parameters: &Parameters,
    ) -> Self {
        let mut block = alloc::vec![0u8; 4 * weight];
        expander.squeeze(&mut block);
        let support = supportWithoutRejection(&block, parameters.vectorLength);
        Self::withSupport(&support, parameters.vectorWordCount())
    }

    /// The vector with the bits of a support set, `vect_write_support_to_vector`: every word
    /// looks at every position, so the time does not depend on the positions.
    fn withSupport(support: &[u32], wordCount: usize) -> Self {
        let mut words = alloc::vec![0u64; wordCount];
        for (wordIndex, word) in words.iter_mut().enumerate() {
            for position in support {
                let mask = 0u64.wrapping_sub(u64::from(isEqual(position >> 6, wordIndex as u32)));
                *word |= (1u64 << (position & 0x3F)) & mask;
            }
        }
        BinaryVector { words }
    }
}

/// The first `weight` distinct positions of the candidates below the rejection threshold, each
/// reduced modulo `n`, `vect_generate_random_support1`.
fn rejectionSupport(
    mut nextCandidate: impl FnMut() -> u32,
    weight: usize,
    parameters: &Parameters,
) -> Vec<u32> {
    let threshold = parameters.rejectionThreshold();
    let mut support = Vec::with_capacity(weight);
    while support.len() < weight {
        let candidate = nextCandidate();
        if candidate >= threshold {
            continue;
        }
        let position = barrettReduced(candidate, parameters);
        if !support.contains(&position) {
            support.push(position);
        }
    }
    support
}

/// The distinct positions below `n` of a block of four bytes for each position,
/// `vect_generate_random_support2`.
fn supportWithoutRejection(block: &[u8], vectorLength: usize) -> Vec<u32> {
    let vectorLength = vectorLength as u64;
    let mut support: Vec<u32> = block
        .chunks_exact(4)
        .enumerate()
        .map(|(index, chunk)| {
            let random = u64::from(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            let index = index as u64;
            (index + ((random * (vectorLength - index)) >> 32)) as u32
        })
        .collect();
    for index in (0..support.len().saturating_sub(1)).rev() {
        let found = support[index + 1..]
            .iter()
            .fold(0u32, |found, later| found | isEqual(*later, support[index]));
        let mask = 0u32.wrapping_sub(found);
        support[index] ^= mask & (index as u32 ^ support[index]);
    }
    support
}

/// 1 when two numbers are equal and 0 otherwise, with no branch, `compare_u32`.
fn isEqual(left: u32, right: u32) -> u32 {
    1 ^ ((left.wrapping_sub(right) | right.wrapping_sub(left)) >> 31)
}

/// A number below `2^24` modulo `n`, with the Barrett reduction of `barrett_reduce`.
fn barrettReduced(value: u32, parameters: &Parameters) -> u32 {
    let vectorLength = parameters.vectorLength as u32;
    let quotient = ((u64::from(value) * parameters.barrettMultiplier()) >> 32) as u32;
    // The estimate of the quotient is low by at most one, so the remainder is below `2 n`.
    let remainder = value - quotient * vectorLength;
    let isReduced = (remainder.wrapping_sub(vectorLength) >> 31) ^ 1;
    remainder - (0u32.wrapping_sub(isReduced) & vectorLength)
}

#[cfg(test)]
mod tests {
    use super::{BinaryVector, barrettReduced, isEqual, rejectionSupport, supportWithoutRejection};
    use crate::parameters::{hqc1, hqc3, hqc5};
    use OQSNativeSHA3::{SHAKE256, SHAKEReader};

    fn expander(seed: u8) -> SHAKEReader {
        SHAKE256::absorbOnce(&[seed; 32])
    }

    fn weight(vector: &BinaryVector) -> u32 {
        vector.words.iter().map(|word| word.count_ones()).sum()
    }

    fn positions(vector: &BinaryVector) -> Vec<usize> {
        (0..64 * vector.words.len())
            .filter(|position| (vector.words[position / 64] >> (position % 64)) & 1 == 1)
            .collect()
    }

    /// The product by the definition for a sparse left factor: the sum of the right factor
    /// shifted by each position, folded modulo `X^n - 1`.
    fn sparseProduct(
        sparse: &BinaryVector,
        dense: &BinaryVector,
        vectorLength: usize,
    ) -> Vec<usize> {
        let mut bits = vec![0u8; vectorLength];
        for left in positions(sparse) {
            for right in positions(dense) {
                bits[(left + right) % vectorLength] ^= 1;
            }
        }
        (0..vectorLength)
            .filter(|position| bits[*position] == 1)
            .collect()
    }

    #[test]
    fn barrettReductionIsTheRemainderForEveryCandidateBelowTheThreshold() {
        for parameters in [&hqc1, &hqc3, &hqc5] {
            let vectorLength = parameters.vectorLength as u32;
            for value in 0..parameters.rejectionThreshold() {
                assert_eq!(barrettReduced(value, parameters), value % vectorLength);
            }
        }
    }

    #[test]
    fn isEqualComparesEveryPairOfItsRange() {
        for (left, right) in [(0, 0), (5, 5), (u32::MAX, u32::MAX), (1 << 31, 1 << 31)] {
            assert_eq!(isEqual(left, right), 1);
        }
        for (left, right) in [(0, 1), (1, 0), (0, 1 << 31), (u32::MAX, 0), (3, 1 << 31)] {
            assert_eq!(isEqual(left, right), 0);
        }
    }

    #[test]
    fn bytesAndWordsAreLittleEndian() {
        let vector = BinaryVector::fromBytes(&[1, 2, 3, 4, 5, 6, 7, 8, 9], 3);
        assert_eq!(vector.words, vec![0x0807_0605_0403_0201, 9, 0]);
        assert_eq!(vector.bytes(10), vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
        assert_eq!(vector.bytes(3), vec![1, 2, 3]);
    }

    #[test]
    fn uniformVectorsTakeTheStreamAndClearTheBitsAboveN() {
        for parameters in [&hqc1, &hqc3, &hqc5] {
            let vector = BinaryVector::sampledUniform(&mut expander(1), parameters);
            let mut stream = vec![0u8; parameters.vectorByteCount()];
            expander(1).squeeze(&mut stream);
            let bytes = vector.bytes(parameters.vectorByteCount());
            let fullBytes = parameters.vectorLength / 8;
            assert_eq!(&bytes[..fullBytes], &stream[..fullBytes]);
            let lastBits = parameters.vectorLength % 8;
            assert_eq!(bytes[fullBytes], stream[fullBytes] & ((1 << lastBits) - 1));
            assert!(
                positions(&vector)
                    .iter()
                    .all(|position| *position < parameters.vectorLength)
            );
        }
    }

    #[test]
    fn rejectionSamplingKeepsTheFirstDistinctPositionsOfTheStream() {
        // The candidates of the stream by hand: each three bytes below the threshold give the
        // next position, unless that position is already taken.
        let parameters = &hqc1;
        let mut stream = expander(2);
        let vector =
            BinaryVector::sampledByRejection(&mut stream, parameters.secretWeight, parameters);
        let mut reader = expander(2);
        let mut expected = Vec::new();
        while expected.len() < parameters.secretWeight {
            let mut bytes = [0u8; 3];
            reader.squeeze(&mut bytes);
            let candidate =
                u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16);
            if candidate < 16_767_881 {
                let position = (candidate % 17_669) as usize;
                if !expected.contains(&position) {
                    expected.push(position);
                }
            }
        }
        expected.sort_unstable();
        assert_eq!(positions(&vector), expected);
        // The sampler leaves the stream after the last accepted candidate.
        let (mut after, mut expectedAfter) = ([0u8; 8], [0u8; 8]);
        stream.squeeze(&mut after);
        reader.squeeze(&mut expectedAfter);
        assert_eq!(after, expectedAfter);
    }

    #[test]
    fn rejectionSkipsTheThresholdAndRepeatedPositions() {
        // The threshold of HQC-1 is 949 n. A candidate at the threshold or above is skipped, the
        // candidate below it is the last position, and `5 + n` repeats 5.
        let parameters = &hqc1;
        let threshold = parameters.rejectionThreshold();
        let vectorLength = parameters.vectorLength as u32;
        let mut candidates = [
            threshold,
            threshold - 1,
            5,
            5 + vectorLength,
            threshold + 1,
            7,
            9,
        ]
        .into_iter();
        let mut next = || candidates.next().expect("enough candidates");
        assert_eq!(
            rejectionSupport(&mut next, 3, parameters),
            vec![vectorLength - 1, 5, 7]
        );
        // The sampler takes no candidate after the last position.
        assert_eq!(candidates.next(), Some(9));
    }

    #[test]
    fn fixedWeightSamplingFollowsAlgorithmFive() {
        let mut collisionCount = 0;
        for parameters in [&hqc1, &hqc3, &hqc5] {
            let weightCount = parameters.randomnessWeight;
            for seed in 0..12 {
                let vector = BinaryVector::sampledWithoutRejection(
                    &mut expander(seed),
                    weightCount,
                    parameters,
                );
                assert_eq!(weight(&vector), weightCount as u32);
                // The positions by hand from the same block of the stream.
                let mut block = vec![0u8; 4 * weightCount];
                expander(seed).squeeze(&mut block);
                let mut expected: Vec<usize> = block
                    .chunks_exact(4)
                    .enumerate()
                    .map(|(index, chunk)| {
                        let random =
                            u64::from(u32::from_le_bytes(chunk.try_into().expect("4 bytes")));
                        let scaled = (random * (parameters.vectorLength - index) as u64) >> 32;
                        index + scaled as usize
                    })
                    .collect();
                for index in (0..weightCount - 1).rev() {
                    if expected[index + 1..].contains(&expected[index]) {
                        expected[index] = index;
                        collisionCount += 1;
                    }
                }
                expected.sort_unstable();
                assert_eq!(
                    positions(&vector),
                    expected,
                    "{}, seed {seed}",
                    parameters.description.name
                );
            }
        }
        // The seeds reach the replacement of a repeated position.
        assert!(collisionCount > 0);
    }

    #[test]
    fn aRepeatedPositionBecomesItsIndex() {
        let block = |numbers: &[u32]| -> Vec<u8> {
            numbers
                .iter()
                .flat_map(|number| number.to_le_bytes())
                .collect()
        };
        // The largest number gives `n - 1` at the first two indices:
        // `floor((2^32 - 1) n / 2^32)` and `1 + floor((2^32 - 1)(n - 1) / 2^32)`. The first
        // becomes 0. The number 0 gives the index itself.
        assert_eq!(
            supportWithoutRejection(&block(&[u32::MAX, u32::MAX, 0, 0]), 17_669),
            vec![0, 17_668, 2, 3]
        );
        // The positions 1, 5 and 5: index 1 becomes 1, and then index 0 repeats the new value
        // of index 1, so it becomes 0.
        assert_eq!(
            supportWithoutRejection(&block(&[243_080, 972_373, 729_321]), 17_669),
            vec![0, 1, 5]
        );
        // Distinct positions stay as they are.
        assert_eq!(
            supportWithoutRejection(&block(&[1 << 31, 1 << 30, 1 << 29]), 17_669),
            vec![8834, 4418, 2210]
        );
        assert!(supportWithoutRejection(&[], 17_669).is_empty());
        let vector = BinaryVector::withSupport(&[0, 17_668], hqc1.vectorWordCount());
        assert_eq!(positions(&vector), vec![0, 17_668]);
    }

    #[test]
    fn productIsTheProductModuloXToTheNMinusOne() {
        for parameters in [&hqc1, &hqc3] {
            let sparse = BinaryVector::sampledWithoutRejection(&mut expander(4), 20, parameters);
            let dense = BinaryVector::sampledWithoutRejection(&mut expander(5), 300, parameters);
            let product = sparse.product(&dense, parameters);
            assert_eq!(
                positions(&product),
                sparseProduct(&sparse, &dense, parameters.vectorLength)
            );
            assert_eq!(product, dense.product(&sparse, parameters));
        }
        // `X^(n - 1)` times `X` is 1, and times `X^2` is `X`.
        let parameters = &hqc1;
        let wordCount = parameters.vectorWordCount();
        let top = BinaryVector::withSupport(&[17_668], wordCount);
        let one = BinaryVector::withSupport(&[0], wordCount);
        assert_eq!(
            top.product(&BinaryVector::withSupport(&[1], wordCount), parameters),
            one
        );
        assert_eq!(
            top.product(&BinaryVector::withSupport(&[2], wordCount), parameters),
            BinaryVector::withSupport(&[1], wordCount)
        );
    }

    #[test]
    fn productOfABitAboveNFollowsTheReductionOfTheCCode() {
        // The last byte of an encoded vector of HQC-1 holds bits 17664 to 17671, of which 17669
        // to 17671 are above `n`. The C code folds the bits from `n` to `2 n` once, so
        // `X^17671 X^17668 = X^35339` would be `X^1` in the ring, but it is past `2 n` and
        // the C reduction drops it, and `X^17671 X^2 = X^17673` folds to `X^4`.
        let parameters = &hqc1;
        let wordCount = parameters.vectorWordCount();
        let mut hostile = BinaryVector::fromBytes(&[], wordCount);
        hostile.words[276] = 1 << 7;
        let zero = BinaryVector::fromBytes(&[], wordCount);
        assert_eq!(
            hostile.product(&BinaryVector::withSupport(&[17_668], wordCount), parameters),
            zero
        );
        assert_eq!(
            hostile.product(&BinaryVector::withSupport(&[2], wordCount), parameters),
            BinaryVector::withSupport(&[4], wordCount)
        );
    }

    #[test]
    fn sumAndTruncationWorkWordByWord() {
        let left = BinaryVector {
            words: vec![0b1100, 7, 1],
        };
        let right = BinaryVector {
            words: vec![0b1010, 7],
        };
        assert_eq!(left.plus(&right).words, vec![0b0110, 0]);
        assert_eq!(left.truncated(2).words, vec![0b1100, 7]);
    }
}
