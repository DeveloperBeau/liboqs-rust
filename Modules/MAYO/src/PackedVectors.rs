//! The arithmetic of packed vectors, as `arithmetic_fixed.h` computes it. A packed vector holds
//! m elements of GF(16), 16 to a 64-bit word with element i in bits `4 (i mod 16)` of word
//! `i / 16`. The C code calls it an m_vec. Each operation works on each nibble alone, so the
//! unused nibbles of the last word never reach the used ones.

use crate::field;
use alloc::vec;
use alloc::vec::Vec;

/// The bit 0 of each nibble of a word.
const lowBits: u64 = 0x1111_1111_1111_1111;

/// The bit 3 of each nibble of a word.
const highBits: u64 = 0x8888_8888_8888_8888;

/// Adds a packed vector to another, as `m_vec_add`.
pub(crate) fn add(input: &[u64], accumulator: &mut [u64]) {
    for (sum, word) in accumulator.iter_mut().zip(input) {
        *sum ^= word;
    }
}

/// Adds the product of a packed vector and an element to another packed vector, as
/// `m_vec_mul_add` and `vec_mul_add_u64`: the bit b of each nibble times the product of the
/// element with x^b.
pub(crate) fn multiplyAdd(input: &[u64], scalar: u8, accumulator: &mut [u64]) {
    let table = field::multiplicationTable(scalar);
    let byProduct = [
        u64::from(table & 0xFF),
        u64::from((table >> 8) & 0x0F),
        u64::from((table >> 16) & 0x0F),
        u64::from((table >> 24) & 0x0F),
    ];
    for (sum, word) in accumulator.iter_mut().zip(input) {
        *sum ^= ((word & lowBits) * byProduct[0])
            ^ (((word >> 1) & lowBits) * byProduct[1])
            ^ (((word >> 2) & lowBits) * byProduct[2])
            ^ (((word >> 3) & lowBits) * byProduct[3]);
    }
}

/// The product of each nibble of a word with x, as the inner step of `m_vec_mul_add_x`.
fn timesX(word: u64) -> u64 {
    let top = word & highBits;
    ((word ^ top) << 1) ^ ((top >> 3) * 3)
}

/// The product of each nibble of a word with x^-1 = x^3 + 1, as the inner step of
/// `m_vec_mul_add_x_inv`.
fn timesInverseX(word: u64) -> u64 {
    let bottom = word & lowBits;
    ((word ^ bottom) >> 1) ^ (bottom * 9)
}

/// The steps of `m_vec_multiply_bins`: each adds the bin `from`, times x^-1 or x, to the bin
/// `to`. The chain leaves in bin 1 the sum of the products of each bin with its number.
const binSteps: [(usize, usize, bool); 14] = [
    (5, 10, true),
    (11, 12, false),
    (10, 7, true),
    (12, 6, false),
    (7, 14, true),
    (6, 3, false),
    (14, 15, true),
    (3, 8, false),
    (15, 13, true),
    (8, 4, false),
    (13, 9, true),
    (4, 2, false),
    (9, 1, true),
    (2, 1, false),
];

/// The sum of the products of 16 bins of packed vectors with the element of the number of each
/// bin, as `m_vec_multiply_bins`. The bins change in the process.
pub(crate) fn multiplyBins(bins: &mut [u64], limbCount: usize, output: &mut [u64]) {
    for (from, to, isInverse) in binSteps {
        for limb in 0..limbCount {
            let word = bins[from * limbCount + limb];
            bins[to * limbCount + limb] ^= if isInverse {
                timesInverseX(word)
            } else {
                timesX(word)
            };
        }
    }
    output[..limbCount].copy_from_slice(&bins[limbCount..2 * limbCount]);
}

/// The element of a packed vector at an index, as `m_extract_element`.
pub(crate) fn element(vector: &[u64], index: usize) -> u8 {
    ((vector[index / 16] >> (4 * (index % 16))) & 0x0F) as u8
}

/// The packed vectors of bytes that hold m elements each, m / 2 bytes to a vector, as
/// `unpack_m_vecs`. The unused nibbles of the last word of each vector are zero.
pub(crate) fn unpacked(bytes: &[u8], vectorBytes: usize, limbCount: usize) -> Vec<u64> {
    let mut vectors = vec![0u64; bytes.len() / vectorBytes * limbCount];
    for (vector, packed) in vectors
        .chunks_exact_mut(limbCount)
        .zip(bytes.chunks_exact(vectorBytes))
    {
        for (word, chunk) in vector.iter_mut().zip(packed.chunks(8)) {
            let mut wordBytes = [0u8; 8];
            wordBytes[..chunk.len()].copy_from_slice(chunk);
            *word = u64::from_le_bytes(wordBytes);
        }
    }
    vectors
}

/// The bytes of packed vectors, m / 2 bytes to a vector, as `pack_m_vecs`.
pub(crate) fn pack(vectors: &[u64], limbCount: usize, vectorBytes: usize, bytes: &mut [u8]) {
    for (vector, packed) in vectors
        .chunks_exact(limbCount)
        .zip(bytes.chunks_exact_mut(vectorBytes))
    {
        for (word, chunk) in vector.iter().zip(packed.chunks_mut(8)) {
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{add, element, multiplyAdd, multiplyBins, pack, timesInverseX, timesX, unpacked};
    use crate::field::product;

    /// Seeded words, the same for each test run.
    fn seededWords(seed: u64, count: usize) -> Vec<u64> {
        let mut state = seed;
        (0..count)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                state ^ (state >> 29)
            })
            .collect()
    }

    fn nibble(word: u64, index: usize) -> u8 {
        ((word >> (4 * index)) & 0x0F) as u8
    }

    #[test]
    fn multiplyAddAddsTheProductOfEachNibble() {
        let input = seededWords(1, 9);
        for scalar in 0..16 {
            let start = seededWords(2 + u64::from(scalar), 9);
            let mut accumulator = start.clone();
            multiplyAdd(&input, scalar, &mut accumulator);
            for word in 0..9 {
                for index in 0..16 {
                    assert_eq!(
                        nibble(accumulator[word], index),
                        nibble(start[word], index) ^ product(scalar, nibble(input[word], index)),
                        "{scalar}, word {word}, nibble {index}"
                    );
                }
            }
        }
        let mut sum = vec![5u64; 3];
        add(&[1, 2, 3], &mut sum);
        assert_eq!(sum, [4, 7, 6]);
    }

    #[test]
    fn timesXAndItsInverseMultiplyEachNibble() {
        for word in seededWords(3, 50) {
            for index in 0..16 {
                let value = nibble(word, index);
                assert_eq!(nibble(timesX(word), index), product(value, 2));
                // x^-1 is x^3 + 1, the element 9.
                assert_eq!(nibble(timesInverseX(word), index), product(value, 9));
            }
        }
        assert_eq!(product(2, 9), 1);
    }

    #[test]
    fn binsGiveTheSumOfTheProductsOfEachBinWithItsNumber() {
        for limbCount in [4usize, 5, 7, 9] {
            let original = seededWords(limbCount as u64, 16 * limbCount);
            let mut bins = original.clone();
            let mut output = vec![0u64; limbCount];
            multiplyBins(&mut bins, limbCount, &mut output);
            let mut expected = vec![0u64; limbCount];
            for bin in 0..16 {
                multiplyAdd(
                    &original[bin * limbCount..(bin + 1) * limbCount],
                    bin as u8,
                    &mut expected,
                );
            }
            assert_eq!(output, expected, "{limbCount} words");
        }
    }

    #[test]
    fn unpackingReadsHalfBytesOfEachVectorAndPackingWritesThem() {
        // Two vectors of m = 18 elements: 9 bytes each, in two words with 14 unused nibbles.
        let bytes: Vec<u8> = (1..=18).collect();
        let vectors = unpacked(&bytes, 9, 2);
        assert_eq!(
            vectors,
            [0x0807_0605_0403_0201, 0x09, 0x1110_0F0E_0D0C_0B0A, 0x12]
        );
        assert_eq!(element(&vectors[..2], 0), 1);
        assert_eq!(element(&vectors[..2], 1), 0);
        assert_eq!(element(&vectors[..2], 16), 9);
        assert_eq!(element(&vectors[2..], 15), 1);
        let mut packed = vec![0u8; 18];
        pack(&vectors, 2, 9, &mut packed);
        assert_eq!(packed, bytes);
    }
}
