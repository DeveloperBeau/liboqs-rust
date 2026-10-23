//! The linear system `A x = y` of a signature attempt, as `compute_A` and `compute_rhs` of
//! `mayo.c` build it. The k (k + 1) / 2 products of the vinegar vectors with the public map
//! each enter the system times a power of z, and f(z) reduces the powers past z^(m - 1).

use crate::Parameters;
use crate::field;
use crate::packedVectors::element;
use alloc::vec;
use alloc::vec::Vec;

/// The bit 0 of each nibble of a word.
const lowBits: u64 = 0x1111_1111_1111_1111;

/// The mask of the used nibbles of the last word of a packed vector of m elements, or `None`
/// when m is a multiple of 16 and every nibble is used.
fn lastWordMask(equationCount: usize) -> Option<u64> {
    (!equationCount.is_multiple_of(16)).then(|| (1u64 << ((equationCount % 16) * 4)) - 1)
}

/// The right-hand side `y = t - sum z^l (v_i P1 v_j^T + v_j P1 v_i^T)` of a signature
/// attempt, as `compute_rhs`. The products are the k by k packed vectors of `V P1 V^T`, whose
/// unused nibbles are cleared first. Each step multiplies the sum by z, reduces z^m with f(z)
/// and adds the next product, from `i = k - 1` down to 0 and `j` from `i` up to `k - 1`.
pub(crate) fn rightHandSide(
    parameters: &Parameters,
    products: &mut [u64],
    target: &[u8],
) -> Vec<u8> {
    let (equationCount, vectorCount) = (parameters.equationCount, parameters.vectorCount);
    let limbCount = parameters.limbCount();
    let last = limbCount - 1;
    if let Some(mask) = lastWordMask(equationCount) {
        for vector in products.chunks_exact_mut(limbCount) {
            vector[last] &= mask;
        }
    }
    let topShift = ((equationCount - 1) % 16) * 4;
    let mut sum = vec![0u64; limbCount];
    for i in (0..vectorCount).rev() {
        for j in i..vectorCount {
            let top = ((sum[last] >> topShift) % 16) as u8;
            sum[last] <<= 4;
            for limb in (0..last).rev() {
                sum[limb + 1] ^= sum[limb] >> 60;
                sum[limb] <<= 4;
            }
            for (place, coefficient) in parameters.reductionTail.iter().enumerate() {
                sum[0] ^= u64::from(field::product(top, *coefficient)) << (4 * place);
            }
            for limb in 0..limbCount {
                let mut term = products[(i * vectorCount + j) * limbCount + limb];
                if i != j {
                    term ^= products[(j * vectorCount + i) * limbCount + limb];
                }
                sum[limb] ^= term;
            }
        }
    }
    target
        .iter()
        .enumerate()
        .map(|(index, value)| value ^ element(&sum, index))
        .collect()
}

/// Transposes a block of 16 words, each a column of 16 nibbles, into 16 rows of 16 nibbles,
/// as `transpose_16x16_nibbles`.
fn transposeNibbles(block: &mut [u64]) {
    const evenNibbles: u64 = 0x0F0F_0F0F_0F0F_0F0F;
    const evenBytes: u64 = 0x00FF_00FF_00FF_00FF;
    const evenPairs: u64 = 0x0000_FFFF_0000_FFFF;
    const evenHalves: u64 = 0x0000_0000_FFFF_FFFF;
    for index in (0..16).step_by(2) {
        let swapped = ((block[index] >> 4) ^ block[index + 1]) & evenNibbles;
        block[index] ^= swapped << 4;
        block[index + 1] ^= swapped;
    }
    for index in (0..16).step_by(4) {
        let first = ((block[index] >> 8) ^ block[index + 2]) & evenBytes;
        let second = ((block[index + 1] >> 8) ^ block[index + 3]) & evenBytes;
        block[index] ^= first << 8;
        block[index + 1] ^= second << 8;
        block[index + 2] ^= first;
        block[index + 3] ^= second;
    }
    for index in 0..4 {
        let first = ((block[index] >> 16) ^ block[index + 4]) & evenPairs;
        let second = ((block[index + 8] >> 16) ^ block[index + 12]) & evenPairs;
        block[index] ^= first << 16;
        block[index + 8] ^= second << 16;
        block[index + 4] ^= first;
        block[index + 12] ^= second;
    }
    for index in 0..8 {
        let swapped = ((block[index] >> 32) ^ block[index + 8]) & evenHalves;
        block[index] ^= swapped << 32;
        block[index + 8] ^= swapped;
    }
}

/// The matrix A of the linear system of a signature attempt, as `compute_A`, from the k
/// matrices `M_i = v_i L` of `V L`, whose unused nibbles are cleared first.
///
/// The step l of the pairs `i <= j`, with i from 0 up and j from k - 1 down to i, adds M_j to
/// the columns of block i and M_i to the columns of block j, each shifted down by l rows. The
/// rows from m up are then reduced with f(z). The matrix has m rows of `k o + 1` elements in
/// row order, then zero rows up to a multiple of 8, which the back substitution of the solution
/// reads. The last column, the place of the right-hand side, is zero.
pub(crate) fn systemMatrix(parameters: &Parameters, vinegarL: &mut [u64]) -> Vec<u8> {
    let equationCount = parameters.equationCount;
    let (oilCount, vectorCount) = (parameters.oilCount, parameters.vectorCount);
    let limbCount = parameters.limbCount();
    let columnCount = parameters.systemColumnCount();
    let width = (oilCount * vectorCount).div_ceil(16) * 16;
    // The words of 16 rows of each column, as the array `A` of the C code.
    let mut words = vec![0u64; width * equationCount.div_ceil(8)];
    if let Some(mask) = lastWordMask(equationCount) {
        for vector in vinegarL.chunks_exact_mut(limbCount) {
            vector[limbCount - 1] &= mask;
        }
    }
    let mut bitsToShift = 0;
    let mut wordsToShift = 0;
    for i in 0..vectorCount {
        for j in (i..vectorCount).rev() {
            let pairs: &[(usize, usize)] = if i == j { &[(i, j)] } else { &[(i, j), (j, i)] };
            for &(block, source) in pairs {
                let matrix = &vinegarL[source * limbCount * oilCount..];
                for column in 0..oilCount {
                    for limb in 0..limbCount {
                        let value = matrix[limb + column * limbCount];
                        let place = oilCount * block + column + (limb + wordsToShift) * width;
                        words[place] ^= value << bitsToShift;
                        if bitsToShift > 0 {
                            words[place + width] ^= value >> (64 - bitsToShift);
                        }
                    }
                }
            }
            bitsToShift += 4;
            if bitsToShift == 64 {
                wordsToShift += 1;
                bitsToShift = 0;
            }
        }
    }
    let reductionRows = vectorCount * (vectorCount + 1) / 2;
    let usedWordRows = (equationCount + reductionRows).div_ceil(16);
    for block in words[..width * usedWordRows].chunks_exact_mut(16) {
        transposeNibbles(block);
    }
    // The products of each coefficient of the tail of f(z) with 1, x, x^2 and x^3.
    let mut table = [0u64; 16];
    for (index, coefficient) in parameters.reductionTail.iter().enumerate() {
        for bit in 0..4 {
            table[4 * index + bit] = u64::from(field::product(*coefficient, 1 << bit));
        }
    }
    for start in (0..width).step_by(16) {
        for row in equationCount..equationCount + reductionRows {
            let value = words[(row / 16) * width + start + row % 16];
            let bits = [
                value & lowBits,
                (value >> 1) & lowBits,
                (value >> 2) & lowBits,
                (value >> 3) & lowBits,
            ];
            for place in 0..4 {
                let target = row + place - equationCount;
                words[(target / 16) * width + start + target % 16] ^= (bits[0] * table[4 * place])
                    ^ (bits[1] * table[4 * place + 1])
                    ^ (bits[2] * table[4 * place + 2])
                    ^ (bits[3] * table[4 * place + 3]);
            }
        }
    }
    let mut matrix = vec![0u8; equationCount.div_ceil(8) * 8 * columnCount];
    for (row, matrixRow) in matrix
        .chunks_exact_mut(columnCount)
        .take(equationCount)
        .enumerate()
    {
        for start in (0..columnCount - 1).step_by(16) {
            let word = words[(row / 16) * width + start + row % 16];
            let count = 16.min(columnCount - 1 - start);
            for (offset, value) in matrixRow[start..start + count].iter_mut().enumerate() {
                *value = ((word >> (4 * offset)) & 0x0F) as u8;
            }
        }
    }
    matrix
}

#[cfg(test)]
mod tests {
    use super::{rightHandSide, systemMatrix, transposeNibbles};
    use crate::parameters::{Parameters, mayo1, mayo2, mayo3, mayo5};
    use crate::testInputs::{digestOfBytes, inputNibbles, inputWords};

    /// The digests that `compute_rhs` and `compute_A` of the C code of the MAYO team give for
    /// the inputs of the labels, each built for its set. The digest of `compute_A` covers the m
    /// rows and the columns before the last.
    const knownAnswers: [(&Parameters, [&str; 2]); 4] = [
        (
            &mayo1,
            [
                "9c89e9dab68d9d0b0c1d1bab0c3639b3a1e1c9c8c1c57a804cefd7f69cf26ace",
                "cd900c18d57596872ed2e2b6495577c0309b29d8771dc9730bae45fa18499a13",
            ],
        ),
        (
            &mayo2,
            [
                "2e4072d5dc42b22fdb12c790844237ca4cceebfeb3206298de4a642fe360bf30",
                "a78d282a75e022a1828995898c2b6d3373ad0ffcea4d65b42b8a84770ef95601",
            ],
        ),
        (
            &mayo3,
            [
                "7a016c2cbf06bd60a54c525bd4faa088b04f7306b0f98aa9a0f8c50e38e5e14a",
                "3f7dde3efd28871787cd23a132f07a6b1b2630a6f8f2685f12ec99dffff8fb57",
            ],
        ),
        (
            &mayo5,
            [
                "fb76b492e0f3eef2b1e4904dc8e5824f3db96fa1eb1aa54fe51687252da81db3",
                "e790fcb40258afd65e2e127acc898a61ba3536899425aa93de5296c634df35d4",
            ],
        ),
    ];

    #[test]
    fn rightHandSideGivesTheAnswerOfTheCFunction() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let vectorCount = parameters.vectorCount;
            let mut products = inputWords(
                name,
                "rightHandSide vPv",
                vectorCount * vectorCount * parameters.limbCount(),
            );
            let target = inputNibbles(name, "rightHandSide t", parameters.equationCount);
            let result = rightHandSide(parameters, &mut products, &target);
            assert_eq!(digestOfBytes(&result), answers[0], "{name}");
        }
    }

    #[test]
    fn systemMatrixGivesTheAnswerOfTheCFunction() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let columnCount = parameters.systemColumnCount();
            let mut vinegarL = inputWords(
                name,
                "linearSystem",
                parameters.vectorCount * parameters.oilCount * parameters.limbCount(),
            );
            let matrix = systemMatrix(parameters, &mut vinegarL);
            let rows = parameters.equationCount.div_ceil(8) * 8;
            assert_eq!(matrix.len(), rows * columnCount);
            let region: Vec<u8> = matrix
                .chunks_exact(columnCount)
                .take(parameters.equationCount)
                .flat_map(|row| row[..columnCount - 1].to_vec())
                .collect();
            assert_eq!(digestOfBytes(&region), answers[1], "{name}");
            // The last column and the rows below m are zero.
            for (row, values) in matrix.chunks_exact(columnCount).enumerate() {
                assert_eq!(values[columnCount - 1], 0, "{name}, row {row}");
                if row >= parameters.equationCount {
                    assert!(values.iter().all(|value| *value == 0), "{name}, row {row}");
                }
            }
        }
    }

    #[test]
    fn transposeMovesTheNibbleOfEachColumnAndRow() {
        let words = inputWords("MAYO", "transpose", 16);
        let mut block = words.clone();
        transposeNibbles(&mut block);
        for (column, word) in words.iter().enumerate() {
            for (row, transposed) in block.iter().enumerate() {
                assert_eq!(
                    (transposed >> (4 * column)) & 0x0F,
                    (word >> (4 * row)) & 0x0F,
                    "row {row}, column {column}"
                );
            }
        }
    }
}
