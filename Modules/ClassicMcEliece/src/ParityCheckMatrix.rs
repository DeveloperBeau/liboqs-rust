use crate::Parameters;
use OQSNativeSortingNetwork::SortingNetwork;
use alloc::vec;
use alloc::vec::Vec;

/// The public key of a key pair, `pk_gen.c` of the C code: the parity-check matrix of the
/// Goppa code, brought into systematic form by Gaussian elimination over GF(2).
///
/// The matrix has `m t` rows of `n` bits, kept as 64-bit words, in which bit `j` of a row is
/// column `j`. The C code keeps bytes, and the exclusive or of a word is the exclusive or of
/// its eight bytes, so each step gives the bytes of the C code. A row operation skips the words
/// below the word of the pivot, which are zero in both rows. The `f` sets move 32 columns with
/// the pivot search `mov_columns` before the last 32 rows, so that the key needs only the
/// semi-systematic form.
pub(crate) struct ParityCheckMatrix<'parameters> {
    parameters: &'parameters Parameters,
    rows: Vec<u64>,
    rowWords: usize,
}

/// A public key and the parts of the secret key that its generation gives.
pub(crate) struct GeneratedKey {
    /// The public key: the rows of the matrix after the identity part.
    pub(crate) publicKey: Vec<u8>,
    /// The permutation of the field elements, `pi`, after the moves of the columns.
    pub(crate) permutation: Vec<i16>,
    /// The pivots `c` of the semi-systematic form, or `0xFFFFFFFF` for the systematic form.
    pub(crate) pivots: u64,
}

impl<'parameters> ParityCheckMatrix<'parameters> {
    /// The rows and columns of the window of the pivot search.
    const windowRows: usize = 32;

    /// The pivots of the systematic form, which `operations.c` stores for the sets without
    /// the pivot search.
    pub(crate) const systematicPivots: u64 = 0xFFFF_FFFF;

    /// The public key of a Goppa polynomial and of the 32-bit values that order the field
    /// elements, `pk_gen`, or `None` when two values are equal, when the matrix has no
    /// systematic form, or when the window of the pivot search has a rank below 32.
    pub(crate) fn generatedKey(
        parameters: &'parameters Parameters,
        goppaPolynomial: &[u16],
        orderValues: &[u32],
    ) -> Option<GeneratedKey> {
        let field = parameters.field();
        let size = parameters.fieldSize();
        let mut sorted: Vec<u64> = orderValues
            .iter()
            .enumerate()
            .map(|(index, value)| (u64::from(*value) << 31) + index as u64)
            .collect();
        SortingNetwork::sortWords(&mut sorted);
        if sorted.windows(2).any(|pair| pair[0] >> 31 == pair[1] >> 31) {
            return None;
        }
        let mut permutation: Vec<i16> = sorted
            .iter()
            .map(|value| (*value & u64::from(field.mask())) as i16)
            .collect();
        debug_assert_eq!(permutation.len(), size);
        let support: Vec<u16> = permutation[..parameters.codeLength]
            .iter()
            .map(|value| field.reversed(*value as u16))
            .collect();
        let mut matrix = Self::filled(parameters, goppaPolynomial, &support);
        let pivots = matrix.eliminated(&mut permutation)?;
        Some(GeneratedKey {
            publicKey: matrix.publicKey(),
            permutation,
            pivots,
        })
    }

    /// The matrix of the Goppa code: for each power `i` below `t`, the `m` bit rows of the
    /// values `L_j^i / g(L_j)` of the support.
    fn filled(
        parameters: &'parameters Parameters,
        goppaPolynomial: &[u16],
        support: &[u16],
    ) -> Self {
        let field = parameters.field();
        let bits = parameters.fieldBits as usize;
        let rowWords = parameters.codeLength.div_ceil(64);
        let mut rows = vec![0u64; parameters.rowCount() * rowWords];
        let mut polynomial = goppaPolynomial.to_vec();
        polynomial.push(1);
        let mut values: Vec<u16> = support
            .iter()
            .map(|point| field.inverse(field.evaluation(&polynomial, *point)))
            .collect();
        for power in 0..parameters.errorWeight {
            for (column, value) in values.iter().enumerate() {
                for bit in 0..bits {
                    let row = power * bits + bit;
                    rows[row * rowWords + column / 64] +=
                        u64::from((value >> bit) & 1) << (column % 64);
                }
            }
            for (value, point) in values.iter_mut().zip(support) {
                *value = field.product(*value, *point);
            }
        }
        ParityCheckMatrix {
            parameters,
            rows,
            rowWords,
        }
    }

    /// The Gaussian elimination of `pk_gen`, with the pivot search of the `f` sets before the
    /// last 32 rows: the pivots, or `None` when a pivot is missing.
    ///
    /// For each row, the C code first adds each later row whose bit in the column of the pivot
    /// differs from the bit of the row, and then adds the row to each other row that has the
    /// bit. Every addition has a mask, so the steps do not depend on the values.
    fn eliminated(&mut self, permutation: &mut [i16]) -> Option<u64> {
        let rowCount = self.parameters.rowCount();
        let words = self.rowWords;
        let mut pivots = Self::systematicPivots;
        let mut pivotRow = vec![0u64; words];
        for row in 0..rowCount {
            if self.parameters.isSemiSystematic && row == rowCount - Self::windowRows {
                pivots = self.movedColumns(permutation)?;
            }
            let (word, bit) = (row / 64, row % 64);
            for later in row + 1..rowCount {
                let (upper, lower) = self.rows.split_at_mut(later * words);
                let target = &mut upper[row * words + word..(row + 1) * words];
                let source = &lower[word..words];
                let mask = (((target[0] ^ source[0]) >> bit) & 1).wrapping_neg();
                for (targetWord, sourceWord) in target.iter_mut().zip(source) {
                    *targetWord ^= sourceWord & mask;
                }
            }
            pivotRow[word..].copy_from_slice(&self.rows[row * words + word..(row + 1) * words]);
            if (pivotRow[word] >> bit) & 1 == 0 {
                return None;
            }
            for (other, otherRow) in self.rows.chunks_exact_mut(words).enumerate() {
                if other != row {
                    let mask = ((otherRow[word] >> bit) & 1).wrapping_neg();
                    for (targetWord, sourceWord) in
                        otherRow[word..].iter_mut().zip(&pivotRow[word..])
                    {
                        *targetWord ^= sourceWord & mask;
                    }
                }
            }
        }
        Some(pivots)
    }

    /// The 64 bits of a row from a column, as the C code loads them from the bytes.
    fn window(&self, row: usize, column: usize) -> u64 {
        let words = &self.rows[row * self.rowWords..(row + 1) * self.rowWords];
        let (index, shift) = (column / 64, column % 64);
        if shift == 0 {
            words[index]
        } else {
            (words[index] >> shift) | (words[index + 1] << (64 - shift))
        }
    }

    /// Writes the 64 bits of a row from a column, and keeps the other bits of the row.
    fn writeWindow(&mut self, row: usize, column: usize, value: u64) {
        let words = &mut self.rows[row * self.rowWords..(row + 1) * self.rowWords];
        let (index, shift) = (column / 64, column % 64);
        if shift == 0 {
            words[index] = value;
        } else {
            let lowMask = (1u64 << shift) - 1;
            words[index] = (words[index] & lowMask) + (value << shift);
            words[index + 1] = (words[index + 1] & !lowMask) + (value >> (64 - shift));
        }
    }

    /// Writes the moved 64 bits of a row from a column back, as `mov_columns` stores them.
    ///
    /// When the column does not start a byte, which only the 6960119f set has, the C code
    /// writes the first byte as `(tmp[0] << tail) | mat[i][block_idx] << (8 - tail) >>
    /// (8 - tail)`. The byte is promoted to `int`, so the shifts keep the whole old byte, and
    /// the first `8 - tail` bits of the window become the or of the old and the new bits.
    fn storeWindow(&mut self, row: usize, column: usize, value: u64) {
        let tail = column % 8;
        let value = if tail == 0 {
            value
        } else {
            value | (self.window(row, column) & ((1 << (8 - tail)) - 1))
        };
        self.writeWindow(row, column, value);
    }

    /// The trailing zeros of a value that is not zero, `ctz` of `pk_gen.c`, with no branch.
    fn trailingZeroCount(value: u64) -> usize {
        let mut isSeen = 0u64;
        let mut count = 0u64;
        for bit in 0..64 {
            let isSet = (value >> bit) & 1;
            isSeen |= isSet;
            count += (isSeen ^ 1) & (isSet ^ 1);
        }
        count as usize
    }

    /// A mask of ones when two values are equal, `same_mask` of `pk_gen.c`.
    fn sameMask(left: u16, right: u16) -> u64 {
        (u64::from(left ^ right).wrapping_sub(1) >> 63).wrapping_neg()
    }

    /// The pivot search `mov_columns`: the pivots of the 32 by 64 window of the last 32 rows
    /// from the column `m t - 32`, and the moves of the permutation and of the columns that
    /// bring them to the diagonal, or `None` when the window has a rank below 32.
    fn movedColumns(&mut self, permutation: &mut [i16]) -> Option<u64> {
        let rowCount = self.parameters.rowCount();
        let start = rowCount - Self::windowRows;
        let mut window: Vec<u64> = (0..Self::windowRows)
            .map(|offset| self.window(start + offset, start))
            .collect();
        let mut pivots = 0u64;
        let mut pivotColumns = [0usize; 32];
        for index in 0..Self::windowRows {
            let below = window[index..]
                .iter()
                .fold(0u64, |total, value| total | value);
            if below == 0 {
                return None;
            }
            let column = Self::trailingZeroCount(below);
            pivotColumns[index] = column;
            pivots += 1 << column;
            for later in index + 1..Self::windowRows {
                let mask = ((window[index] >> column) & 1).wrapping_sub(1);
                window[index] ^= window[later] & mask;
            }
            for later in index + 1..Self::windowRows {
                let mask = ((window[later] >> column) & 1).wrapping_neg();
                window[later] ^= window[index] & mask;
            }
        }
        for (offset, pivotColumn) in pivotColumns.iter().enumerate() {
            for other in offset + 1..64 {
                let mask = Self::sameMask(other as u16, *pivotColumn as u16) as i16;
                let difference = (permutation[start + offset] ^ permutation[start + other]) & mask;
                permutation[start + offset] ^= difference;
                permutation[start + other] ^= difference;
            }
        }
        for row in 0..rowCount {
            let mut value = self.window(row, start);
            for (offset, pivotColumn) in pivotColumns.iter().enumerate() {
                let difference = ((value >> offset) ^ (value >> pivotColumn)) & 1;
                value ^= difference << pivotColumn;
                value ^= difference << offset;
            }
            self.storeWindow(row, start, value);
        }
        Some(pivots)
    }

    /// The public key: of each row, the `n - m t` columns after the identity part, packed from
    /// the low bit of each byte, as the `memcpy` of `pk_gen` copies them, or the shifts of the
    /// 6960119 sets, whose identity part ends inside a byte.
    fn publicKey(&self) -> Vec<u8> {
        let parameters = self.parameters;
        let rowCount = parameters.rowCount();
        let rowLength = parameters.publicKeyRowLength();
        let byteCount = parameters.errorVectorLength();
        let tail = parameters.rowTail();
        let mut publicKey = Vec::with_capacity(rowCount * rowLength);
        let mut bytes = vec![0u8; 8 * self.rowWords];
        for row in self.rows.chunks_exact(self.rowWords) {
            for (target, word) in bytes.chunks_exact_mut(8).zip(row) {
                target.copy_from_slice(&word.to_le_bytes());
            }
            if tail == 0 {
                publicKey.extend_from_slice(&bytes[rowCount / 8..byteCount]);
            } else {
                for index in (rowCount - 1) / 8..byteCount - 1 {
                    publicKey.push((bytes[index] >> tail) | (bytes[index + 1] << (8 - tail)));
                }
                publicKey.push(bytes[byteCount - 1] >> tail);
            }
        }
        publicKey
    }
}

#[cfg(test)]
mod tests {
    use super::ParityCheckMatrix;
    use crate::Parameters;
    use crate::goppaPolynomial::GoppaPolynomial;
    use crate::parameters::{
        classicMcEliece348864, classicMcEliece348864f, classicMcEliece460896,
        classicMcEliece6960119, classicMcEliece6960119f,
    };
    use OQSNativeAlgorithmTests::{FuzzRandom, OutputDigest};

    /// A matrix of a set with seeded rows. The bits from column `n` up are zero, as in a matrix
    /// of the C code.
    fn seededMatrix(parameters: &'static Parameters, seed: u64) -> ParityCheckMatrix<'static> {
        let rowWords = parameters.codeLength.div_ceil(64);
        let mut words = FuzzRandom::seeded(seed);
        let mut rows: Vec<u64> = (0..parameters.rowCount() * rowWords)
            .map(|_| words.nextWord())
            .collect();
        for row in rows.chunks_exact_mut(rowWords) {
            row[rowWords - 1] &= (1 << (parameters.codeLength % 64)) - 1;
        }
        ParityCheckMatrix {
            parameters,
            rows,
            rowWords,
        }
    }

    /// The bytes of each row of a matrix, as the matrix `mat` of the C code holds them.
    fn matrixBytes(matrix: &ParityCheckMatrix) -> Vec<u8> {
        let byteCount = matrix.parameters.errorVectorLength();
        matrix
            .rows
            .chunks_exact(matrix.rowWords)
            .flat_map(|row| {
                row.iter()
                    .flat_map(|word| word.to_le_bytes())
                    .take(byteCount)
                    .collect::<Vec<u8>>()
            })
            .collect()
    }

    /// The identity permutation of the field elements of the 13-bit sets.
    fn identity() -> Vec<i16> {
        (0..8192).collect()
    }

    #[test]
    fn trailingZerosAndSameMasksFollowTheCFunctions() {
        assert_eq!(ParityCheckMatrix::trailingZeroCount(1), 0);
        assert_eq!(ParityCheckMatrix::trailingZeroCount(0b1000), 3);
        assert_eq!(ParityCheckMatrix::trailingZeroCount(1 << 63), 63);
        assert_eq!(ParityCheckMatrix::trailingZeroCount(u64::MAX << 17), 17);
        assert_eq!(ParityCheckMatrix::sameMask(5, 5), u64::MAX);
        assert_eq!(ParityCheckMatrix::sameMask(5, 4), 0);
        assert_eq!(ParityCheckMatrix::sameMask(0, u16::MAX), 0);
    }

    #[test]
    fn windowsReadAndWriteSixtyFourBitsFromAnyColumn() {
        let mut matrix = seededMatrix(&classicMcEliece6960119f, 3);
        let original = matrix.rows.clone();
        for column in [0usize, 1, 63, 64, 1515, 6896] {
            let value = matrix.window(7, column);
            let mut expected = 0u64;
            for bit in 0..64 {
                let place = column + bit;
                let word = original[7 * matrix.rowWords + place / 64];
                expected |= ((word >> (place % 64)) & 1) << bit;
            }
            assert_eq!(value, expected, "column {column}");
            matrix.writeWindow(7, column, !value);
            assert_eq!(matrix.window(7, column), !value, "column {column}");
            matrix.writeWindow(7, column, value);
            assert_eq!(matrix.rows, original, "column {column}");
        }
    }

    #[test]
    fn twoEqualOrderValuesGiveNoKey() {
        let parameters = &classicMcEliece348864;
        let mut words = FuzzRandom::seeded(31);
        let goppa: Vec<u16> = (0..64).map(|_| words.nextWord() as u16 & 0xFFF).collect();
        let mut values: Vec<u32> = (0..4096).map(|_| words.nextWord() as u32).collect();
        values[4095] = values[17];
        assert!(ParityCheckMatrix::generatedKey(parameters, &goppa, &values).is_none());
    }

    #[test]
    fn aWindowOfRank31GivesNoKey() {
        for parameters in [&classicMcEliece348864f, &classicMcEliece6960119f] {
            let mut matrix = seededMatrix(parameters, 4);
            let start = parameters.rowCount() - 32;
            for offset in 0..31 {
                matrix.writeWindow(start + offset, start, 1 << offset);
            }
            matrix.writeWindow(start + 31, start, 0);
            let mut permutation = identity();
            assert_eq!(matrix.movedColumns(&mut permutation), None);
            assert_eq!(permutation, identity());
        }
    }

    #[test]
    fn aWindowOfRank32MovesOnlyAPivotOutsideTheDiagonal() {
        for parameters in [&classicMcEliece348864f, &classicMcEliece6960119f] {
            let name = parameters.description.name;
            // The identity on the diagonal keeps every column.
            let mut matrix = seededMatrix(parameters, 5);
            let start = parameters.rowCount() - 32;
            for offset in 0..32 {
                matrix.writeWindow(start + offset, start, 1 << offset);
            }
            let unchanged = matrix.rows.clone();
            let mut permutation = identity();
            assert_eq!(
                matrix.movedColumns(&mut permutation),
                Some(0xFFFF_FFFF),
                "{name}"
            );
            assert_eq!(permutation, identity(), "{name}");
            assert!(matrix.rows == unchanged, "{name}");
            // The last pivot at column 32 of the window swaps the columns 31 and 32.
            matrix.writeWindow(start + 31, start, 1 << 32);
            let before: Vec<u64> = (0..parameters.rowCount())
                .map(|row| matrix.window(row, start))
                .collect();
            assert_eq!(
                matrix.movedColumns(&mut permutation),
                Some(0x7FFF_FFFF + (1 << 32)),
                "{name}"
            );
            let mut expected = identity();
            expected.swap(start + 31, start + 32);
            assert_eq!(permutation, expected, "{name}");
            for (row, old) in before.iter().enumerate() {
                let bit31 = (old >> 31) & 1;
                let bit32 = (old >> 32) & 1;
                let swapped = (old & !(0b11 << 31)) + (bit31 << 32) + (bit32 << 31);
                assert_eq!(matrix.window(row, start), swapped, "{name}, row {row}");
            }
        }
    }

    #[test]
    fn thePivotSearchOrsTheOldBitsIntoTheFirstByteOfAWindowInsideAByte() {
        // The window of 6960119f starts at column 1515, bit 3 of byte 189. With the columns
        // 1515 and 1516 zero in the last 32 rows, the pivots of the window start at its column
        // 2, and the C code ors the moved bits of the window columns 0 to 4 into their old bits.
        let parameters = &classicMcEliece6960119f;
        let mut matrix = seededMatrix(parameters, 41);
        let start = parameters.rowCount() - 32;
        for row in start..parameters.rowCount() {
            let window = matrix.window(row, start) & !0b11;
            matrix.writeWindow(row, start, window);
        }
        let before: Vec<u64> = (0..parameters.rowCount())
            .map(|row| matrix.window(row, start))
            .collect();
        let mut permutation = identity();
        let pivots = matrix
            .movedColumns(&mut permutation)
            .expect("a window of rank 32");
        assert_eq!(pivots & 0b1111, 0b1100);
        // Place j of the window takes the value of the place of pivot j.
        let mut pivotColumns = Vec::new();
        let mut remaining = pivots;
        while remaining != 0 {
            pivotColumns.push(remaining.trailing_zeros() as usize);
            remaining &= remaining - 1;
        }
        assert_eq!(pivotColumns.len(), 32);
        for (offset, column) in pivotColumns.iter().enumerate() {
            assert_eq!(permutation[start + offset], (start + column) as i16);
        }
        let mut movedFirstBits = 0;
        for (row, old) in before.iter().enumerate() {
            // The swaps of the columns j and pivot j in turn, written by hand.
            let mut swapped = *old;
            for (offset, column) in pivotColumns.iter().enumerate() {
                let difference = ((swapped >> offset) ^ (swapped >> column)) & 1;
                swapped ^= (difference << column) + (difference << offset);
            }
            let new = matrix.window(row, start);
            assert_eq!(new >> 5, swapped >> 5, "row {row}");
            assert_eq!(new & 0b11111, (swapped | old) & 0b11111, "row {row}");
            if (swapped | old) & 0b11111 != swapped & 0b11111 {
                movedFirstBits += 1;
            }
        }
        // The rule changes the result: in many rows the or differs from the clean swap.
        assert!(movedFirstBits > 100, "{movedFirstBits}");
        // `mov_columns` of `pqclean_mceliece6960119f_clean` in liboqs 0.16.0, copied into a
        // test program, on the same matrix: the `OutputDigest` of the rows of 870 bytes, of
        // the permutation as little-endian 16-bit values and of the pivots as 8 little-endian
        // bytes.
        let mut output = matrixBytes(&matrix);
        for value in &permutation {
            output.extend(value.to_le_bytes());
        }
        output.extend(pivots.to_le_bytes());
        assert_eq!(
            OutputDigest::of(&output),
            "26c293e09a7598bdf9fbcba3acfc7e1b0b6265ade6f7935fce1ad904f9f05499"
        );
    }

    #[test]
    fn generatedKeysGiveTheKnownAnswersOfTheCFunction() {
        // `pk_gen` of liboqs 0.16.0 with the Goppa polynomial of `genpoly_gen` of the element
        // of the seed 100, and the 32-bit values of the seeds 200, 201 and so on: the seeds
        // before the given one give no key, and the given one gives a key with the
        // `OutputDigest` of the public key, of the permutation as little-endian 16-bit values
        // and of the pivots as 8 little-endian bytes.
        let expected = [
            (
                &classicMcEliece348864,
                201,
                "75eb64a7f697e62a261d9e3e4acbe4b0aa61aa483366ef9fa35e84d2b5c0edad",
            ),
            (
                &classicMcEliece348864f,
                200,
                "1e71858799c4910e143d313582d8f0472b91d6ee941bde76189d455a82319053",
            ),
            (
                &classicMcEliece460896,
                200,
                "795c574559977cd881fd83deedffae23d2bb43fd11a6b6c6952ae145b4b37bb4",
            ),
            (
                &classicMcEliece6960119,
                205,
                "4f2a8e18755356984baa8d6e34683f27e76f706d231b5e1ed93a5159d7c4aed0",
            ),
            (
                &classicMcEliece6960119f,
                200,
                "71d83fb94909584f8f907ac3c9e6c04461e14e983065483869326e9a5c99a800",
            ),
        ];
        for (parameters, keySeed, keyDigest) in expected {
            let name = parameters.description.name;
            let mask = parameters.field().mask();
            let mut words = FuzzRandom::seeded(100);
            let element: Vec<u16> = (0..parameters.errorWeight)
                .map(|_| words.nextWord() as u16 & mask)
                .collect();
            let goppa = GoppaPolynomial::new(parameters)
                .minimalPolynomial(&element)
                .expect("a Goppa polynomial");
            let values = |seed: u64| {
                let mut words = FuzzRandom::seeded(seed);
                (0..parameters.fieldSize())
                    .map(|_| words.nextWord() as u32)
                    .collect::<Vec<u32>>()
            };
            for seed in 200..keySeed {
                assert!(
                    ParityCheckMatrix::generatedKey(parameters, &goppa, &values(seed)).is_none(),
                    "{name}, seed {seed}"
                );
            }
            let key = ParityCheckMatrix::generatedKey(parameters, &goppa, &values(keySeed))
                .unwrap_or_else(|| panic!("{name}: a key"));
            let mut output = key.publicKey.clone();
            for value in &key.permutation {
                output.extend(value.to_le_bytes());
            }
            output.extend(key.pivots.to_le_bytes());
            assert_eq!(OutputDigest::of(&output), keyDigest, "{name}");
        }
    }
}
