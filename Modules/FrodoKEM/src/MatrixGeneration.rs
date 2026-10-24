use crate::Packing;
use OQSNativeAES::AES128;
use OQSNativeSHA3::SHAKE128;
use alloc::vec;

/// The generation of the public matrix `A` of `n` rows of `n` values from its 16-byte seed,
/// `Frodo.Gen` of the specification.
///
/// liboqs makes the matrix on the fly in `frodo_macrify_as_plus_e.c`,
/// `frodo_macrify_aes_portable.c` and `frodo_macrify_shake_portable.c`, four rows or eight
/// columns at a time. The port makes it one row at a time. The products use only sums and
/// products modulo `2^16`, so the order of the rows does not change them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MatrixGeneration {
    /// AES-128 in ECB mode with the seed as the key. The values `8 j` to `8 j + 7` of row `i`
    /// are the eight little-endian 16-bit words of the encryption of the block that holds `i`
    /// and `8 j` as little-endian 16-bit words, and zero bytes.
    aes128,
    /// SHAKE128. Row `i` is the `2 n` bytes of SHAKE128 of `i` as a little-endian 16-bit word
    /// and the seed, as little-endian 16-bit values.
    shake128,
}

impl MatrixGeneration {
    /// Calls a closure with the index and the values of each row of the matrix of a seed, in
    /// order.
    pub(crate) fn forEachRow(
        &self,
        seed: &[u8; 16],
        dimension: usize,
        mut body: impl FnMut(usize, &[u16]),
    ) {
        let mut rowBytes = vec![0u8; 2 * dimension];
        let mut row = vec![0u16; dimension];
        match self {
            MatrixGeneration::aes128 => {
                let cipher = AES128::new(seed);
                // Block `j` of a row holds the row index and then the column `8 j`.
                let mut blocks = vec![0u8; 2 * dimension];
                for (blockIndex, block) in blocks.chunks_exact_mut(16).enumerate() {
                    block[2..4].copy_from_slice(&((8 * blockIndex) as u16).to_le_bytes());
                }
                for rowIndex in 0..dimension {
                    let rowWord = (rowIndex as u16).to_le_bytes();
                    for block in blocks.chunks_exact_mut(16) {
                        block[..2].copy_from_slice(&rowWord);
                    }
                    cipher.encryptBlocks(&blocks, &mut rowBytes);
                    Packing::decodeLittleEndian(&rowBytes, &mut row);
                    body(rowIndex, &row);
                }
            }
            MatrixGeneration::shake128 => {
                for rowIndex in 0..dimension {
                    let mut function = SHAKE128::new();
                    function.absorb(&(rowIndex as u16).to_le_bytes());
                    function.absorb(seed);
                    function.finalize().squeeze(&mut rowBytes);
                    Packing::decodeLittleEndian(&rowBytes, &mut row);
                    body(rowIndex, &row);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MatrixGeneration;
    use OQSNativeAES::AES128;
    use OQSNativeSHA3::SHAKE128;

    /// The rows of the matrix of a seed.
    fn rows(generation: MatrixGeneration, seed: &[u8; 16], dimension: usize) -> Vec<Vec<u16>> {
        let mut rows = Vec::new();
        generation.forEachRow(seed, dimension, |index, row| {
            assert_eq!(index, rows.len());
            rows.push(row.to_vec());
        });
        rows
    }

    #[test]
    fn anAESRowIsTheEncryptionOfTheRowAndColumnBlocks() {
        let seed: [u8; 16] = core::array::from_fn(|index| index as u8);
        let rows = rows(MatrixGeneration::aes128, &seed, 640);
        assert_eq!(rows.len(), 640);
        let cipher = AES128::new(&seed);
        for (rowIndex, columnStart) in [(0usize, 0usize), (0, 632), (1, 8), (639, 320)] {
            let mut block = [0u8; 16];
            block[..2].copy_from_slice(&(rowIndex as u16).to_le_bytes());
            block[2..4].copy_from_slice(&(columnStart as u16).to_le_bytes());
            let mut encrypted = [0u8; 16];
            cipher.encryptBlocks(&block, &mut encrypted);
            for (offset, pair) in encrypted.chunks_exact(2).enumerate() {
                assert_eq!(
                    rows[rowIndex][columnStart + offset],
                    u16::from_le_bytes([pair[0], pair[1]]),
                    "row {rowIndex}, column {}",
                    columnStart + offset
                );
            }
        }
    }

    #[test]
    fn aSHAKERowIsTheHashOfTheRowIndexAndTheSeed() {
        let seed = [0xA5u8; 16];
        let rows = rows(MatrixGeneration::shake128, &seed, 976);
        assert_eq!(rows.len(), 976);
        for rowIndex in [0usize, 1, 258, 975] {
            let mut input = (rowIndex as u16).to_le_bytes().to_vec();
            input.extend_from_slice(&seed);
            let mut bytes = vec![0u8; 2 * 976];
            SHAKE128::hash(&input, &mut bytes);
            let expected: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            assert_eq!(rows[rowIndex], expected, "row {rowIndex}");
        }
    }
}
