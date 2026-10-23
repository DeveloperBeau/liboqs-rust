use crate::Parameters;
use alloc::vec;
use alloc::vec::Vec;

/// The matrix arithmetic of one parameter set, as liboqs `frodo_macrify_optimized.c` and the
/// portable generate-and-multiply files compute it.
///
/// Each matrix is a list of 16-bit values, row after row. Sums and products are modulo `2^16`,
/// with no reduction modulo `q = 2^D` inside a sum. The results that the C code reduces
/// modulo `q` keep their low `D` bits. The other results keep all 16 bits, and the packing or
/// the comparison of decapsulation takes their low `D` bits.
///
/// The secret matrix `S` of `n` rows and `n̄` columns is kept as its transpose: `n̄` rows of
/// `n` values, as the secret key holds it.
pub(crate) struct MatrixArithmetic<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> MatrixArithmetic<'parameters> {
    /// Makes the arithmetic of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        MatrixArithmetic { parameters }
    }

    /// The mask of the low `D` bits, the reduction modulo `q`.
    fn modulusMask(&self) -> u16 {
        ((1u32 << self.parameters.modulusBits) - 1) as u16
    }

    /// The matrix `B = A S + E` of a public key, `n` rows of `n̄` values, from the seed of `A`,
    /// the transpose of `S` and the error `E`, as `frodo_mul_add_as_plus_e` computes it. The
    /// values are not reduced.
    pub(crate) fn publicKeyMatrix(
        &self,
        matrixSeed: &[u8; 16],
        secret: &[u16],
        error: &[u16],
    ) -> Vec<u16> {
        let dimension = self.parameters.dimension;
        let width = Parameters::shortDimension;
        let mut product = error.to_vec();
        self.parameters
            .matrixGeneration
            .forEachRow(matrixSeed, dimension, |rowIndex, row| {
                for (column, secretColumn) in secret.chunks_exact(dimension).enumerate() {
                    let dotProduct = row
                        .iter()
                        .zip(secretColumn)
                        .fold(0u16, |sum, (value, factor)| {
                            sum.wrapping_add(value.wrapping_mul(*factor))
                        });
                    let target = &mut product[rowIndex * width + column];
                    *target = target.wrapping_add(dotProduct);
                }
            });
        product
    }

    /// The matrix `B' = S' A + E'` of a ciphertext, `n̄` rows of `n` values, from the seed of
    /// `A`, the ephemeral secret `S'` and the error `E'`, as `frodo_mul_add_sa_plus_e`
    /// computes it. The values are not reduced.
    pub(crate) fn ciphertextMatrix(
        &self,
        matrixSeed: &[u8; 16],
        ephemeralSecret: &[u16],
        error: &[u16],
    ) -> Vec<u16> {
        let dimension = self.parameters.dimension;
        let mut product = error.to_vec();
        self.parameters
            .matrixGeneration
            .forEachRow(matrixSeed, dimension, |rowIndex, row| {
                for (secretRow, productRow) in ephemeralSecret
                    .chunks_exact(dimension)
                    .zip(product.chunks_exact_mut(dimension))
                {
                    let factor = secretRow[rowIndex];
                    for (target, value) in productRow.iter_mut().zip(row) {
                        *target = target.wrapping_add(factor.wrapping_mul(*value));
                    }
                }
            });
        product
    }

    /// The mask `V = S' B + E''` of encryption modulo `q`, `n̄` rows of `n̄` values, from the
    /// matrix `B` of the public key, as `frodo_mul_add_sb_plus_e` computes it.
    pub(crate) fn encryptionMask(
        &self,
        publicKeyMatrix: &[u16],
        ephemeralSecret: &[u16],
        error: &[u16],
    ) -> Vec<u16> {
        let width = Parameters::shortDimension;
        let mask = self.modulusMask();
        let mut result = vec![0u16; width * width];
        for (row, secretRow) in ephemeralSecret
            .chunks_exact(self.parameters.dimension)
            .enumerate()
        {
            for column in 0..width {
                let sum = secretRow
                    .iter()
                    .zip(publicKeyMatrix.chunks_exact(width))
                    .fold(error[row * width + column], |sum, (factor, keyRow)| {
                        sum.wrapping_add(factor.wrapping_mul(keyRow[column]))
                    });
                result[row * width + column] = sum & mask;
            }
        }
        result
    }

    /// The mask `B' S` of decryption modulo `q`, `n̄` rows of `n̄` values, from the matrix
    /// `B'` of a ciphertext and the transpose of `S`, as `frodo_mul_bs` computes it.
    pub(crate) fn decryptionMask(&self, ciphertextMatrix: &[u16], secret: &[u16]) -> Vec<u16> {
        let dimension = self.parameters.dimension;
        let mask = self.modulusMask();
        ciphertextMatrix
            .chunks_exact(dimension)
            .flat_map(|ciphertextRow| {
                secret.chunks_exact(dimension).map(move |secretColumn| {
                    let sum = ciphertextRow
                        .iter()
                        .zip(secretColumn)
                        .fold(0u16, |sum, (value, factor)| {
                            sum.wrapping_add(value.wrapping_mul(*factor))
                        });
                    sum & mask
                })
            })
            .collect()
    }

    /// Reduces each value of a matrix modulo `q`, as decapsulation reduces the matrix `B'` of
    /// its re-encryption before the comparison.
    pub(crate) fn reduce(&self, matrix: &mut [u16]) {
        let mask = self.modulusMask();
        for value in matrix.iter_mut() {
            *value &= mask;
        }
    }

    /// The sum of two matrices modulo `q`, as `frodo_add` computes it.
    pub(crate) fn sum(&self, left: &[u16], right: &[u16]) -> Vec<u16> {
        let mask = self.modulusMask();
        left.iter()
            .zip(right)
            .map(|(left, right)| left.wrapping_add(*right) & mask)
            .collect()
    }

    /// The difference of two matrices modulo `q`, as `frodo_sub` computes it.
    pub(crate) fn difference(&self, left: &[u16], right: &[u16]) -> Vec<u16> {
        let mask = self.modulusMask();
        left.iter()
            .zip(right)
            .map(|(left, right)| left.wrapping_sub(*right) & mask)
            .collect()
    }

    /// The message matrix of a message, `Frodo.Encode` and `frodo_key_encode`.
    ///
    /// Each group of `B` bytes is a little-endian number whose bits give eight values, from the
    /// low bits: each `B` bits become the high bits of a `D`-bit value.
    pub(crate) fn encoded(&self, message: &[u8]) -> Vec<u16> {
        let bits = self.parameters.messageBits;
        let shift = self.parameters.modulusBits - bits;
        let valueMask = (1u64 << bits) - 1;
        let mut values = Vec::new();
        for group in message.chunks_exact(bits as usize) {
            let mut word = group.iter().enumerate().fold(0u64, |word, (index, byte)| {
                word + (u64::from(*byte) << (8 * index))
            });
            for _ in 0..Parameters::shortDimension {
                values.push(((word & valueMask) << shift) as u16);
                word >>= bits;
            }
        }
        values
    }

    /// The message of a matrix, `Frodo.Decode` and `frodo_key_decode`: each value rounds to its
    /// high `B` bits, modulo `2^B`, and each eight values make a group of `B` bytes.
    pub(crate) fn decoded(&self, matrix: &[u16]) -> Vec<u8> {
        let bits = self.parameters.messageBits;
        let shift = self.parameters.modulusBits - bits;
        let modulusMask = u32::from(self.modulusMask());
        let valueMask = (1u32 << bits) - 1;
        let mut message = Vec::new();
        for group in matrix.chunks_exact(Parameters::shortDimension) {
            let word = group.iter().enumerate().fold(0u64, |word, (index, value)| {
                let rounded = ((u32::from(*value) & modulusMask) + (1 << (shift - 1))) >> shift;
                word + (u64::from(rounded & valueMask) << (bits as usize * index))
            });
            for index in 0..bits {
                message.push((word >> (8 * index)) as u8);
            }
        }
        message
    }
}

#[cfg(test)]
mod tests {
    use super::MatrixArithmetic;
    use crate::parameters::{
        frodoKEM640AES, frodoKEM640SHAKE, frodoKEM976AES, frodoKEM976SHAKE, frodoKEM1344AES,
        frodoKEM1344SHAKE,
    };
    use crate::testInputs::{sequence, sequenceBytes, valuesDigest};

    /// The seed 0 to 15 of the matrix of the C program.
    const matrixSeed: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    #[test]
    fn productsWithThePublicMatrixGiveTheValuesOfTheCCode() {
        // The first values and the digests of `frodo_mul_add_as_plus_e` with the secret and
        // error sequences 1 and 2, and of `frodo_mul_add_sa_plus_e` with 3 and 4, from liboqs
        // 0.16.0.
        for (parameters, publicKeyFirst, publicKeyDigest, ciphertextFirst, ciphertextDigest) in [
            (
                &frodoKEM640AES,
                [9209u16, 53860, 50282, 38411],
                "600d2bd4d4de83ea2294a4c7d96e1be3410b358ccf9594a4aa147fa6b43fe2a6",
                [62909u16, 13690, 5120, 31887],
                "0129637b9d2dfa4384337315a954c90552d98cb7ad1d9e1a3fbf2ecfa8713ef7",
            ),
            (
                &frodoKEM640SHAKE,
                [36843, 4200, 44434, 44325],
                "f1011d275e0cb18c02d637031a66e0c94e44f676967270243a4376cd525c5409",
                [8820, 59013, 55880, 2808],
                "a642004c8adb81e2ef8b1515c0da066729f8e0a862b983904f23a4159a35953d",
            ),
            (
                &frodoKEM976AES,
                [8024, 10456, 19028, 23737],
                "696fea6034299bd4181ee1905de70d1fd541e1f8b06cf3de7f9e7c2c98ca8227",
                [25108, 23526, 46032, 48397],
                "1ad5cf787edcade1c37816b48724aa7f35a8a9f27153f3e9454f5dbc1f886740",
            ),
            (
                &frodoKEM976SHAKE,
                [56232, 56148, 61391, 38412],
                "a8418a17a641c82f750e050a56390b804257466d6093e4926ce1da5d6ab8136f",
                [33493, 19530, 19401, 6341],
                "12964718b8a18d24f1c93e4183088590d597155525ea97a01a19223efd03cdff",
            ),
            (
                &frodoKEM1344AES,
                [8031, 23302, 22869, 30556],
                "72c40df5a8bd2f90c6dec73523d946349d2d2178d58c53d25bdf19f5ac5e728d",
                [11053, 46226, 30295, 16231],
                "575185e1b7ba8b5b9661a253afd81347508e7887f0ca13ffab3e7bcfbdb89442",
            ),
            (
                &frodoKEM1344SHAKE,
                [36602, 22663, 19663, 38369],
                "7b87d799df851fce8a7767aeea7e39319879dc86da72d9a0266083c2950e8c37",
                [57054, 19603, 24653, 61766],
                "d72a0e81d2a0f2d0be34665fc9586aeee2d60dfc561fd2ab975d8da46b8d685c",
            ),
        ] {
            let name = parameters.description.name;
            let count = parameters.matrixValueCount();
            let arithmetic = MatrixArithmetic::new(parameters);
            let publicKeyMatrix =
                arithmetic.publicKeyMatrix(&matrixSeed, &sequence(count, 1), &sequence(count, 2));
            assert_eq!(&publicKeyMatrix[..4], &publicKeyFirst, "{name}");
            assert_eq!(valuesDigest(&publicKeyMatrix), publicKeyDigest, "{name}");
            let ciphertextMatrix =
                arithmetic.ciphertextMatrix(&matrixSeed, &sequence(count, 3), &sequence(count, 4));
            assert_eq!(&ciphertextMatrix[..4], &ciphertextFirst, "{name}");
            assert_eq!(valuesDigest(&ciphertextMatrix), ciphertextDigest, "{name}");
        }
    }

    #[test]
    fn smallProductsSumsAndDifferencesGiveTheValuesOfTheCCode() {
        // `frodo_mul_add_sb_plus_e` with the sequences 5, 6 and 7, `frodo_mul_bs` with 8 and 9,
        // and `frodo_add` and `frodo_sub` with 10 and 11, from liboqs 0.16.0.
        for (
            parameters,
            encryptionFirst,
            encryption,
            decryptionFirst,
            decryption,
            sum,
            difference,
        ) in [
            (
                &frodoKEM640AES,
                [18458u16, 10025, 8302, 26998],
                "520eaa5dc484ec69c711f7410c3594f505f597bcb4c9f88e43d58cf462c075fc",
                [1918u16, 22414, 28759, 16937],
                "a6a48c12fb5b28e42246cc9a88cb98fe6e1ff60ec56a59bbed41fc5ea3427ee8",
                "7639ba65039df32f60aa15a01135142ea2a11138f91560d73c301ea70e114e00",
                "c59bc11a6f2dc30aeeba54d94647ffe3c991fc3eb04bc15f38dc9b3edde77601",
            ),
            (
                &frodoKEM976AES,
                [60106, 19644, 43780, 40740],
                "3d4ba6b02cc435122fa6a9b45958677b1a23341e3c86d5ca5f0c18a38637fc6a",
                [7822, 45534, 64208, 55660],
                "a83848e50a44956697a6359b6027533808dc6ffd69d40bf27c5bc12faefd41a8",
                "a822009cbaeaa20318cd5c14692000dc994972298b744fa99fa6b6b602dfb344",
                "ef2386f18175e070979341e28b0c5917862fcb5636e0a52d2d073ecd04920ccc",
            ),
            (
                &frodoKEM1344AES,
                [33192, 27066, 39872, 62987],
                "ca2a740624836cd4adae5efcfac4152a5c56397062561f25ce2243dc421cff06",
                [39275, 63404, 2381, 41694],
                "b9833177834bf326f56583d306dfac1c4bcdf491b31595c364993b4c1fdc10ac",
                "a822009cbaeaa20318cd5c14692000dc994972298b744fa99fa6b6b602dfb344",
                "ef2386f18175e070979341e28b0c5917862fcb5636e0a52d2d073ecd04920ccc",
            ),
        ] {
            let name = parameters.description.name;
            let count = parameters.matrixValueCount();
            let arithmetic = MatrixArithmetic::new(parameters);
            let mask = arithmetic.encryptionMask(
                &sequence(count, 5),
                &sequence(count, 6),
                &sequence(64, 7),
            );
            assert_eq!(&mask[..4], &encryptionFirst, "{name}");
            assert_eq!(valuesDigest(&mask), encryption, "{name}");
            let mask = arithmetic.decryptionMask(&sequence(count, 8), &sequence(count, 9));
            assert_eq!(&mask[..4], &decryptionFirst, "{name}");
            assert_eq!(valuesDigest(&mask), decryption, "{name}");
            let (left, right) = (sequence(64, 10), sequence(64, 11));
            assert_eq!(valuesDigest(&arithmetic.sum(&left, &right)), sum, "{name}");
            assert_eq!(
                valuesDigest(&arithmetic.difference(&left, &right)),
                difference,
                "{name}"
            );
        }
    }

    #[test]
    fn encodingAndDecodingGiveTheValuesOfTheCCode() {
        // `frodo_key_encode` of the bytes of sequence 12, and `frodo_key_decode` of sequence 13,
        // from liboqs 0.16.0.
        for (parameters, encodedFirst, encodedDigest, decodedHex) in [
            (
                &frodoKEM640AES,
                [24576u16, 16384, 0, 8192, 8192, 8192, 8192, 0],
                "48db704a7b9beb1a4d950b9edbf1589759c9fd514fef933e1eb639995844e271",
                "dbd06886ecb1e3040b2cc700aa493d60",
            ),
            (
                &frodoKEM976AES,
                [24576, 8192, 40960, 16384, 8192, 49152, 49152, 24576],
                "d790b9f2f4d4af15a2d860441585f1875115da25eeb54145c5f89b7b5bbf379a",
                "730e6694ea50bc17dc83cf9237c0990f0f90b215a3d9012a",
            ),
            (
                &frodoKEM1344AES,
                [45056, 16384, 20480, 4096, 45056, 28672, 12288, 61440],
                "3527a0790f64de8e45a1f629f433782e05b9c785e0faa44d191741444b0e94cf",
                "b5f3806248952c48e95b02cd06eb9877deff778b3ed90189c45db190620e8113",
            ),
        ] {
            let name = parameters.description.name;
            let arithmetic = MatrixArithmetic::new(parameters);
            let message = &sequenceBytes(16, 12)[..parameters.messageLength()];
            let encoded = arithmetic.encoded(message);
            assert_eq!(&encoded[..8], &encodedFirst, "{name}");
            assert_eq!(valuesDigest(&encoded), encodedDigest, "{name}");
            let decoded: String = arithmetic
                .decoded(&sequence(64, 13))
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(decoded, decodedHex, "{name}");
        }
    }

    #[test]
    fn decodingRoundsEachValueToTheNearestMessageValue() {
        // FrodoKEM-640 has D = 15 and B = 2, so each message value is a multiple of 2^13, and
        // a value rounds to the nearest one: up from 2^12 and down below it.
        let arithmetic = MatrixArithmetic::new(&frodoKEM640AES);
        let decodedFirst = |value: u16| {
            let mut matrix = vec![0u16; 64];
            matrix[0] = value;
            arithmetic.decoded(&matrix)[0] & 0b11
        };
        assert_eq!(decodedFirst(0x0FFF), 0);
        assert_eq!(decodedFirst(0x1000), 1);
        assert_eq!(decodedFirst(0x2FFF), 1);
        assert_eq!(decodedFirst(0x3000), 2);
        // The largest values round up to 2^B, which is 0 modulo 2^B, and the high bit above
        // D is not part of the value.
        assert_eq!(decodedFirst(0x7000), 0);
        assert_eq!(decodedFirst(0x6FFF), 3);
        assert_eq!(decodedFirst(0x8000 | 0x2000), 1);
        // Encoding places each two bits in the high bits of a value, from the low bits of the
        // first byte.
        let message = [0b1110_0100u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let encoded = arithmetic.encoded(&message);
        assert_eq!(&encoded[..5], &[0, 0x2000, 0x4000, 0x6000, 0]);
        assert_eq!(arithmetic.decoded(&encoded), message.to_vec());
    }

    #[test]
    fn sumsDifferencesAndReductionsKeepTheLowBitsOfTheModulus() {
        let arithmetic = MatrixArithmetic::new(&frodoKEM640AES);
        assert_eq!(arithmetic.sum(&[0x7FFF, 3], &[1, 0x7FFF]), vec![0, 2]);
        assert_eq!(
            arithmetic.difference(&[0, 5], &[1, 7]),
            vec![0x7FFF, 0x7FFE]
        );
        let mut matrix = [0xFFFFu16, 0x8000, 0x7FFF, 0x1234];
        arithmetic.reduce(&mut matrix);
        assert_eq!(matrix, [0x7FFF, 0, 0x7FFF, 0x1234]);
        let arithmetic = MatrixArithmetic::new(&frodoKEM976SHAKE);
        assert_eq!(arithmetic.sum(&[0xFFFF], &[2]), vec![1]);
        assert_eq!(arithmetic.difference(&[0], &[1]), vec![0xFFFF]);
        let mut matrix = [0xFFFFu16, 0x8000];
        arithmetic.reduce(&mut matrix);
        assert_eq!(matrix, [0xFFFF, 0x8000]);
    }
}
