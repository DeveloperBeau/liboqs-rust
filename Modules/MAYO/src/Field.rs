//! The arithmetic of GF(16), the field `F2[x] / (x^4 + x + 1)` of MAYO, as
//! `simple_arithmetic.h` computes it. An element is a nibble: bit i is the coefficient of x^i.
//! Addition is the exclusive or.

/// The product of two elements, as `mul_f`: the carry-less product of the nibbles, reduced
/// modulo `x^4 + x + 1`.
pub(crate) fn product(left: u8, right: u8) -> u8 {
    let mut wide = (left & 1) * right;
    wide ^= (left & 2) * right;
    wide ^= (left & 4) * right;
    wide ^= (left & 8) * right;
    // x^4 = x + 1, x^5 = x^2 + x and x^6 = x^3 + x^2.
    let high = wide & 0xF0;
    (wide ^ (high >> 4) ^ (high >> 3)) & 0x0F
}

/// The products of one element with eight elements, one in the low nibble of each byte of a
/// word whose high nibbles are zero, as `mul_fx8`.
pub(crate) fn productsInBytes(scalar: u8, values: u64) -> u64 {
    let scalar = u64::from(scalar);
    let mut wide = (scalar & 1) * values;
    wide ^= (scalar & 2) * values;
    wide ^= (scalar & 4) * values;
    wide ^= (scalar & 8) * values;
    let high = wide & 0xF0F0_F0F0_F0F0_F0F0;
    (wide ^ (high >> 4) ^ (high >> 3)) & 0x0F0F_0F0F_0F0F_0F0F
}

/// The inverse of an element, as `inverse_f`: `a^14`, which is zero for zero.
pub(crate) fn inverse(value: u8) -> u8 {
    let square = product(value, value);
    let fourth = product(square, square);
    let eighth = product(fourth, fourth);
    let sixth = product(square, fourth);
    product(eighth, sixth)
}

/// The products of an element with 1, x, x^2 and x^3, in the low nibbles of the bytes 0 to 3
/// of a word, as `mul_table`. The high nibbles of the bytes 1 to 3 are not part of the products.
pub(crate) fn multiplicationTable(scalar: u8) -> u32 {
    let spread = u32::from(scalar) * 0x0804_0201;
    let high = spread & 0xF0F0_F0F0;
    spread ^ (high >> 4) ^ (high >> 3)
}

/// The product of a matrix of `output.len()` rows and `vector.len()` columns, in row order,
/// with a vector, as `mat_mul` with one column and `lincomb` of each row.
pub(crate) fn matrixTimesVector(matrix: &[u8], vector: &[u8], output: &mut [u8]) {
    for (row, result) in matrix.chunks_exact(vector.len()).zip(output.iter_mut()) {
        *result = row
            .iter()
            .zip(vector)
            .fold(0, |sum, (entry, element)| sum ^ product(*entry, *element));
    }
}

/// The elements of bytes, two to a byte with the low nibble first, as `decode`: the length of
/// the output is the number of elements, and an odd number takes the low nibble of the last
/// byte.
pub(crate) fn decode(bytes: &[u8], elements: &mut [u8]) {
    for (pair, byte) in elements.chunks_mut(2).zip(bytes) {
        pair[0] = byte & 0x0F;
        if let Some(high) = pair.get_mut(1) {
            *high = byte >> 4;
        }
    }
}

/// The bytes of elements, two to a byte with the low nibble first, as `encode`: an odd number
/// of elements puts the last one in the low nibble of the last byte.
pub(crate) fn encode(elements: &[u8], bytes: &mut [u8]) {
    for (pair, byte) in elements.chunks(2).zip(bytes.iter_mut()) {
        // The two nibbles have no bit in common, so `+` joins them.
        *byte = pair[0] + pair.get(1).map_or(0, |high| high << 4);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode, encode, inverse, matrixTimesVector, multiplicationTable, product, productsInBytes,
    };

    /// The product in `F2[x] / (x^4 + x + 1)` by its definition: shift and add, with
    /// `x^4 = x + 1` after each shift.
    fn definedProduct(left: u8, right: u8) -> u8 {
        let (mut shifted, mut remaining, mut result) = (left, right, 0u8);
        for _ in 0..4 {
            if remaining & 1 == 1 {
                result ^= shifted;
            }
            remaining >>= 1;
            let overflow = shifted & 8 != 0;
            shifted = (shifted << 1) & 0x0F;
            if overflow {
                shifted ^= 0b0011;
            }
        }
        result
    }

    #[test]
    fn productIsTheProductOfTheFieldForEveryPair() {
        for left in 0..16 {
            for right in 0..16 {
                assert_eq!(
                    product(left, right),
                    definedProduct(left, right),
                    "{left} {right}"
                );
            }
        }
        // x^3 x = x^4 = x + 1, and x^3 x^3 = x^6 = x^3 + x^2.
        assert_eq!(product(8, 2), 3);
        assert_eq!(product(8, 8), 12);
    }

    #[test]
    fn inverseIsTheTableOfTheCodeOfTheMAYOTeam() {
        // The table in the comment of `inverse_f` in `simple_arithmetic.h`.
        let table = [0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8];
        for (value, expected) in table.iter().enumerate() {
            assert_eq!(inverse(value as u8), *expected, "{value}");
        }
        for value in 1..16 {
            assert_eq!(product(value, inverse(value)), 1, "{value}");
        }
    }

    #[test]
    fn productsInBytesMultiplyTheElementOfEachByte() {
        let mut state = 0x4D41_594Fu64;
        for scalar in 0..16 {
            for _ in 0..20 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let values = state & 0x0F0F_0F0F_0F0F_0F0F;
                let products = productsInBytes(scalar, values);
                for byte in 0..8 {
                    let element = ((values >> (8 * byte)) & 0x0F) as u8;
                    assert_eq!(
                        (products >> (8 * byte)) & 0xFF,
                        u64::from(definedProduct(scalar, element)),
                        "{scalar} {values:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn multiplicationTableHoldsTheProductsWithEachPowerOfX() {
        for scalar in 0..16 {
            let table = multiplicationTable(scalar);
            // The first byte is the element itself, with no high nibble, so `mul_table & 0xff`
            // of the C code is the product with 1.
            assert_eq!(table & 0xFF, u32::from(scalar));
            for power in 0..4 {
                assert_eq!(
                    (table >> (8 * power)) & 0x0F,
                    u32::from(definedProduct(scalar, 1 << power)),
                    "{scalar} {power}"
                );
            }
        }
    }

    #[test]
    fn decodingReadsTheLowNibbleFirstAndEncodingWritesIt() {
        let mut elements = [0u8; 5];
        decode(&[0x21, 0x43, 0xA5], &mut elements);
        assert_eq!(elements, [1, 2, 3, 4, 5]);
        let mut bytes = [0xFFu8; 3];
        encode(&[1, 2, 3, 4, 5], &mut bytes);
        assert_eq!(bytes, [0x21, 0x43, 0x05]);
        let mut even = [0u8; 4];
        decode(&[0xF0, 0x0F], &mut even);
        assert_eq!(even, [0, 15, 15, 0]);
        let mut evenBytes = [0u8; 2];
        encode(&even, &mut evenBytes);
        assert_eq!(evenBytes, [0xF0, 0x0F]);
    }

    #[test]
    fn matrixTimesVectorSumsTheProductsOfEachRow() {
        // Two rows of three columns: (1, x, x^3) and (x + 1, 0, x^2).
        let matrix = [1, 2, 8, 3, 0, 4];
        let vector = [7, 9, 2];
        let mut output = [0u8; 2];
        matrixTimesVector(&matrix, &vector, &mut output);
        let expected = [
            definedProduct(1, 7) ^ definedProduct(2, 9) ^ definedProduct(8, 2),
            definedProduct(3, 7) ^ definedProduct(4, 2),
        ];
        assert_eq!(output, expected);
        assert_eq!(expected, [7 ^ 1 ^ 3, 9 ^ 8]);
    }
}
