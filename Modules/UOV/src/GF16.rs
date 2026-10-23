use crate::FieldArithmetic;

/// GF(16) = GF(2)[x] / (x^4 + x + 1), the field of `OV-Is` and its compressed forms, with two
/// elements in a byte.
pub(crate) struct GF16;

impl GF16 {
    /// The square of an element, as `gf16_squ` computes it.
    fn square(element: u8) -> u8 {
        let mut square = element & 1;
        square ^= (element << 1) & 4;
        square ^= ((element >> 2) & 1) * 3;
        square ^ (((element >> 3) & 1) * 12)
    }
}

impl FieldArithmetic for GF16 {
    const elementBits: u32 = 4;
    const topBits: u64 = 0x8888_8888_8888_8888;
    const reducedPower: u64 = 0x3;

    /// The inverse `a^14` by the chain of squares of `gf16_inv`, the Fermat inversion.
    fn inverse(element: u8) -> u8 {
        let element = element & Self::elementMask;
        let power2 = Self::square(element);
        let power4 = Self::square(power2);
        let power8 = Self::square(power4);
        let power6 = Self::product(power4, power2);
        Self::product(power8, power6)
    }
}

#[cfg(test)]
mod tests {
    use super::GF16;
    use crate::FieldArithmetic;
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The product of two elements by the definition: the carry-less product of the
    /// polynomials, reduced by x^4 + x + 1.
    fn definedProduct(left: u8, right: u8) -> u8 {
        let mut product = 0u16;
        for bit in 0..4 {
            if (right >> bit) & 1 == 1 {
                product ^= u16::from(left) << bit;
            }
        }
        for bit in (4..8).rev() {
            if (product >> bit) & 1 == 1 {
                product ^= 0b1_0011 << (bit - 4);
            }
        }
        product as u8
    }

    #[test]
    fn everyProductIsTheProductOfTheDefinitionAndOfTheCCode() {
        let mut table = Vec::with_capacity(256);
        for left in 0..16u8 {
            for right in 0..16u8 {
                let product = GF16::product(left, right);
                assert_eq!(product, definedProduct(left, right), "{left} * {right}");
                table.push(product);
            }
        }
        // x^4 = x + 1, so x * x^3 = 3.
        assert_eq!(GF16::product(2, 8), 3);
        // The digest of every `gf16_mul(a, b)` at `a * 16 + b`, from liboqs 0.16.0.
        assert_eq!(
            OutputDigest::of(&table),
            "0eadebed1b47eb4e333fcf592bd7ffa161d353982b78a9bb0eeece9c07859895"
        );
    }

    #[test]
    fn everySquareIsTheProductOfTheElementWithItself() {
        for element in 0..16u8 {
            assert_eq!(GF16::square(element), GF16::product(element, element));
        }
    }

    #[test]
    fn everyInverseIsTheInverseOfTheCCode() {
        // `gf16_inv` of 0 to 15, from liboqs 0.16.0.
        let inverses = [0u8, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8];
        for element in 0..16u8 {
            let inverse = GF16::inverse(element);
            assert_eq!(inverse, inverses[element as usize], "{element}");
            if element != 0 {
                assert_eq!(GF16::product(element, inverse), 1, "{element}");
            }
        }
    }

    #[test]
    fn theWordProductIsTheWordProductOfTheCCode() {
        // `gf16v_mul_u32` of the words 0x76543210 and 0xFEDCBA98 times each scalar from 0 to
        // 15, as eight little-endian bytes for each scalar, from liboqs 0.16.0.
        let mut bytes = Vec::with_capacity(128);
        for scalar in 0..16u8 {
            let scaled =
                GF16::scaledWord(0xFEDC_BA98_7654_3210, &GF16::scalarMasks(scalar)).to_le_bytes();
            bytes.extend_from_slice(&scaled);
        }
        assert_eq!(
            OutputDigest::of(&bytes),
            "25894d27443dc7a4b25bd9cac34a438a3bf5cda097c5ba736e319b3d08eee3ee"
        );
    }
}
