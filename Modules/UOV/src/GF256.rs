use crate::FieldArithmetic;

/// GF(256) = GF(2)[x] / (x^8 + x^4 + x^3 + x + 1), the field of AES and of `OV-Ip`, `OV-III`,
/// `OV-V` and their compressed forms, with one element in a byte.
pub(crate) struct GF256;

impl FieldArithmetic for GF256 {
    const elementBits: u32 = 8;
    const topBits: u64 = 0x8080_8080_8080_8080;
    const reducedPower: u64 = 0x1B;

    /// The inverse by the constant-time extended GCD of `gf256_inv`, with the 16-bit
    /// arithmetic of the C code.
    fn inverse(element: u8) -> u8 {
        let mut f: u16 = 0x11B;
        let mut g: u16 = u16::from(element) << 1;
        let mut delta: i16 = 1;
        let mut r: u16 = 0x100;
        let mut v: u16 = 0;
        for _ in 0..15 {
            let g0 = (g >> 8) & 1;
            // `uint16_t minus_delta = -delta`, and the swap takes its sign bit.
            let minusDelta = (delta as u16).wrapping_neg();
            let swap = (minusDelta >> 15) & g0;
            // The C code computes `swap * (minus_delta << 1) + delta + 1` in `int` and keeps
            // the low 16 bits in `int16_t`.
            delta = (i32::from(swap) * (i32::from(minusDelta) << 1) + i32::from(delta) + 1) as i16;
            let fg = f ^ g;
            g ^= f * g0;
            f ^= fg * swap;
            let vr = v ^ r;
            r ^= v * g0;
            v ^= vr * swap;
            g <<= 1;
            v >>= 1;
        }
        (v & 0xFF) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::GF256;
    use crate::FieldArithmetic;
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The product of two elements by the definition: the carry-less product of the
    /// polynomials, reduced by x^8 + x^4 + x^3 + x + 1.
    fn definedProduct(left: u8, right: u8) -> u8 {
        let mut product = 0u32;
        for bit in 0..8 {
            if (right >> bit) & 1 == 1 {
                product ^= u32::from(left) << bit;
            }
        }
        for bit in (8..16).rev() {
            if (product >> bit) & 1 == 1 {
                product ^= 0x11B << (bit - 8);
            }
        }
        product as u8
    }

    #[test]
    fn everyProductIsTheProductOfTheDefinitionAndOfTheCCode() {
        let mut table = Vec::with_capacity(65536);
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                let product = GF256::product(left, right);
                assert_eq!(product, definedProduct(left, right), "{left} * {right}");
                table.push(product);
            }
        }
        // FIPS 197, Section 4.2: {57} * {83} = {c1} and {57} * {13} = {fe}.
        assert_eq!(GF256::product(0x57, 0x83), 0xC1);
        assert_eq!(GF256::product(0x57, 0x13), 0xFE);
        // The digest of every `gf256_mul(a, b)` at `a * 256 + b`, from liboqs 0.16.0.
        assert_eq!(
            OutputDigest::of(&table),
            "b7098b38497099f3514450b1a7eac473c469f515446646821a83608681f4365c"
        );
    }

    #[test]
    fn everyInverseIsTheInverseOfTheCCode() {
        let inverses: Vec<u8> = (0..=255u8).map(GF256::inverse).collect();
        for (element, inverse) in inverses.iter().enumerate().skip(1) {
            assert_eq!(GF256::product(element as u8, *inverse), 1, "{element}");
        }
        assert_eq!(inverses[0], 0);
        // FIPS 197, Section 5.1.1: the inverse of {53} is {ca}.
        assert_eq!(inverses[0x53], 0xCA);
        // The digest of `gf256_inv` of 0 to 255, from liboqs 0.16.0.
        assert_eq!(
            OutputDigest::of(&inverses),
            "5638a6211c9ba3869b1868d44faad13c71b583995624cbfba07b8c2d97fbfdfa"
        );
    }
}
