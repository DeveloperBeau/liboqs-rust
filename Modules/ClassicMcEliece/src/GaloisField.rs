/// The field GF(2^m) of a parameter set, with `m` 12 or 13, as `gf.c`, `root.c` and the field
/// functions of `util.c` compute it.
///
/// An element is a `u16`. The products, squares and inverses copy the integer formulas of the C
/// code, which have no branch on a value, so they give the bytes of the C code also for a value
/// with bits above `m`. GF(2^12) reduces by `x^12 + x^3 + 1` and GF(2^13) by
/// `x^13 + x^4 + x^3 + x + 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GaloisField {
    bits: u32,
}

impl GaloisField {
    /// The field of `m` bits.
    pub(crate) const fn new(bits: u32) -> Self {
        GaloisField { bits }
    }

    /// The mask of the bits of an element, `GFMASK`.
    pub(crate) const fn mask(self) -> u16 {
        ((1u32 << self.bits) - 1) as u16
    }

    /// The element of two little-endian bytes, `load_gf`. The bits above `m` are dropped.
    pub(crate) fn loaded(self, bytes: &[u8]) -> u16 {
        ((u16::from(bytes[1]) << 8) + u16::from(bytes[0])) & self.mask()
    }

    /// The `m` bits of a value in the reverse order, `bitrev`.
    pub(crate) fn reversed(self, value: u16) -> u16 {
        let mut reversed = ((value & 0x00FF) << 8) + ((value & 0xFF00) >> 8);
        reversed = ((reversed & 0x0F0F) << 4) + ((reversed & 0xF0F0) >> 4);
        reversed = ((reversed & 0x3333) << 2) + ((reversed & 0xCCCC) >> 2);
        reversed = ((reversed & 0x5555) << 1) + ((reversed & 0xAAAA) >> 1);
        reversed >> (16 - self.bits)
    }

    /// The mask `gf_iszero`: the 13 low bits set for zero, and zero for any other value.
    pub(crate) fn zeroMask(value: u16) -> u16 {
        (u32::from(value).wrapping_sub(1) >> 19) as u16
    }

    /// The product of two elements, `gf_mul`.
    pub(crate) fn product(self, left: u16, right: u16) -> u16 {
        if self.bits == 12 {
            Self::product12(left, right)
        } else {
            Self::product13(left, right)
        }
    }

    /// The inverse of an element, `gf_inv`, which is zero for zero.
    pub(crate) fn inverse(self, value: u16) -> u16 {
        if self.bits == 12 {
            Self::inverse12(value)
        } else {
            Self::quotient13(value, 1)
        }
    }

    /// The quotient of a numerator by a denominator, `gf_frac(denominator, numerator)`, which is
    /// zero for a zero denominator.
    pub(crate) fn quotient(self, numerator: u16, denominator: u16) -> u16 {
        if self.bits == 12 {
            Self::product12(Self::inverse12(denominator), numerator)
        } else {
            Self::quotient13(denominator, numerator)
        }
    }

    /// The value of a polynomial at a point, `eval` of `root.c`. The coefficients start at the
    /// constant term, and the last one is the leading coefficient.
    pub(crate) fn evaluation(self, polynomial: &[u16], point: u16) -> u16 {
        let (leading, lower) = polynomial
            .split_last()
            .expect("a polynomial has a coefficient");
        lower.iter().rev().fold(*leading, |value, coefficient| {
            self.product(value, point) ^ coefficient
        })
    }

    /// The product in GF(2^12). The C code multiplies the left factor by each bit of the right
    /// one, which is a shift or zero, and folds the bits 14 to 22 and then 12 and 13.
    fn product12(left: u16, right: u16) -> u16 {
        let factor = u32::from(left);
        let mut product = 0u32;
        for bit in 0..12 {
            let mask = 0u32.wrapping_sub((u32::from(right) >> bit) & 1);
            product ^= (factor << bit) & mask;
        }
        let mut high = product & 0x7F_C000;
        product ^= high >> 9;
        product ^= high >> 12;
        high = product & 0x3000;
        product ^= high >> 9;
        product ^= high >> 12;
        (product & 0xFFF) as u16
    }

    /// The square in GF(2^12), `gf_sq`: the bits spread to the even places and then folded.
    fn square12(value: u16) -> u16 {
        let mut spread = u32::from(value);
        spread = (spread | (spread << 8)) & 0x00FF_00FF;
        spread = (spread | (spread << 4)) & 0x0F0F_0F0F;
        spread = (spread | (spread << 2)) & 0x3333_3333;
        spread = (spread | (spread << 1)) & 0x5555_5555;
        let mut high = spread & 0x7F_C000;
        spread ^= high >> 9;
        spread ^= high >> 12;
        high = spread & 0x3000;
        spread ^= high >> 9;
        spread ^= high >> 12;
        (spread & 0xFFF) as u16
    }

    /// The inverse in GF(2^12), `gf_inv`: the power `2^12 - 2` by the chain of the C code.
    fn inverse12(value: u16) -> u16 {
        let mut power = Self::square12(value);
        let power11 = Self::product12(power, value);
        power = Self::square12(power11);
        power = Self::square12(power);
        let power1111 = Self::product12(power, power11);
        power = Self::square12(power1111);
        power = Self::square12(power);
        power = Self::square12(power);
        power = Self::square12(power);
        power = Self::product12(power, power1111);
        power = Self::square12(power);
        power = Self::square12(power);
        power = Self::product12(power, power11);
        power = Self::square12(power);
        power = Self::product12(power, value);
        Self::square12(power)
    }

    /// Folds the bits of a mask of a GF(2^13) product once, as the C code does.
    fn folded13(value: u64, mask: u64) -> u64 {
        let high = value & mask;
        value ^ (high >> 9) ^ (high >> 10) ^ (high >> 12) ^ (high >> 13)
    }

    /// The product in GF(2^13). The C code multiplies the left factor by each bit of the right
    /// one, which is a shift or zero, and folds the bits 16 to 24 and then 13 to 15.
    fn product13(left: u16, right: u16) -> u16 {
        let factor = u64::from(left);
        let mut product = 0u64;
        for bit in 0..13 {
            let mask = 0u64.wrapping_sub((u64::from(right) >> bit) & 1);
            product ^= (factor << bit) & mask;
        }
        product = Self::folded13(product, 0x1FF_0000);
        product = Self::folded13(product, 0x000_E000);
        (product & 0x1FFF) as u16
    }

    /// The square of the square in GF(2^13), `gf_sq2`.
    fn squareSquared13(value: u16) -> u16 {
        const masks: [u64; 4] = [
            0x0001_FF00_0000_0000,
            0x0000_00FF_8000_0000,
            0x0000_0000_7FC0_0000,
            0x0000_0000_003F_E000,
        ];
        let mut spread = u64::from(value);
        spread = (spread | (spread << 24)) & 0x0000_00FF_0000_00FF;
        spread = (spread | (spread << 12)) & 0x000F_000F_000F_000F;
        spread = (spread | (spread << 6)) & 0x0303_0303_0303_0303;
        spread = (spread | (spread << 3)) & 0x1111_1111_1111_1111;
        for mask in masks {
            spread = Self::folded13(spread, mask);
        }
        (spread & 0x1FFF) as u16
    }

    /// The square of a value times a factor in GF(2^13), `gf_sqmul`.
    fn squareProduct13(value: u16, factor: u16) -> u16 {
        const masks: [u64; 3] = [
            0x0000_001F_F000_0000,
            0x0000_0000_0FF8_0000,
            0x0000_0000_0007_E000,
        ];
        let mut spread = u64::from(value);
        let factor = u64::from(factor);
        let mut product = (factor << 6) * (spread & (1 << 6));
        spread ^= spread << 7;
        product ^= factor * (spread & 0x04001);
        product ^= (factor * (spread & 0x08002)) << 1;
        product ^= (factor * (spread & 0x10004)) << 2;
        product ^= (factor * (spread & 0x20008)) << 3;
        product ^= (factor * (spread & 0x40010)) << 4;
        product ^= (factor * (spread & 0x80020)) << 5;
        for mask in masks {
            product = Self::folded13(product, mask);
        }
        (product & 0x1FFF) as u16
    }

    /// The square of the square of a value times a factor in GF(2^13), `gf_sq2mul`.
    fn squareSquaredProduct13(value: u16, factor: u16) -> u16 {
        const masks: [u64; 6] = [
            0x1FF0_0000_0000_0000,
            0x000F_F800_0000_0000,
            0x0000_07FC_0000_0000,
            0x0000_0003_FE00_0000,
            0x0000_0000_01FE_0000,
            0x0000_0000_0001_E000,
        ];
        let mut spread = u64::from(value);
        let factor = u64::from(factor);
        let mut product = (factor << 18) * (spread & (1 << 6));
        spread ^= spread << 21;
        product ^= factor * (spread & 0x0_1000_0001);
        product ^= (factor * (spread & 0x0_2000_0002)) << 3;
        product ^= (factor * (spread & 0x0_4000_0004)) << 6;
        product ^= (factor * (spread & 0x0_8000_0008)) << 9;
        product ^= (factor * (spread & 0x1_0000_0010)) << 12;
        product ^= (factor * (spread & 0x2_0000_0020)) << 15;
        for mask in masks {
            product = Self::folded13(product, mask);
        }
        (product & 0x1FFF) as u16
    }

    /// The quotient in GF(2^13), `gf_frac`: the numerator times the power `2^13 - 2` of the
    /// denominator, by the chain of the C code.
    fn quotient13(denominator: u16, numerator: u16) -> u16 {
        let power11 = Self::squareProduct13(denominator, denominator);
        let power1111 = Self::squareSquaredProduct13(power11, power11);
        let mut power = Self::squareSquared13(power1111);
        power = Self::squareSquaredProduct13(power, power1111);
        power = Self::squareSquared13(power);
        power = Self::squareSquaredProduct13(power, power1111);
        Self::squareProduct13(power, numerator)
    }
}

#[cfg(test)]
mod tests {
    use super::GaloisField;
    use crate::testSupport::{SeededWords, digest};

    const field12: GaloisField = GaloisField::new(12);
    const field13: GaloisField = GaloisField::new(13);

    /// The product of two elements by the schoolbook method: the carry-less product of the
    /// bits, then the reduction by the field polynomial from the top bit down.
    fn schoolbookProduct(bits: u32, left: u16, right: u16) -> u16 {
        let polynomial: u32 = if bits == 12 { 0x1009 } else { 0x201B };
        let mut product = 0u32;
        for bit in 0..bits {
            if (right >> bit) & 1 == 1 {
                product ^= u32::from(left) << bit;
            }
        }
        for bit in (bits..2 * bits).rev() {
            if (product >> bit) & 1 == 1 {
                product ^= polynomial << (bit - bits);
            }
        }
        product as u16
    }

    /// The power of an element by repeated products of the schoolbook method.
    fn schoolbookPower(bits: u32, value: u16, exponent: u32) -> u16 {
        (0..exponent).fold(1, |power, _| schoolbookProduct(bits, power, value))
    }

    #[test]
    fn productsAreTheSchoolbookProductsOfTheField() {
        let mut words = SeededWords::new(0x6766_6D75_6C00);
        for field in [field12, field13] {
            let bits = field.bits;
            let mut factors: Vec<u16> = vec![0, 1, 2, field.mask(), field.mask() - 1];
            factors.extend((0..64).map(|_| words.next() as u16 & field.mask()));
            for left in 0..=field.mask() {
                for right in &factors {
                    assert_eq!(
                        field.product(left, *right),
                        schoolbookProduct(bits, left, *right),
                        "{bits} bits: {left} times {right}"
                    );
                }
            }
        }
    }

    #[test]
    fn inversesAndQuotientsAreTheInversesOfTheField() {
        for field in [field12, field13] {
            let bits = field.bits;
            assert_eq!(field.inverse(0), 0);
            assert_eq!(field.quotient(5, 0), 0);
            for value in 1..=field.mask() {
                let inverse = field.inverse(value);
                assert_eq!(field.product(value, inverse), 1, "{bits} bits: {value}");
                assert_eq!(field.quotient(1, value), inverse, "{bits} bits: {value}");
            }
            // The power 2^m - 2 is the inverse by Fermat, written by hand for a few values.
            for value in [2u16, 3, 0x123, field.mask()] {
                assert_eq!(
                    field.inverse(value),
                    schoolbookPower(bits, value, (1 << bits) - 2),
                    "{bits} bits: {value}"
                );
            }
            let mut words = SeededWords::new(u64::from(bits));
            for _ in 0..2000 {
                let numerator = words.next() as u16 & field.mask();
                let denominator = (words.next() as u16 & field.mask()).max(1);
                let quotient = field.quotient(numerator, denominator);
                assert_eq!(field.product(quotient, denominator), numerator);
            }
        }
    }

    #[test]
    fn fieldFunctionsGiveTheKnownAnswersOfTheCFunctions() {
        // The SHA3-256 of the outputs of `gf_mul`, `gf_inv` and `gf_frac` of
        // `pqclean_mceliece348864_clean` and `pqclean_mceliece460896_clean` in liboqs 0.16.0, as
        // little-endian 16-bit values. `gf_inv` takes every 16-bit value, and `gf_mul` and
        // `gf_frac` take 20000 pairs of 16-bit values from SplitMix64 of the seed 1, the low
        // half of each word first. Values with bits above m are in the domain too.
        let expected = [
            (
                field12,
                "ff41362a9a55f6b6e26e078abc80b617697dff02bf6a2ef3027f7883a4e29935",
                "5cfd50462a0b31b30fba587bb6b32b62dbe7882c5253b2e89dea6f855044c2b8",
                "e6a1bebddfa86240056901b42ccccac1aa919e1dd0b2efda18cbe2660e15156c",
            ),
            (
                field13,
                "3be8195f2d07bcd898c1e9868fc9af91a5698612ea53be4f578dd3348c240758",
                "15a5cb36e87b400fb45b61769d5f8f1b94ab7ed80cd3f126c8262e315ca589d7",
                "55f83dc0787ce95336232126679c184da606cc81b443d9096e822a6d29d6f838",
            ),
        ];
        for (field, productDigest, inverseDigest, quotientDigest) in expected {
            let mut words = SeededWords::new(1);
            let mut products = Vec::new();
            let mut quotients = Vec::new();
            for _ in 0..20_000 {
                let word = words.next();
                let (left, right) = (word as u16, (word >> 16) as u16);
                products.extend(field.product(left, right).to_le_bytes());
                quotients.extend(field.quotient(right, left).to_le_bytes());
            }
            let inverses: Vec<u8> = (0..=u16::MAX)
                .flat_map(|value| field.inverse(value).to_le_bytes())
                .collect();
            assert_eq!(digest(&products), productDigest, "{} bits", field.bits);
            assert_eq!(digest(&inverses), inverseDigest, "{} bits", field.bits);
            assert_eq!(digest(&quotients), quotientDigest, "{} bits", field.bits);
        }
    }

    #[test]
    fn theZeroMaskSetsThirteenBitsForZeroOnly() {
        assert_eq!(GaloisField::zeroMask(0), 0x1FFF);
        for value in 1..=u16::MAX {
            assert_eq!(GaloisField::zeroMask(value), 0, "{value}");
        }
    }

    #[test]
    fn reversalAndLoadingFollowUtilC() {
        assert_eq!(field12.reversed(1), 0x800);
        assert_eq!(field12.reversed(0x801), 0x801);
        assert_eq!(field13.reversed(1), 0x1000);
        assert_eq!(field13.reversed(0x0F0F), 0x1E1E);
        for field in [field12, field13] {
            for value in 0..=field.mask() {
                assert_eq!(field.reversed(field.reversed(value)), value);
            }
        }
        assert_eq!(field12.loaded(&[0x34, 0xF2]), 0x234);
        assert_eq!(field13.loaded(&[0x34, 0xF2]), 0x1234);
        assert_eq!(field13.mask(), 0x1FFF);
    }

    #[test]
    fn evaluationIsTheValueOfThePolynomialAtThePoint() {
        // 3 + 2 x + x^2 at x = 5 in GF(2^12): 3 + 10 + 17 = 3 ^ 10 ^ 17.
        assert_eq!(field12.evaluation(&[3, 2, 1], 5), 3 ^ 10 ^ 17);
        assert_eq!(field13.evaluation(&[7], 0x1ABC), 7);
        let mut words = SeededWords::new(9);
        let polynomial: Vec<u16> = (0..20).map(|_| words.next() as u16 & 0x1FFF).collect();
        for point in [0u16, 1, 0x1FFF, 0x1234] {
            let mut expected = 0u16;
            let mut power = 1u16;
            for coefficient in &polynomial {
                expected ^= schoolbookProduct(13, *coefficient, power);
                power = schoolbookProduct(13, power, point);
            }
            assert_eq!(field13.evaluation(&polynomial, point), expected, "{point}");
        }
    }
}
