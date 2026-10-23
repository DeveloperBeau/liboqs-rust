/// The arithmetic of GF(16), the field `Z2[x] / (x^4 + x + 1)` of SNOVA, in the two forms of the
/// C code.
///
/// An element in a nibble holds its four coefficients in its low four bits, and `product` reads
/// the table `mt4b` of `gf16_init.h`. The spread form of `snova_kernel.h` holds coefficient `i`
/// at bit `3 i`. The integer product of two spread elements is then their product as
/// polynomials: the coefficient of `x^k` is the low bit of the three bits at `3 k`, and the at
/// most four terms of a coefficient never carry into the next one. The exclusive or of such
/// products is their sum, `coefficientBits` keeps the low bit of each coefficient, and `reduced`
/// folds the result back to an element. The port keeps both forms where the C code uses them, so
/// every intermediate value is the value of the C code.
pub(crate) struct FieldArithmetic;

/// The low bit of each coefficient of a spread polynomial up to degree 10: every third bit,
/// `0x49249249` of the C code.
pub(crate) const coefficientBits: u32 = 0x4924_9249;

/// The bits of a spread element of degree below 4.
const elementBits: u32 = 0x249;

/// The powers `x^0` to `x^14` of `F_star` in `init_gf16_tables`.
const powersOfX: [u8; 15] = [1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9];

/// The product table `mt4b` of `init_gf16_tables`: entry `16 a ^ b` is the product of `a` and
/// `b`, from the logarithms of the powers of `x`.
const productTable: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut first = 0;
    while first < 15 {
        let mut second = 0;
        while second < 15 {
            let index = ((powersOfX[first] as usize) << 4) ^ powersOfX[second] as usize;
            table[index] = powersOfX[(first + second) % 15];
            second += 1;
        }
        first += 1;
    }
    table
};

impl FieldArithmetic {
    /// The product of two elements, `gf16_get_mul` with the table `mt4b`.
    pub(crate) fn product(left: u8, right: u8) -> u8 {
        productTable[(usize::from(left) << 4) ^ usize::from(right)]
    }

    /// The spread form of an element, `gf16_from_nibble`: coefficient `i` at bit `3 i`.
    pub(crate) fn spread(element: u8) -> u32 {
        debug_assert!(element < 16, "{element} is not an element of GF(16)");
        // The element and its copy four bits up have disjoint bits, so `+` joins them, and the
        // two masks keep disjoint bits too.
        let doubled = u32::from(element) + (u32::from(element) << 4);
        (doubled & 0x41) + ((doubled << 2) & 0x208)
    }

    /// The spread element of a spread polynomial up to degree 10, `gf16_reduce`.
    ///
    /// Each of the three steps folds the coefficients from `x^4` up onto `x^0` and `x^1`, with
    /// `x^4 = x + 1`. The bits between the coefficients move only to other bits between the
    /// coefficients, so they never reach the result.
    pub(crate) fn reduced(value: u32) -> u32 {
        let mut result = value & coefficientBits;
        let mut upper = value >> 12;
        result = result ^ upper ^ (upper << 3);
        upper = result >> 12;
        result = result ^ upper ^ (upper << 3);
        upper = result >> 12;
        result = result ^ upper ^ (upper << 3);
        result & elementBits
    }

    /// The element of a spread polynomial up to degree 10, `gf16_to_nibble`.
    pub(crate) fn element(value: u32) -> u8 {
        let reduced = Self::reduced(value);
        let folded = reduced | (reduced >> 4);
        // The two masks keep disjoint bits, so `+` joins them.
        ((folded & 0x5) + ((folded >> 2) & 0xA)) as u8
    }

    /// A spread element, of 10 bits, in 16 bits. The product of two such values cannot exceed
    /// 32 bits, so the hot loops multiply them with no overflow check and with the same products
    /// as the C code.
    pub(crate) fn narrowed(value: u32) -> u16 {
        u16::try_from(value).expect("a spread element has 10 bits")
    }

    /// The product of two narrowed spread elements in 32 bits.
    pub(crate) fn spreadProduct(left: u16, right: u16) -> u32 {
        u32::from(left) * u32::from(right)
    }

    /// The inverse of a spread element, or zero for zero, `gf16_inv`: `x^14`, the product of
    /// `x^2`, `x^4` and `x^8`.
    pub(crate) fn inverse(value: u32) -> u32 {
        let value = Self::reduced(value);
        let square = Self::reduced(value * value);
        let fourthPower = Self::reduced(square * square);
        let eighthPower = Self::reduced(fourthPower * fourthPower);
        Self::reduced(square * ((fourthPower * eighthPower) & coefficientBits))
    }

    /// One when a spread element is not zero and zero when it is, with no branch,
    /// `ct_xgf16_is_not_zero`.
    pub(crate) fn isNonZero(value: u32) -> u32 {
        (value | (value >> 3) | (value >> 6) | (value >> 9)) & 1
    }

    /// One when an element is not zero and zero when it is, with no branch,
    /// `ct_gf16_is_not_zero`.
    pub(crate) fn isNonZeroElement(element: u8) -> u32 {
        u32::from((element | (element >> 1) | (element >> 2) | (element >> 3)) & 1)
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldArithmetic, coefficientBits};

    /// The product of two polynomials over GF(2) of degree below 4, modulo `x^4 + x + 1`, bit by
    /// bit.
    fn polynomialProduct(left: u8, right: u8) -> u8 {
        let mut wide = 0u32;
        for bit in 0..4 {
            if (right >> bit) & 1 == 1 {
                wide ^= u32::from(left) << bit;
            }
        }
        polynomialRemainder(wide)
    }

    /// A polynomial over GF(2) modulo `x^4 + x + 1`, bit by bit from the top.
    fn polynomialRemainder(mut wide: u32) -> u8 {
        for degree in (4..32).rev() {
            if (wide >> degree) & 1 == 1 {
                wide ^= 0b10011 << (degree - 4);
            }
        }
        wide as u8
    }

    /// The spread form written out bit by bit: coefficient `i` at bit `3 i`.
    fn spreadByBits(polynomial: u32) -> u32 {
        (0..11)
            .filter(|bit| (polynomial >> bit) & 1 == 1)
            .map(|bit| 1u32 << (3 * bit))
            .sum()
    }

    #[test]
    fn theTableHoldsThePolynomialProductsModuloX4PlusXPlus1() {
        for left in 0..16u8 {
            for right in 0..16u8 {
                assert_eq!(
                    FieldArithmetic::product(left, right),
                    polynomialProduct(left, right),
                    "{left} * {right}"
                );
            }
        }
        // x * x^3 = x^4 = x + 1, and x^14 is the inverse of x.
        assert_eq!(FieldArithmetic::product(2, 8), 3);
        assert_eq!(FieldArithmetic::product(2, 9), 1);
    }

    #[test]
    fn theSpreadFormHoldsCoefficientIAtBit3I() {
        for element in 0..16u8 {
            assert_eq!(
                FieldArithmetic::spread(element),
                spreadByBits(u32::from(element)),
                "{element}"
            );
            assert_eq!(
                FieldArithmetic::element(FieldArithmetic::spread(element)),
                element
            );
        }
    }

    #[test]
    fn spreadProductsAreTheProductsOfTheTable() {
        for left in 0..16u8 {
            for right in 0..16u8 {
                let product = FieldArithmetic::spread(left) * FieldArithmetic::spread(right);
                assert_eq!(
                    FieldArithmetic::element(product),
                    FieldArithmetic::product(left, right),
                    "{left} * {right}"
                );
            }
        }
    }

    #[test]
    fn reductionFoldsEveryPolynomialUpToDegree10AndIgnoresTheBitsBetween() {
        let mut noise = 0x1234_5678u32;
        for polynomial in 0..1u32 << 11 {
            let expected = spreadByBits(u32::from(polynomialRemainder(polynomial)));
            let spread = spreadByBits(polynomial);
            assert_eq!(
                FieldArithmetic::reduced(spread),
                expected,
                "{polynomial:#b}"
            );
            // Any bits between the coefficients, as the sums of products leave them.
            noise = noise.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let withNoise = spread | (noise & !coefficientBits);
            assert_eq!(
                FieldArithmetic::reduced(withNoise),
                expected,
                "{polynomial:#b} with the bits {withNoise:#x}"
            );
        }
    }

    #[test]
    fn theInverseIsTheInverseOfEachNonZeroElementAndZeroForZero() {
        assert_eq!(FieldArithmetic::inverse(0), 0);
        for element in 1..16u8 {
            let spread = FieldArithmetic::spread(element);
            let inverse = FieldArithmetic::inverse(spread);
            assert_eq!(FieldArithmetic::element(spread * inverse), 1, "{element}");
            assert_eq!(FieldArithmetic::reduced(inverse), inverse);
        }
    }

    #[test]
    fn zeroTestsAreOneExactlyForTheNonZeroElements() {
        for element in 0..16u8 {
            let expected = u32::from(element != 0);
            assert_eq!(FieldArithmetic::isNonZeroElement(element), expected);
            assert_eq!(
                FieldArithmetic::isNonZero(FieldArithmetic::spread(element)),
                expected
            );
        }
    }
}
