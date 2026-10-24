/// The field GF(2^8) of the Reed-Solomon code of HQC, `gf.c` and `gf.h` of the reference code.
///
/// The field polynomial is `x^8 + x^4 + x^3 + x^2 + 1` and the primitive element `alpha` is
/// `x`. The product works on the bits with masks, so its time does not depend on the values.
pub(crate) struct GaloisField;

/// The field polynomial, `PARAM_GF_POLY`.
const fieldPolynomial: u16 = 0x11D;

/// The order of the multiplicative group, `2^8 - 1`, `PARAM_GF_MUL_ORDER`.
pub(crate) const multiplicativeOrder: usize = 255;

/// The powers `alpha^i` for `i` below 255, the table `gf_exp`.
const powers: [u8; multiplicativeOrder] = powerTable();

/// The logarithms to the base `alpha`, with the logarithm of 0 set to 0, the table `gf_log`.
const logarithms: [u8; 256] = logarithmTable();

/// The powers of `alpha`, as `gf_generate` makes them.
const fn powerTable() -> [u8; multiplicativeOrder] {
    let mut table = [0u8; multiplicativeOrder];
    let mut element = 1u16;
    let mut exponent = 0;
    while exponent < multiplicativeOrder {
        table[exponent] = element as u8;
        element <<= 1;
        if element >= 256 {
            element ^= fieldPolynomial;
        }
        exponent += 1;
    }
    table
}

/// The logarithm of each nonzero element, the inverse of the power table.
const fn logarithmTable() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut exponent = 0;
    while exponent < multiplicativeOrder {
        table[powers[exponent] as usize] = exponent as u8;
        exponent += 1;
    }
    table
}

impl GaloisField {
    /// The power `alpha^exponent`.
    pub(crate) fn power(exponent: usize) -> u8 {
        powers[exponent % multiplicativeOrder]
    }

    /// The logarithm of an element to the base `alpha`, or 0 for 0.
    pub(crate) fn logarithm(element: u8) -> usize {
        usize::from(logarithms[usize::from(element)])
    }

    /// The product of two elements, `gf_mul`: the carry-less product of the bytes, then the
    /// reduction by the field polynomial.
    pub(crate) fn product(left: u8, right: u8) -> u8 {
        let mut wide = 0u16;
        for bit in 0..8 {
            // All ones when the bit of the right factor is set, with no branch on the value.
            let mask = 0u16.wrapping_sub(u16::from((right >> bit) & 1));
            wide ^= (u16::from(left) << bit) & mask;
        }
        Self::reduced(wide)
    }

    /// A carry-less product of degree at most 14 modulo the field polynomial, `gf_reduce`.
    fn reduced(wide: u16) -> u8 {
        let mut value = wide;
        // `x^8` is `x^4 + x^3 + x^2 + 1` modulo the field polynomial. The first step brings the
        // degree to at most 10, and the second below 8.
        for _ in 0..2 {
            let high = value >> 8;
            value = (value & 0xFF) ^ high ^ (high << 2) ^ (high << 3) ^ (high << 4);
        }
        value as u8
    }

    /// The square of an element, `gf_square`.
    pub(crate) fn square(element: u8) -> u8 {
        Self::product(element, element)
    }

    /// The inverse `a^254` of an element, or 0 for 0, with the addition chain of `gf_inverse`:
    /// 1, 2, 3, 4, 7, 11, 15, 30, 60, 120, 127 and 254.
    pub(crate) fn inverse(element: u8) -> u8 {
        let second = Self::square(element);
        let third = Self::product(second, element);
        let fourth = Self::square(second);
        let seventh = Self::product(fourth, third);
        let eleventh = Self::product(fourth, seventh);
        let fifteenth = Self::product(eleventh, fourth);
        let thirtieth = Self::square(fifteenth);
        let sixtieth = Self::square(thirtieth);
        let hundredTwentieth = Self::square(sixtieth);
        let hundredTwentySeventh = Self::product(hundredTwentieth, seventh);
        Self::square(hundredTwentySeventh)
    }
}

#[cfg(test)]
mod tests {
    use super::{GaloisField, logarithms, powers};

    /// The product by the definition: the carry-less product, then the remainder of the
    /// division by the field polynomial, bit by bit.
    fn productByDivision(left: u8, right: u8) -> u8 {
        let mut wide = 0u32;
        for bit in 0..8 {
            if (right >> bit) & 1 == 1 {
                wide ^= u32::from(left) << bit;
            }
        }
        for degree in (8..16).rev() {
            if (wide >> degree) & 1 == 1 {
                wide ^= 0x11D << (degree - 8);
            }
        }
        wide as u8
    }

    #[test]
    fn tablesHoldTheValuesOfTheGaloisFieldHeader() {
        // The first entries of `gf_exp` and `gf_log` of `gf.h`, and the last power.
        assert_eq!(
            &powers[..16],
            &[
                1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38
            ]
        );
        assert_eq!(&powers[250..], &[108, 216, 173, 71, 142]);
        assert_eq!(
            &logarithms[..16],
            &[
                0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75
            ]
        );
        assert_eq!(&logarithms[252..], &[168, 80, 88, 175]);
        for element in 1..=255u8 {
            assert_eq!(GaloisField::power(GaloisField::logarithm(element)), element);
        }
        assert_eq!(GaloisField::logarithm(0), 0);
        assert_eq!(GaloisField::power(255), 1);
        assert_eq!(GaloisField::power(255 + 7), 128);
    }

    #[test]
    fn productIsTheProductModuloTheFieldPolynomialForEveryPair() {
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                assert_eq!(
                    GaloisField::product(left, right),
                    productByDivision(left, right),
                    "{left} * {right}"
                );
            }
        }
        // `alpha^8 = alpha^4 + alpha^3 + alpha^2 + 1`.
        assert_eq!(GaloisField::product(128, 2), 29);
    }

    #[test]
    fn inverseGivesOneInTheProductAndZeroForZero() {
        assert_eq!(GaloisField::inverse(0), 0);
        for element in 1..=255u8 {
            let inverse = GaloisField::inverse(element);
            assert_eq!(GaloisField::product(element, inverse), 1, "{element}");
            assert_eq!(
                GaloisField::square(element),
                productByDivision(element, element)
            );
        }
        assert_eq!(GaloisField::inverse(2), 142);
    }
}
