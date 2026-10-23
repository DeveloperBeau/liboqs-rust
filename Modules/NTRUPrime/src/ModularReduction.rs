/// The reductions of `sntrup761.c` to the centered residues modulo 3 and modulo `q`, and the
/// masks of the cryptoint helpers that the code uses.
///
/// Each function computes with the integer types of the C code: a coefficient modulo 3 is an
/// `i8`, a coefficient modulo `q` an `i16`, and the sums of the products are 32-bit values.
pub(crate) struct ModularReduction;

impl ModularReduction {
    /// The residue of a value modulo 3 in `{-1, 0, 1}`, `F3_freeze`: the value minus 3 times
    /// its nearest multiple of 3, by a multiplication with `10923 / 2^15`.
    pub(crate) fn residueModuloThree(value: i16) -> i8 {
        let value = i32::from(value);
        (value - 3 * ((10923 * value + 16384) >> 15)) as i8
    }

    /// The centered residue of a value modulo `q`, `Fq_freeze`: three steps that subtract the
    /// estimates of the quotient by `2^16 / q`, `2^20 / q` and `2^28 / q`.
    pub(crate) fn residueModuloModulus(value: i32, modulus: i16) -> i16 {
        let q = i32::from(modulus);
        let q16 = (0x10000 + q / 2) / q;
        let q20 = (0x10_0000 + q / 2) / q;
        let q28 = (0x1000_0000 + q / 2) / q;
        let mut value = value;
        value -= q * ((q16 * value) >> 16);
        value -= q * ((q20 * value) >> 20);
        (value - q * ((q28 * value + 0x800_0000) >> 28)) as i16
    }

    /// The inverse of a value modulo `q`, `a^(q - 2)`, by `q - 3` products, `Fq_recip`. The
    /// value 0 gives 0.
    pub(crate) fn reciprocalModuloModulus(value: i16, modulus: i16) -> i16 {
        let mut power = value;
        for _ in 1..modulus - 2 {
            power = Self::residueModuloModulus(i32::from(value) * i32::from(power), modulus);
        }
        power
    }

    /// -1 for a negative value and else 0, `crypto_int16_negative_mask`.
    pub(crate) fn negativeMask(value: i16) -> i16 {
        value >> 15
    }

    /// -1 for a value that is not zero and else 0, `crypto_int16_nonzero_mask`.
    pub(crate) fn nonzeroMask(value: i16) -> i16 {
        Self::negativeMask(value | value.wrapping_neg())
    }
}

#[cfg(test)]
mod tests {
    use super::ModularReduction;

    /// The centered residue of the definition.
    fn centered(value: i64, modulus: i64) -> i64 {
        let residue = value.rem_euclid(modulus);
        if residue > modulus / 2 {
            residue - modulus
        } else {
            residue
        }
    }

    #[test]
    fn residueModuloThreeIsCenteredForTheValuesOfTheCode() {
        // The products of R3_mult and the coefficients of Round stay within 4566 in absolute
        // value. Beyond 16383 the estimate of the quotient is one off, as in the C code.
        for value in -16383..=16383i16 {
            assert_eq!(
                i64::from(ModularReduction::residueModuloThree(value)),
                centered(i64::from(value), 3),
                "{value}"
            );
        }
        assert_eq!(ModularReduction::residueModuloThree(32767), -2);
    }

    #[test]
    fn residueModuloModulusIsCenteredOverTheRangeOfTheProducts() {
        // The products of Rq_mult_small reach 3 * 761 * 2295 * 2 in absolute value.
        let bound = 3 * 761 * 2295 * 2;
        for value in (-bound..=bound)
            .step_by(997)
            .chain([-bound, bound, 0, 2295, 2296, -2296])
        {
            assert_eq!(
                i64::from(ModularReduction::residueModuloModulus(value, 4591)),
                centered(i64::from(value), 4591),
                "{value}"
            );
        }
        for value in -20_000..20_000 {
            assert_eq!(
                i64::from(ModularReduction::residueModuloModulus(value, 4591)),
                centered(i64::from(value), 4591),
                "{value}"
            );
        }
    }

    #[test]
    fn reciprocalModuloModulusIsTheInverse() {
        for value in [1i16, 3, -1, 2, 1000, -1000, -2295, 2295] {
            let inverse = ModularReduction::reciprocalModuloModulus(value, 4591);
            assert_eq!(
                centered(i64::from(value) * i64::from(inverse), 4591),
                1,
                "{value}"
            );
        }
        // 3 * 3061 = 2 * 4591 + 1, and 3061 is -1530 centered.
        assert_eq!(ModularReduction::reciprocalModuloModulus(3, 4591), -1530);
        assert_eq!(ModularReduction::reciprocalModuloModulus(0, 4591), 0);
    }

    #[test]
    fn masksAreAllOnesOrZero() {
        assert_eq!(ModularReduction::negativeMask(-1), -1);
        assert_eq!(ModularReduction::negativeMask(i16::MIN), -1);
        assert_eq!(ModularReduction::negativeMask(0), 0);
        assert_eq!(ModularReduction::negativeMask(i16::MAX), 0);
        assert_eq!(ModularReduction::nonzeroMask(0), 0);
        for value in [1i16, -1, 2, i16::MIN, i16::MAX, 0x100] {
            assert_eq!(ModularReduction::nonzeroMask(value), -1, "{value}");
        }
    }
}
