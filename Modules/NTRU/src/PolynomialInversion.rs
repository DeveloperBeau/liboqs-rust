use crate::PolynomialRing;
use alloc::vec;
use alloc::vec::Vec;

/// The inverses of NTRU polynomials modulo `Phi_n`: modulo 2 and modulo 3 by the constant-time
/// algorithm of Bernstein and Yang, `poly_r2_inv.c` and `poly_s3_inv.c` from `invhrss701` of
/// SUPERCOP, and modulo `q` by four Newton steps from the inverse modulo 2, `poly_Rq_inv`.
///
/// Each loop runs `2 (n - 1) - 1` times for every input, and each choice is a mask, so the
/// time does not depend on the polynomial. A polynomial that has no inverse gives the value
/// that the C code gives.
pub(crate) struct PolynomialInversion;

impl PolynomialInversion {
    /// -1 when both values are negative, and else 0, `both_negative_mask`.
    fn bothNegativeMask(left: i16, right: i16) -> i16 {
        (left & right) >> 15
    }

    /// The residue modulo 3 of a value from 0 to 9, `mod3` of `poly_s3_inv.c`.
    fn smallResidueModuloThree(value: u8) -> u8 {
        let reduced = (value >> 2) + (value & 3);
        let difference = i16::from(reduced) - 3;
        let mask = difference >> 5;
        (difference ^ (mask & (i16::from(reduced) ^ difference))) as u8
    }

    /// The inverse modulo 2 and `Phi_n`, `poly_R2_inv`. Only the low bit of each
    /// coefficient counts.
    pub(crate) fn inverseModuloTwo(polynomial: &[u16]) -> Vec<u16> {
        let count = polynomial.len();
        let last = polynomial[count - 1];
        let mut v = vec![0u16; count];
        let mut w = vec![0u16; count];
        w[0] = 1;
        let mut f = vec![1u16; count];
        let mut g = vec![0u16; count];
        for index in 0..count - 1 {
            g[count - 2 - index] = (polynomial[index] ^ last) & 1;
        }
        let mut delta: i16 = 1;
        for _ in 0..2 * (count - 1) - 1 {
            v.copy_within(0..count - 1, 1);
            v[0] = 0;
            let sign = (g[0] & f[0]) as i16;
            let swap = Self::bothNegativeMask(-delta, -(g[0] as i16));
            delta ^= swap & (delta ^ -delta);
            delta += 1;
            for index in 0..count {
                let t = (swap as u16) & (f[index] ^ g[index]);
                f[index] ^= t;
                g[index] ^= t;
                let t = (swap as u16) & (v[index] ^ w[index]);
                v[index] ^= t;
                w[index] ^= t;
            }
            for index in 0..count {
                g[index] ^= (sign as u16) & f[index];
            }
            for index in 0..count {
                w[index] ^= (sign as u16) & v[index];
            }
            g.copy_within(1..count, 0);
            g[count - 1] = 0;
        }
        let mut inverse = vec![0u16; count];
        for index in 0..count - 1 {
            inverse[index] = v[count - 2 - index];
        }
        inverse
    }

    /// The inverse modulo 3 and `Phi_n`, `poly_S3_inv`. The coefficients are read modulo 4,
    /// and must be 0, 1 or 2.
    pub(crate) fn inverseModuloThree(polynomial: &[u16]) -> Vec<u16> {
        let count = polynomial.len();
        let last = polynomial[count - 1];
        let mut v = vec![0u16; count];
        let mut w = vec![0u16; count];
        w[0] = 1;
        let mut f = vec![1u16; count];
        let mut g = vec![0u16; count];
        for index in 0..count - 1 {
            let sum = (polynomial[index] & 3) + 2 * (last & 3);
            g[count - 2 - index] = u16::from(Self::smallResidueModuloThree(sum as u8));
        }
        let mut delta: i16 = 1;
        for _ in 0..2 * (count - 1) - 1 {
            v.copy_within(0..count - 1, 1);
            v[0] = 0;
            let sign = i16::from(Self::smallResidueModuloThree((2 * g[0] * f[0]) as u8));
            let swap = Self::bothNegativeMask(-delta, -(g[0] as i16));
            delta ^= swap & (delta ^ -delta);
            delta += 1;
            for index in 0..count {
                let t = (swap as u16) & (f[index] ^ g[index]);
                f[index] ^= t;
                g[index] ^= t;
                let t = (swap as u16) & (v[index] ^ w[index]);
                v[index] ^= t;
                w[index] ^= t;
            }
            for index in 0..count {
                let sum = g[index] as i16 + sign * f[index] as i16;
                g[index] = u16::from(Self::smallResidueModuloThree(sum as u8));
            }
            for index in 0..count {
                let sum = w[index] as i16 + sign * v[index] as i16;
                w[index] = u16::from(Self::smallResidueModuloThree(sum as u8));
            }
            g.copy_within(1..count, 0);
            g[count - 1] = 0;
        }
        let sign = f[0] as i16;
        let mut inverse = vec![0u16; count];
        for index in 0..count - 1 {
            let product = sign * v[count - 2 - index] as i16;
            inverse[index] = u16::from(Self::smallResidueModuloThree(product as u8));
        }
        inverse
    }

    /// The inverse modulo `q` and `Phi_n`, `poly_Rq_inv`: the inverse modulo 2 and then four
    /// Newton steps `ai = ai (2 - a ai)`, each of which doubles the bits of the inverse,
    /// `poly_R2_inv_to_Rq_inv`.
    pub(crate) fn inverseModuloModulus(ring: &PolynomialRing, polynomial: &[u16]) -> Vec<u16> {
        let mut inverse = Self::inverseModuloTwo(polynomial);
        let negated: Vec<u16> = polynomial
            .iter()
            .map(|coefficient| coefficient.wrapping_neg())
            .collect();
        for _ in 0..2 {
            let mut step = ring.product(&inverse, &negated);
            step[0] = step[0].wrapping_add(2);
            let next = ring.product(&step, &inverse);
            let mut step = ring.product(&next, &negated);
            step[0] = step[0].wrapping_add(2);
            inverse = ring.product(&step, &next);
        }
        inverse
    }
}

#[cfg(test)]
mod tests {
    use super::PolynomialInversion;
    use crate::PolynomialRing;
    use crate::parameters::{ntruHPS2048509, ntruHRSS701, ntruHRSS1373};
    use crate::testInputs::{cAnswer, everySet, sequence, ternarySequence, valuesDigest};

    #[test]
    fn smallResidueModuloThreeIsTheRemainderFromZeroToNine() {
        for value in 0..=9u8 {
            assert_eq!(
                PolynomialInversion::smallResidueModuloThree(value),
                value % 3
            );
        }
    }

    #[test]
    fn bothNegativeMaskIsSetOnlyWhenBothValuesAreNegative() {
        assert_eq!(PolynomialInversion::bothNegativeMask(-1, -5), -1);
        assert_eq!(PolynomialInversion::bothNegativeMask(-1, 0), 0);
        assert_eq!(PolynomialInversion::bothNegativeMask(3, -2), 0);
        assert_eq!(PolynomialInversion::bothNegativeMask(i16::MIN, -1), -1);
    }

    /// The coefficients of a product modulo `Phi_n`, as values modulo a power of two or 3.
    fn productModuloPhi(left: &[u16], right: &[u16], modulus: u32) -> Vec<u32> {
        let count = left.len();
        let mut cyclic = vec![0u64; count];
        for (leftIndex, leftValue) in left.iter().enumerate() {
            for (rightIndex, rightValue) in right.iter().enumerate() {
                cyclic[(leftIndex + rightIndex) % count] +=
                    u64::from(*leftValue) * u64::from(*rightValue);
            }
        }
        // x^(n - 1) = -(1 + x + ... + x^(n - 2)) modulo Phi_n.
        let last = cyclic[count - 1];
        let modulus = u64::from(modulus);
        cyclic
            .iter()
            .map(|value| ((value % modulus + modulus - last % modulus) % modulus) as u32)
            .collect()
    }

    fn isOne(coefficients: &[u32]) -> bool {
        coefficients[0] == 1 && coefficients[1..].iter().all(|value| *value == 0)
    }

    #[test]
    fn eachInverseTimesItsPolynomialIsOne() {
        // 2 and 3 have the order n - 1 modulo n for each set, so Phi_n is irreducible modulo 2
        // and 3, and every polynomial that is not 0 modulo Phi_n has both inverses.
        for parameters in [&ntruHPS2048509, &ntruHRSS701, &ntruHRSS1373] {
            let name = parameters.description.name;
            let count = parameters.coefficientCount;
            let ring = PolynomialRing::new(parameters);
            for seed in 0..3 {
                let values = sequence(count, 31 + seed);
                let ternary: Vec<u16> = values.iter().map(|value| value % 3).collect();
                let inverse = PolynomialInversion::inverseModuloThree(&ternary);
                assert!(
                    isOne(&productModuloPhi(&ternary, &inverse, 3)),
                    "{name}, seed {seed}, modulo 3"
                );
                let binary: Vec<u16> = values.iter().map(|value| value & 1).collect();
                let inverse = PolynomialInversion::inverseModuloTwo(&values);
                assert!(
                    isOne(&productModuloPhi(&binary, &inverse, 2)),
                    "{name}, seed {seed}, modulo 2"
                );
                let inverse = PolynomialInversion::inverseModuloModulus(&ring, &values);
                let modulus = u32::from(parameters.modulus());
                assert!(
                    isOne(&productModuloPhi(&values, &inverse, modulus)),
                    "{name}, seed {seed}, modulo q"
                );
            }
        }
    }

    #[test]
    fn aPolynomialWithoutAnInverseGivesNoInverse() {
        // Phi_n itself, all ones, is 0 modulo Phi_n.
        let count = ntruHRSS701.coefficientCount;
        let ones = vec![1u16; count];
        let inverse = PolynomialInversion::inverseModuloThree(&ones);
        assert!(!isOne(&productModuloPhi(&ones, &inverse, 3)));
        let inverse = PolynomialInversion::inverseModuloTwo(&ones);
        assert!(!isOne(&productModuloPhi(&ones, &inverse, 2)));
    }

    #[test]
    fn eachInverseHasTheBitsOfTheCFunction() {
        // poly_S3_inv, poly_R2_inv and poly_Rq_inv of liboqs 0.16.0 on the same inputs.
        for parameters in everySet() {
            let count = parameters.coefficientCount;
            let name = parameters.description.name;
            let ring = PolynomialRing::new(parameters);
            let inverse = PolynomialInversion::inverseModuloThree(&ternarySequence(count, 3));
            assert_eq!(
                valuesDigest(&inverse),
                cAnswer(name, "inverseModuloThree"),
                "{name}"
            );
            let inverse = PolynomialInversion::inverseModuloTwo(&sequence(count, 4));
            assert_eq!(
                valuesDigest(&inverse),
                cAnswer(name, "inverseModuloTwo"),
                "{name}"
            );
            let inverse = PolynomialInversion::inverseModuloModulus(&ring, &sequence(count, 5));
            assert_eq!(
                valuesDigest(&inverse),
                cAnswer(name, "inverseModuloModulus"),
                "{name}"
            );
        }
    }
}
