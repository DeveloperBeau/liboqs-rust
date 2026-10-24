use crate::{ModularReduction, Parameters};
use alloc::vec;
use alloc::vec::Vec;

/// The arithmetic of the rings `R3 = Z[x] / (3, x^p - x - 1)` and
/// `Rq = Z[x] / (q, x^p - x - 1)` of Streamlined NTRU Prime, `sntrup761.c`.
///
/// A small polynomial has `i8` coefficients in `{-1, 0, 1}`, and a polynomial modulo `q` has
/// `i16` coefficients in `[-(q - 1) / 2, (q - 1) / 2]`. The products are schoolbook products,
/// and `x^p = x + 1` folds the high coefficients back. The reciprocals are the constant-time
/// algorithm of Bernstein and Yang, with `2 p - 1` steps for every input.
pub(crate) struct PolynomialRing<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> PolynomialRing<'parameters> {
    /// Makes the arithmetic of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        PolynomialRing { parameters }
    }

    fn freeze(&self, value: i32) -> i16 {
        ModularReduction::residueModuloModulus(value, self.parameters.modulus)
    }

    /// The coefficients of a polynomial modulo `q` reduced modulo 3, `R3_fromRq`.
    pub(crate) fn ternaryFromModulus(polynomial: &[i16]) -> Vec<i8> {
        polynomial
            .iter()
            .map(|coefficient| ModularReduction::residueModuloThree(*coefficient))
            .collect()
    }

    /// The product of two small polynomials in `R3`, `R3_mult`. The C code sums the products
    /// in 16 bits.
    pub(crate) fn ternaryProduct(&self, left: &[i8], right: &[i8]) -> Vec<i8> {
        let p = self.parameters.degree;
        let mut product = vec![0i16; 2 * p - 1];
        for (leftIndex, leftValue) in left.iter().enumerate() {
            for (rightIndex, rightValue) in right.iter().enumerate() {
                product[leftIndex + rightIndex] = product[leftIndex + rightIndex]
                    .wrapping_add(i16::from(*leftValue) * i16::from(*rightValue));
            }
        }
        Self::foldHighCoefficients16(&mut product, p);
        product[..p]
            .iter()
            .map(|coefficient| ModularReduction::residueModuloThree(*coefficient))
            .collect()
    }

    /// The product of a polynomial modulo `q` and a small polynomial in `Rq`,
    /// `Rq_mult_small`. The C code sums the products in 32 bits.
    pub(crate) fn productWithSmall(&self, polynomial: &[i16], small: &[i8]) -> Vec<i16> {
        let p = self.parameters.degree;
        let mut product = vec![0i32; 2 * p - 1];
        for (leftIndex, leftValue) in polynomial.iter().enumerate() {
            let leftValue = i32::from(*leftValue);
            for (rightIndex, rightValue) in small.iter().enumerate() {
                product[leftIndex + rightIndex] += leftValue * i32::from(*rightValue);
            }
        }
        for index in p..2 * p - 1 {
            product[index - p] += product[index];
        }
        for index in p..2 * p - 1 {
            product[index - p + 1] += product[index];
        }
        product[..p]
            .iter()
            .map(|coefficient| self.freeze(*coefficient))
            .collect()
    }

    /// `x^p = x + 1`: each coefficient from `p` up adds to the coefficients `p` and `p - 1`
    /// places lower, in 16 bits.
    fn foldHighCoefficients16(product: &mut [i16], p: usize) {
        for index in p..2 * p - 1 {
            product[index - p] = product[index - p].wrapping_add(product[index]);
        }
        for index in p..2 * p - 1 {
            product[index - p + 1] = product[index - p + 1].wrapping_add(product[index]);
        }
    }

    /// Three times a polynomial modulo `q`, `Rq_mult3`.
    pub(crate) fn tripled(&self, polynomial: &[i16]) -> Vec<i16> {
        polynomial
            .iter()
            .map(|coefficient| self.freeze(3 * i32::from(*coefficient)))
            .collect()
    }

    /// Each coefficient rounded to the nearest multiple of 3, `Round`.
    pub(crate) fn rounded(polynomial: &[i16]) -> Vec<i16> {
        polynomial
            .iter()
            .map(|coefficient| {
                coefficient - i16::from(ModularReduction::residueModuloThree(*coefficient))
            })
            .collect()
    }

    /// The reciprocal of a small polynomial in `R3`, and the mask 0 when it exists or -1 when
    /// it does not, `R3_recip`.
    pub(crate) fn ternaryReciprocal(&self, small: &[i8]) -> (Vec<i8>, i16) {
        let p = self.parameters.degree;
        let mut f = vec![0i8; p + 1];
        let mut g = vec![0i8; p + 1];
        let mut v = vec![0i8; p + 1];
        let mut r = vec![0i8; p + 1];
        r[0] = 1;
        // f = x^p - x - 1, in reversed order.
        f[0] = 1;
        f[p - 1] = -1;
        f[p] = -1;
        for (index, coefficient) in small.iter().enumerate() {
            g[p - 1 - index] = *coefficient;
        }
        let mut delta: i32 = 1;
        for _ in 0..2 * p - 1 {
            v.copy_within(0..p, 1);
            v[0] = 0;
            let sign = -i32::from(g[0]) * i32::from(f[0]);
            let swap = i32::from(
                ModularReduction::negativeMask(-delta as i16)
                    & ModularReduction::nonzeroMask(i16::from(g[0])),
            );
            delta ^= swap & (delta ^ -delta);
            delta += 1;
            let swapMask = swap as i8;
            for index in 0..p + 1 {
                let t = swapMask & (f[index] ^ g[index]);
                f[index] ^= t;
                g[index] ^= t;
                let t = swapMask & (v[index] ^ r[index]);
                v[index] ^= t;
                r[index] ^= t;
            }
            for index in 0..p + 1 {
                let sum = i32::from(g[index]) + sign * i32::from(f[index]);
                g[index] = ModularReduction::residueModuloThree(sum as i16);
            }
            for index in 0..p + 1 {
                let sum = i32::from(r[index]) + sign * i32::from(v[index]);
                r[index] = ModularReduction::residueModuloThree(sum as i16);
            }
            g.copy_within(1..p + 1, 0);
            g[p] = 0;
        }
        let sign = i32::from(f[0]);
        let reciprocal = (0..p)
            .map(|index| (sign * i32::from(v[p - 1 - index])) as i8)
            .collect();
        (reciprocal, ModularReduction::nonzeroMask(delta as i16))
    }

    /// The reciprocal of 3 times a small polynomial in `Rq`, and the mask 0 when it exists or
    /// -1 when it does not, `Rq_recip3`.
    pub(crate) fn reciprocalOfTriple(&self, small: &[i8]) -> (Vec<i16>, i16) {
        let parameters = self.parameters;
        let p = parameters.degree;
        let mut f = vec![0i16; p + 1];
        let mut g = vec![0i16; p + 1];
        let mut v = vec![0i16; p + 1];
        let mut r = vec![0i16; p + 1];
        r[0] = ModularReduction::reciprocalModuloModulus(3, parameters.modulus);
        f[0] = 1;
        f[p - 1] = -1;
        f[p] = -1;
        for (index, coefficient) in small.iter().enumerate() {
            g[p - 1 - index] = i16::from(*coefficient);
        }
        let mut delta: i32 = 1;
        for _ in 0..2 * p - 1 {
            v.copy_within(0..p, 1);
            v[0] = 0;
            let swap = i32::from(
                ModularReduction::negativeMask(-delta as i16) & ModularReduction::nonzeroMask(g[0]),
            );
            delta ^= swap & (delta ^ -delta);
            delta += 1;
            let swapMask = swap as i16;
            for index in 0..p + 1 {
                let t = swapMask & (f[index] ^ g[index]);
                f[index] ^= t;
                g[index] ^= t;
                let t = swapMask & (v[index] ^ r[index]);
                v[index] ^= t;
                r[index] ^= t;
            }
            let f0 = i32::from(f[0]);
            let g0 = i32::from(g[0]);
            for index in 0..p + 1 {
                g[index] = self.freeze(f0 * i32::from(g[index]) - g0 * i32::from(f[index]));
            }
            for index in 0..p + 1 {
                r[index] = self.freeze(f0 * i32::from(r[index]) - g0 * i32::from(v[index]));
            }
            g.copy_within(1..p + 1, 0);
            g[p] = 0;
        }
        let scale = i32::from(ModularReduction::reciprocalModuloModulus(
            f[0],
            parameters.modulus,
        ));
        let reciprocal = (0..p)
            .map(|index| self.freeze(scale * i32::from(v[p - 1 - index])))
            .collect();
        (reciprocal, ModularReduction::nonzeroMask(delta as i16))
    }
}

#[cfg(test)]
mod tests {
    use super::PolynomialRing;
    use crate::Sampler;
    use crate::parameters::sntrup761;
    use crate::testInputs::{
        cAnswer, modulusBytes, modulusSequence, sequence, smallBytes, smallSequence, wordSequence,
    };
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The product of two polynomials modulo `x^p - x - 1` with integer coefficients.
    fn product(left: &[i64], right: &[i64]) -> Vec<i64> {
        let p = left.len();
        let mut wide = vec![0i64; 2 * p - 1];
        for (leftIndex, leftValue) in left.iter().enumerate() {
            for (rightIndex, rightValue) in right.iter().enumerate() {
                wide[leftIndex + rightIndex] += leftValue * rightValue;
            }
        }
        // x^k for k from 2p - 2 down to p is x^(k - p + 1) + x^(k - p).
        for index in (p..2 * p - 1).rev() {
            let value = wide[index];
            wide[index - p + 1] += value;
            wide[index - p] += value;
        }
        wide.truncate(p);
        wide
    }

    fn centered(value: i64, modulus: i64) -> i64 {
        let residue = value.rem_euclid(modulus);
        if residue > modulus / 2 {
            residue - modulus
        } else {
            residue
        }
    }

    fn small(seed: u32) -> Vec<i8> {
        sequence(761, seed)
            .iter()
            .map(|value| (value % 3) as i8 - 1)
            .collect()
    }

    #[test]
    fn productsAreTheProductsModuloXToThePMinusXMinusOne() {
        let ring = PolynomialRing::new(&sntrup761);
        let left = small(1);
        let right = small(2);
        let wide =
            |values: &[i8]| -> Vec<i64> { values.iter().map(|value| i64::from(*value)).collect() };
        let expected: Vec<i8> = product(&wide(&left), &wide(&right))
            .iter()
            .map(|value| centered(*value, 3) as i8)
            .collect();
        assert_eq!(ring.ternaryProduct(&left, &right), expected);
        let modular: Vec<i16> = sequence(761, 3)
            .iter()
            .map(|value| (i32::from(*value) % 4591 - 2295) as i16)
            .collect();
        let expected: Vec<i16> = product(
            &modular
                .iter()
                .map(|value| i64::from(*value))
                .collect::<Vec<_>>(),
            &wide(&left),
        )
        .iter()
        .map(|value| centered(*value, 4591) as i16)
        .collect();
        assert_eq!(ring.productWithSmall(&modular, &left), expected);
        // The fold of x^p: x^(p - 1) times x is x + 1.
        let mut last = vec![0i8; 761];
        last[760] = 1;
        let mut x = vec![0i8; 761];
        x[1] = 1;
        let mut expected = vec![0i8; 761];
        expected[0] = 1;
        expected[1] = 1;
        assert_eq!(ring.ternaryProduct(&last, &x), expected);
    }

    #[test]
    fn reciprocalsTimesTheirPolynomialsAreOneAndOneThird() {
        let ring = PolynomialRing::new(&sntrup761);
        for seed in 0..3 {
            let g = small(10 + seed);
            let (inverse, mask) = ring.ternaryReciprocal(&g);
            assert_eq!(mask, 0, "seed {seed}");
            let mut one = vec![0i8; 761];
            one[0] = 1;
            assert_eq!(ring.ternaryProduct(&g, &inverse), one, "seed {seed}");
            let (inverse, mask) = ring.reciprocalOfTriple(&g);
            assert_eq!(mask, 0, "seed {seed}");
            // 3 g times (3 g)^-1 is 1, so g times it is 1/3, which is -1530.
            let product = ring.productWithSmall(&inverse, &g);
            assert_eq!(product[0], -1530, "seed {seed}");
            assert!(product[1..].iter().all(|value| *value == 0), "seed {seed}");
        }
    }

    #[test]
    fn theZeroPolynomialHasNoReciprocal() {
        let ring = PolynomialRing::new(&sntrup761);
        let zero = vec![0i8; 761];
        assert_eq!(ring.ternaryReciprocal(&zero).1, -1);
        assert_eq!(ring.reciprocalOfTriple(&zero).1, -1);
    }

    #[test]
    fn roundingGivesTheNearestMultipleOfThree() {
        let values: Vec<i16> = (-2295..=2295).collect();
        for (value, rounded) in values.iter().zip(PolynomialRing::rounded(&values)) {
            assert_eq!(rounded % 3, 0);
            assert!((value - rounded).abs() <= 1, "{value}");
        }
        // 3000 is -1591 centered modulo 4591, and -6885 is 2297, which is -2294 centered.
        let ring = PolynomialRing::new(&sntrup761);
        assert_eq!(ring.tripled(&[1000, -2295, 0]), vec![-1591, -2294, 0]);
    }

    #[test]
    fn eachOperationHasTheBytesOfTheCFunctions() {
        // R3_recip, Rq_recip3, Rq_mult_small and R3_mult of liboqs 0.16.0 on the same inputs.
        let ring = PolynomialRing::new(&sntrup761);
        let (inverse, mask) = ring.ternaryReciprocal(&smallSequence(1));
        assert_eq!(
            OutputDigest::of(&smallBytes(&inverse)),
            cAnswer("ternaryReciprocal")
        );
        assert_eq!(mask.to_string(), cAnswer("ternaryReciprocalMask"));
        let short = Sampler::new(&sntrup761).shortFromWords(&wordSequence(2));
        let (inverse, mask) = ring.reciprocalOfTriple(&short);
        assert_eq!(
            OutputDigest::of(&modulusBytes(&inverse)),
            cAnswer("reciprocalOfTriple")
        );
        assert_eq!(mask.to_string(), cAnswer("reciprocalOfTripleMask"));
        let product = ring.productWithSmall(&modulusSequence(3), &smallSequence(4));
        assert_eq!(
            OutputDigest::of(&modulusBytes(&product)),
            cAnswer("productWithSmall")
        );
        let product = ring.ternaryProduct(&smallSequence(5), &smallSequence(6));
        assert_eq!(
            OutputDigest::of(&smallBytes(&product)),
            cAnswer("ternaryProduct")
        );
    }
}
