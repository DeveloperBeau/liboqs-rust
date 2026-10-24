/// The arithmetic modulo one small prime `p` with `2^30 < p < 2^31`, the `modp_*` functions of
/// `keygen.c` of the Falcon code of PQClean.
///
/// Values lie in `0..p`. The products use the Montgomery representation with `R = 2^31`, and
/// the number-theoretic transform works on polynomials modulo `X^N + 1` whose coefficients sit
/// at a fixed stride in a larger array, as the residues of big integers do.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PrimeModulus {
    /// The prime `p`.
    pub(crate) p: u32,
    /// `-1/p mod 2^31`.
    pub(crate) p0i: u32,
    /// `R^2 = 2^62 mod p`.
    pub(crate) r2: u32,
}

/// The reversal of the 10 low bits of each index, as `REV10` of `keygen.c` holds it.
const reversed10: [u16; 1024] = reversals();

const fn reversals() -> [u16; 1024] {
    let mut table = [0u16; 1024];
    let mut index = 0;
    while index < 1024 {
        let mut reversed = 0;
        let mut bit = 0;
        while bit < 10 {
            reversed = (reversed << 1) + ((index >> bit) & 1);
            bit += 1;
        }
        table[index] = reversed as u16;
        index += 1;
    }
    table
}

impl PrimeModulus {
    /// The arithmetic modulo a prime, with its Montgomery constants.
    pub(crate) fn new(p: u32) -> Self {
        let p0i = Self::negativeInverse(p);
        let mut modulus = PrimeModulus { p, p0i, r2: 0 };
        modulus.r2 = modulus.montgomerySquare();
        modulus
    }

    /// `-1/p mod 2^31` for an odd `p` below 2^31, as `modp_ninv31` does.
    pub(crate) fn negativeInverse(p: u32) -> u32 {
        let mut y = 2u32.wrapping_sub(p);
        for _ in 0..4 {
            y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
        }
        0x7FFF_FFFF & y.wrapping_neg()
    }

    /// `R = 2^31 mod p`, which is `2^31 - p`, as `modp_R` does.
    pub(crate) fn r(&self) -> u32 {
        (1u32 << 31) - self.p
    }

    /// `R^2 = 2^62 mod p`, as `modp_R2` does.
    fn montgomerySquare(&self) -> u32 {
        // 2^32 in Montgomery representation, squared five times to 2^63, then halved.
        let mut z = self.sum(self.r(), self.r());
        for _ in 0..5 {
            z = self.product(z, z);
        }
        z.wrapping_add(self.p & (z & 1).wrapping_neg()) >> 1
    }

    /// A signed value with `-p < x < p`, reduced to `0..p`, as `modp_set` does.
    pub(crate) fn reduced(&self, value: i32) -> u32 {
        let value = value as u32;
        value.wrapping_add(self.p & (value >> 31).wrapping_neg())
    }

    /// A value in `0..p` normalized around zero, into `-(p - 1)/2..=(p - 1)/2`, as `modp_norm`
    /// does.
    pub(crate) fn normalized(&self, value: u32) -> i32 {
        let isAboveHalf = (value.wrapping_sub((self.p + 1) >> 1) >> 31).wrapping_sub(1);
        value.wrapping_sub(self.p & isAboveHalf) as i32
    }

    /// The sum modulo `p`, as `modp_add` does.
    pub(crate) fn sum(&self, left: u32, right: u32) -> u32 {
        let value = left.wrapping_add(right).wrapping_sub(self.p);
        value.wrapping_add(self.p & (value >> 31).wrapping_neg())
    }

    /// The difference modulo `p`, as `modp_sub` does.
    pub(crate) fn difference(&self, left: u32, right: u32) -> u32 {
        let value = left.wrapping_sub(right);
        value.wrapping_add(self.p & (value >> 31).wrapping_neg())
    }

    /// The Montgomery product `a b / R mod p`, as `modp_montymul` does.
    pub(crate) fn product(&self, left: u32, right: u32) -> u32 {
        let z = u64::from(left) * u64::from(right);
        let w = (z.wrapping_mul(u64::from(self.p0i)) & 0x7FFF_FFFF) * u64::from(self.p);
        let value = (((z + w) >> 31) as u32).wrapping_sub(self.p);
        value.wrapping_add(self.p & (value >> 31).wrapping_neg())
    }

    /// `2^(31 x) mod p` for `1 <= x < 2^11`, as `modp_Rx` does.
    pub(crate) fn powerOfR(&self, x: u32) -> u32 {
        // The Montgomery representation of (2^31)^(x - 1), and R2 is 2^31 in that
        // representation.
        let exponent = x - 1;
        let mut base = self.r2;
        let mut result = self.r();
        let mut bit = 0;
        while (1u32 << bit) <= exponent {
            if exponent & (1 << bit) != 0 {
                result = self.product(result, base);
            }
            base = self.product(base, base);
            bit += 1;
        }
        result
    }

    /// The quotient `a / b mod p`, or zero for a zero divisor, as `modp_div` does.
    pub(crate) fn quotient(&self, dividend: u32, divisor: u32) -> u32 {
        // b^(p - 2) with b taken as Montgomery representation gives R^2 / b, and two products
        // remove the extra factors.
        let exponent = self.p - 2;
        let mut z = self.r();
        for bit in (0..=30).rev() {
            z = self.product(z, z);
            let multiplied = self.product(z, divisor);
            z ^= (z ^ multiplied) & ((exponent >> bit) & 1).wrapping_neg();
        }
        z = self.product(z, 1);
        self.product(dividend, z)
    }

    /// The roots of the transform and of its inverse for degree `2^logn`, from a primitive
    /// 2048th root of unity, in Montgomery representation, as `modp_mkgm2` does:
    /// `roots[rev(i)] = g^i` and `inverseRoots[rev(i)] = g^-i`. Each slice receives `2^logn`
    /// values.
    pub(crate) fn fillRoots(
        &self,
        roots: &mut [u32],
        inverseRoots: &mut [u32],
        generator: u32,
        logn: u32,
    ) {
        let n = 1usize << logn;
        // The root of order 2N, from the root of order 2048.
        let mut g = self.product(generator, self.r2);
        for _ in logn..10 {
            g = self.product(g, g);
        }
        let inverse = self.quotient(self.r2, g);
        let shift = 10 - logn;
        let mut power = self.r();
        let mut inversePower = self.r();
        for index in 0..n {
            let position = usize::from(reversed10[index << shift]);
            roots[position] = power;
            inverseRoots[position] = inversePower;
            power = self.product(power, g);
            inversePower = self.product(inversePower, inverse);
        }
    }

    /// The transform in place of the polynomial whose coefficients are `values[k stride]` for
    /// `k < 2^logn`, as `modp_NTT2_ext` does.
    pub(crate) fn transform(&self, values: &mut [u32], stride: usize, roots: &[u32], logn: u32) {
        if logn == 0 {
            return;
        }
        let n = 1usize << logn;
        let mut t = n;
        let mut m = 1;
        while m < n {
            let ht = t >> 1;
            for u in 0..m {
                let root = roots[m + u];
                let first = u * t * stride;
                for v in 0..ht {
                    let low = first + v * stride;
                    let high = low + ht * stride;
                    let x = values[low];
                    let y = self.product(values[high], root);
                    values[low] = self.sum(x, y);
                    values[high] = self.difference(x, y);
                }
            }
            t = ht;
            m <<= 1;
        }
    }

    /// The inverse transform in place, with the division by `2^logn`, as `modp_iNTT2_ext` does.
    pub(crate) fn inverseTransform(
        &self,
        values: &mut [u32],
        stride: usize,
        inverseRoots: &[u32],
        logn: u32,
    ) {
        if logn == 0 {
            return;
        }
        let n = 1usize << logn;
        let mut t = 1;
        let mut m = n;
        while m > 1 {
            let hm = m >> 1;
            let dt = t << 1;
            for u in 0..hm {
                let root = inverseRoots[hm + u];
                let first = u * dt * stride;
                for v in 0..t {
                    let low = first + v * stride;
                    let high = low + t * stride;
                    let x = values[low];
                    let y = values[high];
                    values[low] = self.sum(x, y);
                    values[high] = self.product(self.difference(x, y), root);
                }
            }
            t = dt;
            m = hm;
        }
        // 1/N in Montgomery representation is R/N = 2^(31 - logn), below p.
        let scale = 1u32 << (31 - logn);
        for k in 0..n {
            values[k * stride] = self.product(values[k * stride], scale);
        }
    }

    /// Replaces the first `N/2` values of a transformed polynomial `f` with the transform of
    /// `f0^2 - X f1^2` for `f = f0(X^2) + X f1(X^2)`, as `modp_poly_rec_res` does.
    pub(crate) fn reduceResultant(&self, values: &mut [u32], logn: u32) {
        let hn = 1usize << (logn - 1);
        for u in 0..hn {
            let (w0, w1) = (values[2 * u], values[2 * u + 1]);
            values[u] = self.product(self.product(w0, w1), self.r2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PrimeModulus, reversed10};
    use crate::smallPrime::smallPrimes;

    fn modulus() -> PrimeModulus {
        PrimeModulus::new(smallPrimes[0].p)
    }

    #[test]
    fn constantsAreTheValuesOfTheirDefinition() {
        for prime in [smallPrimes[0], smallPrimes[1], smallPrimes[520]] {
            let modulus = PrimeModulus::new(prime.p);
            let p = u64::from(prime.p);
            assert_eq!(
                u64::from(prime.p) * u64::from(modulus.p0i) % (1 << 31),
                (1 << 31) - 1
            );
            assert_eq!(u64::from(modulus.r()), (1u64 << 31) % p);
            assert_eq!(u128::from(modulus.r2), (1u128 << 62) % u128::from(p));
            for x in [1u32, 2, 7, 64] {
                let expected = (0..x).fold(1u128, |value, _| value * (1u128 << 31) % u128::from(p));
                assert_eq!(u128::from(modulus.powerOfR(x)), expected, "2^(31 {x})");
            }
        }
    }

    #[test]
    fn modularOperationsGiveTheValuesOfTheirDefinitions() {
        let modulus = modulus();
        let p = u64::from(modulus.p);
        let values = [
            0u32,
            1,
            2,
            12289,
            modulus.p / 2,
            modulus.p / 2 + 1,
            modulus.p - 1,
        ];
        for left in values {
            for right in values {
                assert_eq!(
                    u64::from(modulus.sum(left, right)),
                    (u64::from(left) + u64::from(right)) % p
                );
                assert_eq!(
                    u64::from(modulus.difference(left, right)),
                    (u64::from(left) + p - u64::from(right)) % p
                );
                let product = u64::from(modulus.product(left, right));
                assert_eq!(
                    product * (1 << 31) % p,
                    u64::from(left) * u64::from(right) % p
                );
                if right != 0 {
                    let quotient = u64::from(modulus.quotient(left, right));
                    assert_eq!(
                        quotient * u64::from(right) % p,
                        u64::from(left),
                        "{left} / {right}"
                    );
                }
            }
            assert_eq!(modulus.quotient(left, 0), 0);
        }
        // Each value within (p - 1)/2 of zero comes back from its residue.
        for value in [-5i32, -1, 0, 1, 1 << 29, -(1 << 29)] {
            let reduced = modulus.reduced(value);
            assert_eq!(i64::from(reduced), i64::from(value).rem_euclid(p as i64));
            assert_eq!(modulus.normalized(reduced), value);
        }
        // (p - 1) / 2 stays positive and (p + 1) / 2 becomes negative.
        assert_eq!(modulus.normalized(modulus.p / 2), (modulus.p / 2) as i32);
        assert_eq!(
            modulus.normalized(modulus.p / 2 + 1),
            -((modulus.p / 2) as i32)
        );
    }

    #[test]
    fn reversalTableIsTheTableOfTheCCode() {
        assert_eq!(&reversed10[..8], &[0, 512, 256, 768, 128, 640, 384, 896]);
        assert_eq!(reversed10[1023], 1023);
        assert_eq!(reversed10[1022], 511);
    }

    #[test]
    fn transformProductIsTheNegacyclicProductAndTheInverseUndoesIt() {
        let modulus = modulus();
        let p = u64::from(modulus.p);
        for logn in [1u32, 2, 4, 7] {
            let n = 1usize << logn;
            let mut roots = vec![0; n];
            let mut inverseRoots = vec![0; n];
            modulus.fillRoots(&mut roots, &mut inverseRoots, smallPrimes[0].g, logn);
            let left: Vec<u32> = (0..n)
                .map(|u| ((u as u64 * 1_000_003 + 17) % p) as u32)
                .collect();
            let right: Vec<u32> = (0..n)
                .map(|u| ((u as u64 * 7_919 + 3) % p) as u32)
                .collect();
            let mut expected = vec![0u64; n];
            for (i, a) in left.iter().enumerate() {
                for (j, b) in right.iter().enumerate() {
                    let term = u64::from(*a) * u64::from(*b) % p;
                    let slot = (i + j) % n;
                    expected[slot] = if i + j < n {
                        (expected[slot] + term) % p
                    } else {
                        (expected[slot] + p - term) % p
                    };
                }
            }
            // The coefficients sit at stride 3, as the residues of big integers do.
            let mut spread = vec![0u32; 3 * n];
            for (k, value) in left.iter().enumerate() {
                spread[3 * k] = *value;
            }
            modulus.transform(&mut spread, 3, &roots, logn);
            let mut other = right.clone();
            modulus.transform(&mut other, 1, &roots, logn);
            for (k, value) in other.iter().enumerate() {
                let product = modulus.product(spread[3 * k], *value);
                spread[3 * k] = modulus.product(product, modulus.r2);
            }
            modulus.inverseTransform(&mut spread, 3, &inverseRoots, logn);
            let product: Vec<u64> = (0..n).map(|k| u64::from(spread[3 * k])).collect();
            assert_eq!(product, expected, "logn {logn}");
            let mut roundTrip = left.clone();
            modulus.transform(&mut roundTrip, 1, &roots, logn);
            modulus.inverseTransform(&mut roundTrip, 1, &inverseRoots, logn);
            assert_eq!(roundTrip, left, "logn {logn}");
        }
    }
}
