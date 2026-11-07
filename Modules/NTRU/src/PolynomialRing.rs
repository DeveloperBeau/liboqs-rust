use crate::{Parameters, PolynomialMultiplication, Variant};
use alloc::vec;
use alloc::vec::Vec;

/// The arithmetic of NTRU polynomials of one parameter set, `poly.c`, `poly_mod.c` and
/// `poly_lift.c`.
///
/// A polynomial is a list of `n` 16-bit coefficients. The C code keeps each coefficient
/// modulo `2^16` and reduces modulo `q` only where it packs a polynomial or where it needs
/// the value, so the port does the same, with wrapping operations. A polynomial modulo 3 has
/// the coefficients 0, 1 and 2, where 2 stands for -1.
pub(crate) struct PolynomialRing<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> PolynomialRing<'parameters> {
    /// Makes the arithmetic of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        PolynomialRing { parameters }
    }

    /// The residue of a 16-bit value modulo 3, `mod3` of `poly_mod.c` and `sample_iid.c`.
    pub(crate) fn residueModuloThree(value: u16) -> u16 {
        // Each step keeps the value modulo 3, because 256, 16 and 4 are 1 modulo 3.
        let mut reduced = (value >> 8) + (value & 0xFF);
        reduced = (reduced >> 4) + (reduced & 0xF);
        reduced = (reduced >> 2) + (reduced & 0x3);
        reduced = (reduced >> 2) + (reduced & 0x3);
        let difference = reduced as i16 - 3;
        let mask = difference >> 15;
        ((mask & reduced as i16) ^ (!mask & difference)) as u16
    }

    /// The value of a coefficient modulo `q`, `MODQ`.
    pub(crate) fn residueModuloModulus(&self, value: u16) -> u16 {
        value & (self.parameters.modulus() - 1)
    }

    /// The product of two polynomials modulo `x^n - 1`, `poly_Rq_mul`.
    pub(crate) fn product(&self, left: &[u16], right: &[u16]) -> Vec<u16> {
        PolynomialMultiplication::product(self.parameters, left, right)
    }

    /// The product of two polynomials modulo `Phi_n = 1 + x + ... + x^(n - 1)`, with the
    /// coefficients modulo `2^16`, `poly_Sq_mul`.
    pub(crate) fn productModuloPhi(&self, left: &[u16], right: &[u16]) -> Vec<u16> {
        let mut product = self.product(left, right);
        Self::reduceModuloPhi(&mut product);
        product
    }

    /// The product of two polynomials modulo 3 and `Phi_n`, `poly_S3_mul`. The C code reduces
    /// the product of the ring modulo `q` before it reduces modulo 3.
    pub(crate) fn ternaryProduct(&self, left: &[u16], right: &[u16]) -> Vec<u16> {
        let mut product = self.product(left, right);
        for coefficient in product.iter_mut() {
            *coefficient = self.residueModuloModulus(*coefficient);
        }
        Self::reduceModuloThreeAndPhi(&mut product);
        product
    }

    /// Reduces a polynomial modulo 3 and `Phi_n`, `poly_mod_3_Phi_n`: it subtracts `Phi_n`
    /// times the last coefficient, which leaves the last coefficient 0.
    pub(crate) fn reduceModuloThreeAndPhi(polynomial: &mut [u16]) {
        let last = polynomial.len() - 1;
        for index in 0..polynomial.len() {
            // Adding twice the last coefficient is subtracting it modulo 3. The last
            // coefficient changes only in the last step.
            let sum = polynomial[index].wrapping_add(polynomial[last].wrapping_mul(2));
            polynomial[index] = Self::residueModuloThree(sum);
        }
    }

    /// Reduces a polynomial modulo `Phi_n` with the coefficients modulo `2^16`,
    /// `poly_mod_q_Phi_n`: it subtracts the last coefficient from each coefficient.
    pub(crate) fn reduceModuloPhi(polynomial: &mut [u16]) {
        let last = polynomial.len() - 1;
        for index in 0..polynomial.len() {
            polynomial[index] = polynomial[index].wrapping_sub(polynomial[last]);
        }
    }

    /// The polynomial modulo 3 and `Phi_n` of a polynomial modulo `q`, `poly_Rq_to_S3`. Each
    /// coefficient is read in `[-q / 2, q / 2)` before its reduction modulo 3.
    pub(crate) fn ternaryFromModulus(&self, polynomial: &[u16]) -> Vec<u16> {
        let bits = self.parameters.modulusBits;
        let mut result: Vec<u16> = polynomial
            .iter()
            .map(|coefficient| {
                let value = self.residueModuloModulus(*coefficient);
                let isHigh = value >> (bits - 1);
                // -q modulo 3 is 1 for an odd exponent and 2 for an even one.
                value + (isHigh << (1 - (bits & 1)))
            })
            .collect();
        Self::reduceModuloThreeAndPhi(&mut result);
        result
    }

    /// Maps the coefficients 0, 1 and 2 to 0, 1 and `q - 1` in place, `poly_Z3_to_Zq`.
    pub(crate) fn liftTernaryCoefficients(&self, polynomial: &mut [u16]) {
        let mask = self.parameters.modulus() - 1;
        for coefficient in polynomial.iter_mut() {
            *coefficient |= 0u16.wrapping_sub(*coefficient >> 1) & mask;
        }
    }

    /// Maps the coefficients 0, 1 and `q - 1` modulo `q` to 0, 1 and 2 in place,
    /// `poly_trinary_Zq_to_Z3`.
    pub(crate) fn lowerTrinaryCoefficients(&self, polynomial: &mut [u16]) {
        let bits = self.parameters.modulusBits;
        for coefficient in polynomial.iter_mut() {
            let value = self.residueModuloModulus(*coefficient);
            *coefficient = 3 & (value ^ (value >> (bits - 1)));
        }
    }

    /// The lift of a message polynomial modulo 3 to a polynomial modulo `q`, `poly_lift`.
    ///
    /// NTRU-HPS lifts each coefficient to 0, 1 or `q - 1`. NTRU-HRSS lifts `m` to
    /// `(x - 1) (m / (x - 1) mod (3, Phi_n))`, so that the lift is 0 at `x = 1`. The message
    /// must have coefficients in 0, 1 and 2.
    pub(crate) fn lift(&self, message: &[u16]) -> Vec<u16> {
        match self.parameters.variant {
            Variant::hps => {
                let mut lifted = message.to_vec();
                self.liftTernaryCoefficients(&mut lifted);
                lifted
            }
            Variant::hrss => self.liftByXMinusOne(message),
        }
    }

    /// The lift of NTRU-HRSS: `b = m / (x - 1)` modulo 3 and `Phi_n`, lifted to 0, 1 and
    /// `q - 1`, times `x - 1`.
    fn liftByXMinusOne(&self, message: &[u16]) -> Vec<u16> {
        let count = self.parameters.coefficientCount;
        let a = message;
        let mut b = vec![0u16; count];
        // t = -1 / n modulo 3, and z with <z x^i, x - 1> = delta(i, 0) modulo 3 gives the first
        // three coefficients of b as inner products.
        let t = 3 - (count % 3) as u16;
        b[0] = a[0]
            .wrapping_mul(2 - t)
            .wrapping_add(a[1].wrapping_mul(0))
            .wrapping_add(a[2].wrapping_mul(t));
        b[1] = a[1].wrapping_mul(2 - t).wrapping_add(a[2].wrapping_mul(0));
        b[2] = a[2].wrapping_mul(2 - t);
        let mut zj = 0u16;
        for coefficient in &a[3..] {
            b[0] = b[0].wrapping_add(coefficient.wrapping_mul(zj + 2 * t));
            b[1] = b[1].wrapping_add(coefficient.wrapping_mul(zj + t));
            b[2] = b[2].wrapping_add(coefficient.wrapping_mul(zj));
            zj = (zj + t) % 3;
        }
        b[1] = b[1].wrapping_add(a[0].wrapping_mul(zj + t));
        b[2] = b[2].wrapping_add(a[0].wrapping_mul(zj));
        b[2] = b[2].wrapping_add(a[1].wrapping_mul(zj + t));
        // b[i] = b[i - 3] - (a[i] + a[i - 1] + a[i - 2]) modulo 3.
        for index in 3..count {
            b[index] = b[index - 3].wrapping_add(
                2u16.wrapping_mul(
                    a[index]
                        .wrapping_add(a[index - 1])
                        .wrapping_add(a[index - 2]),
                ),
            );
        }
        Self::reduceModuloThreeAndPhi(&mut b);
        self.liftTernaryCoefficients(&mut b);
        let mut lifted = vec![0u16; count];
        lifted[0] = b[0].wrapping_neg();
        for index in 0..count - 1 {
            lifted[index + 1] = b[index].wrapping_sub(b[index + 1]);
        }
        lifted
    }
}

#[cfg(test)]
mod tests {
    use super::PolynomialRing;
    use crate::parameters::{ntruHPS2048509, ntruHPS4096821, ntruHRSS701, ntruHRSS1373};
    use crate::testInputs::{cAnswer, everySet, sequence, ternarySequence, valuesDigest};

    #[test]
    fn residueModuloThreeIsTheRemainderForEverySixteenBitValue() {
        for value in 0..=u16::MAX {
            assert_eq!(
                PolynomialRing::residueModuloThree(value),
                value % 3,
                "{value}"
            );
        }
    }

    #[test]
    fn reductionModuloPhiSubtractsTheLastCoefficient() {
        let mut polynomial = vec![5u16, 0, 0xFFFF, 3];
        PolynomialRing::reduceModuloPhi(&mut polynomial);
        assert_eq!(polynomial, vec![2, 0xFFFD, 0xFFFC, 0]);
        // Modulo 3: 7 + 2 * 2 = 11 is 2, 0 + 4 is 1, 1 + 4 is 2, and the last becomes 0.
        let mut ternary = vec![7u16, 0, 1, 2];
        PolynomialRing::reduceModuloThreeAndPhi(&mut ternary);
        assert_eq!(ternary, vec![2, 1, 2, 0]);
    }

    #[test]
    fn ternaryCoefficientsMapToZeroOneAndQMinusOneAndBack() {
        for parameters in [
            &ntruHPS2048509,
            &ntruHPS4096821,
            &ntruHRSS701,
            &ntruHRSS1373,
        ] {
            let ring = PolynomialRing::new(parameters);
            let q = parameters.modulus();
            let mut polynomial = vec![0u16, 1, 2, 1, 0];
            ring.liftTernaryCoefficients(&mut polynomial);
            assert_eq!(polynomial, vec![0, 1, q - 1, 1, 0]);
            // A lowered coefficient is read modulo q first.
            polynomial[0] = 2 * q;
            polynomial[4] = 3 * q - 1;
            ring.lowerTrinaryCoefficients(&mut polynomial);
            assert_eq!(polynomial, vec![0, 1, 2, 1, 2]);
        }
    }

    #[test]
    fn modulusToTernaryReadsEachCoefficientAsASignedValue() {
        // For q = 2^11, the value q - 1 is -1, which is 2 modulo 3, and q / 2 is -1024, which
        // is 2 modulo 3. For q = 2^12, -2048 is 1 modulo 3.
        let ring = PolynomialRing::new(&ntruHPS2048509);
        let mut polynomial = vec![0u16; 509];
        polynomial[..5].copy_from_slice(&[2047, 1024, 1023, 4, 2048 + 5]);
        let ternary = ring.ternaryFromModulus(&polynomial);
        assert_eq!(&ternary[..5], &[2, 2, 0, 1, 2]);
        let ring = PolynomialRing::new(&ntruHPS4096821);
        let mut polynomial = vec![0u16; 821];
        polynomial[..3].copy_from_slice(&[2048, 4095, 2047]);
        let ternary = ring.ternaryFromModulus(&polynomial);
        assert_eq!(&ternary[..3], &[1, 2, 1]);
    }

    #[test]
    fn theLiftOfHRSSIsZeroAtOneAndEqualsTheMessageModuloThreeAndPhi() {
        for parameters in [&ntruHRSS701, &ntruHRSS1373] {
            let ring = PolynomialRing::new(parameters);
            let count = parameters.coefficientCount;
            let q = i64::from(parameters.modulus());
            let message: Vec<u16> = (0..count)
                .map(|index| ((index * 7 + index / 3) % 3) as u16)
                .collect();
            let mut reduced = message.clone();
            PolynomialRing::reduceModuloThreeAndPhi(&mut reduced);
            let lifted = ring.lift(&message);
            let signed: Vec<i64> = lifted
                .iter()
                .map(|value| {
                    let value = i64::from(*value) % q;
                    if value > q / 2 { value - q } else { value }
                })
                .collect();
            // Each coefficient is small, and the sum is 0, the value at x = 1.
            assert!(signed.iter().all(|value| value.abs() <= 2));
            assert_eq!(signed.iter().sum::<i64>(), 0);
            // Modulo 3 and Phi_n the lift is the message.
            let ternary: Vec<u16> = signed
                .iter()
                .map(|value| value.rem_euclid(3) as u16)
                .collect();
            let mut ternary = ternary;
            PolynomialRing::reduceModuloThreeAndPhi(&mut ternary);
            assert_eq!(ternary, reduced, "{}", parameters.description.name);
        }
    }

    #[test]
    fn eachOperationHasTheCoefficientsOfTheCFunctions() {
        // poly_lift, poly_Rq_to_S3, poly_S3_mul and poly_Sq_mul of liboqs 0.16.0 on the same
        // inputs.
        for parameters in everySet() {
            let ring = PolynomialRing::new(parameters);
            let count = parameters.coefficientCount;
            let name = parameters.description.name;
            let lifted = ring.lift(&ternarySequence(count, 12));
            assert_eq!(valuesDigest(&lifted), cAnswer(name, "lift"), "{name}");
            let ternary = ring.ternaryFromModulus(&sequence(count, 13));
            assert_eq!(
                valuesDigest(&ternary),
                cAnswer(name, "ternaryFromModulus"),
                "{name}"
            );
            let product =
                ring.ternaryProduct(&ternarySequence(count, 14), &ternarySequence(count, 15));
            assert_eq!(
                valuesDigest(&product),
                cAnswer(name, "ternaryProduct"),
                "{name}"
            );
            let product = ring.productModuloPhi(&sequence(count, 16), &sequence(count, 17));
            assert_eq!(
                valuesDigest(&product),
                cAnswer(name, "productModuloPhi"),
                "{name}"
            );
        }
    }
}
