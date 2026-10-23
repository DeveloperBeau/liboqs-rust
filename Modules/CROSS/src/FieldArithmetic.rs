use crate::{Parameters, Problem};
use alloc::vec::Vec;

/// The arithmetic of a parameter set on vectors of the field F_p, from `fp_arith.h`.
///
/// The parity-check matrix is H = [V I] with n - k rows. The C code keeps the transpose V^T of
/// V, k rows of n - k elements, so the syndrome of a vector e is the last n - k entries of e
/// plus the sum of each of the first k entries times its row of V^T. Each step of each sum is
/// reduced as in the C code, so every value keeps the form of the C code.
pub(crate) struct FieldArithmetic {
    problem: Problem,
    /// The dimension k of the code.
    dimension: usize,
}

impl FieldArithmetic {
    /// Makes the arithmetic of a parameter set.
    pub(crate) fn new(parameters: &Parameters) -> Self {
        FieldArithmetic {
            problem: parameters.problem(),
            dimension: parameters.code.dimension,
        }
    }

    /// Adds each row of a matrix times its factor to a syndrome, with a reduction of each step,
    /// the loops of `restr_vec_by_fp_matrix` and `fp_vec_by_fp_matrix`.
    fn accumulated(
        &self,
        syndrome: &mut [u16],
        factors: impl Iterator<Item = u32>,
        matrix: &[u16],
    ) {
        // The loop is written once for each reduction, so that the reduction is not a branch of
        // its inner step.
        match self.problem {
            Problem::rsdp => accumulate(syndrome, factors, matrix, Problem::rsdpReduced),
            Problem::rsdpg => accumulate(syndrome, factors, matrix, Problem::rsdpgReduced),
        }
    }

    /// The syndrome e H^T of a restricted vector of n exponents, `restr_vec_by_fp_matrix`, before
    /// its normalization.
    pub(crate) fn restrictedSyndrome(&self, exponents: &[u8], matrix: &[u16]) -> Vec<u16> {
        let problem = self.problem;
        let mut syndrome = self.restrictedValues(&exponents[self.dimension..]);
        let factors = exponents[..self.dimension]
            .iter()
            .map(|exponent| problem.restrictedValue(*exponent));
        self.accumulated(&mut syndrome, factors, matrix);
        syndrome
    }

    /// The syndrome e H^T of a vector of n field elements, `fp_vec_by_fp_matrix`, before its
    /// normalization.
    pub(crate) fn syndrome(&self, vector: &[u16], matrix: &[u16]) -> Vec<u16> {
        let mut syndrome = vector[self.dimension..].to_vec();
        let factors = vector[..self.dimension]
            .iter()
            .map(|value| u32::from(*value));
        self.accumulated(&mut syndrome, factors, matrix);
        syndrome
    }

    /// The product of two vectors entry by entry, `fp_vec_by_fp_vec_pointwise`.
    pub(crate) fn pointwiseProduct(&self, first: &[u16], second: &[u16]) -> Vec<u16> {
        first
            .iter()
            .zip(second)
            .map(|(left, right)| self.problem.reduced(u32::from(*left) * u32::from(*right)) as u16)
            .collect()
    }

    /// The response `u' + c g^e'` of a mask u', a restricted vector e' and a challenge c,
    /// `fp_vec_by_restr_vec_scaled`, before its normalization.
    pub(crate) fn scaledSum(&self, exponents: &[u8], challenge: u16, mask: &[u16]) -> Vec<u16> {
        let problem = self.problem;
        exponents
            .iter()
            .zip(mask)
            .map(|(exponent, value)| {
                problem.reduced(
                    u32::from(*value) + problem.restrictedValue(*exponent) * u32::from(challenge),
                ) as u16
            })
            .collect()
    }

    /// The commitment syndrome `y' H^T - c s` of a verification, `fp_synd_minus_fp_vec_scaled`,
    /// before its normalization: c s is reduced and normalized, negated and added with one
    /// reduction step.
    pub(crate) fn syndromeDifference(
        &self,
        syndrome: &[u16],
        challenge: u16,
        publicSyndrome: &[u16],
    ) -> Vec<u16> {
        let problem = self.problem;
        syndrome
            .iter()
            .zip(publicSyndrome)
            .map(|(value, public)| {
                let scaled =
                    problem.normalized(problem.reduced(u32::from(*public) * u32::from(challenge)));
                problem.reducedOnce(u32::from(*value) + problem.negated(scaled)) as u16
            })
            .collect()
    }

    /// The field elements `g^e` of a restricted vector, `convert_restr_vec_to_fp`.
    pub(crate) fn restrictedValues(&self, exponents: &[u8]) -> Vec<u16> {
        exponents
            .iter()
            .map(|exponent| self.problem.restrictedValue(*exponent) as u16)
            .collect()
    }

    /// Replaces the second form of zero of each entry, `fp_dz_norm` and `fp_dz_norm_synd`.
    pub(crate) fn normalize(&self, vector: &mut [u16]) {
        for value in vector.iter_mut() {
            *value = self.problem.normalized(u32::from(*value)) as u16;
        }
    }
}

/// The inner loops of a syndrome with one reduction: for each factor in order, each entry of the
/// syndrome takes the reduction of itself plus the factor times its coefficient of the row.
fn accumulate(
    syndrome: &mut [u16],
    factors: impl Iterator<Item = u32>,
    matrix: &[u16],
    reduce: impl Fn(u32) -> u32,
) {
    let width = syndrome.len();
    for (factor, row) in factors.zip(matrix.chunks_exact(width)) {
        for (entry, coefficient) in syndrome.iter_mut().zip(row) {
            *entry = reduce(u32::from(*entry) + factor * u32::from(*coefficient)) as u16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FieldArithmetic;
    use crate::parameters::{crossRSDP128Balanced, crossRSDPG192Fast};
    use crate::testInputs::SeededSequence;

    /// The syndrome of a vector over the integers modulo p with the plain sums, the definition
    /// that the steps of the C code must agree with modulo p.
    fn plainSyndrome(values: &[u64], matrix: &[u16], dimension: usize, prime: u64) -> Vec<u64> {
        let width = values.len() - dimension;
        (0..width)
            .map(|column| {
                let sum: u64 = (0..dimension)
                    .map(|row| values[row] * u64::from(matrix[row * width + column]))
                    .sum();
                (sum + values[dimension + column]) % prime
            })
            .collect()
    }

    #[test]
    fn theSyndromeOfEachProblemIsTheProductWithTheParityCheckMatrix() {
        for parameters in [&crossRSDP128Balanced, &crossRSDPG192Fast] {
            let arithmetic = FieldArithmetic::new(parameters);
            let problem = parameters.problem();
            let prime = problem.prime();
            let (length, dimension) = (parameters.code.length, parameters.code.dimension);
            let mut sequence = SeededSequence::new(11);
            let matrix: Vec<u16> = sequence
                .values(dimension * (length - dimension), prime)
                .iter()
                .map(|value| *value as u16)
                .collect();
            // Any value of the bits of the field, also the forms that a hostile input unpacks.
            let vector: Vec<u16> = sequence
                .values(length, 1 << problem.fieldBits())
                .iter()
                .map(|value| *value as u16)
                .collect();
            let mut syndrome = arithmetic.syndrome(&vector, &matrix);
            assert!(syndrome.iter().all(|value| u32::from(*value) <= prime));
            arithmetic.normalize(&mut syndrome);
            let values: Vec<u64> = vector.iter().map(|value| u64::from(*value)).collect();
            let expected = plainSyndrome(&values, &matrix, dimension, u64::from(prime));
            let actual: Vec<u64> = syndrome.iter().map(|value| u64::from(*value)).collect();
            assert_eq!(actual, expected, "{}", parameters.description.name);
            let exponents: Vec<u8> = sequence
                .values(length, problem.restrictedOrder() + 1)
                .iter()
                .map(|value| *value as u8)
                .collect();
            let mut syndrome = arithmetic.restrictedSyndrome(&exponents, &matrix);
            arithmetic.normalize(&mut syndrome);
            let values: Vec<u64> = arithmetic
                .restrictedValues(&exponents)
                .iter()
                .map(|value| u64::from(*value))
                .collect();
            let expected = plainSyndrome(&values, &matrix, dimension, u64::from(prime));
            let actual: Vec<u64> = syndrome.iter().map(|value| u64::from(*value)).collect();
            assert_eq!(actual, expected, "{}", parameters.description.name);
        }
    }

    #[test]
    fn theStepsKeepTheSecondFormOfZeroUntilTheNormalization() {
        // RSDP: 127 * 1 reduces to 127, the second form of zero, and the normalization makes it 0.
        let arithmetic = FieldArithmetic::new(&crossRSDP128Balanced);
        assert_eq!(
            arithmetic.pointwiseProduct(&[127, 2, 126], &[1, 64, 126]),
            vec![127, 1, 1]
        );
        let mut vector = vec![127, 0, 126];
        arithmetic.normalize(&mut vector);
        assert_eq!(vector, vec![0, 0, 126]);
        // RSDP(G) reduces each product fully, and has one form of zero.
        let arithmetic = FieldArithmetic::new(&crossRSDPG192Fast);
        assert_eq!(
            arithmetic.pointwiseProduct(&[508, 511, 509], &[508, 2, 3]),
            vec![1, 4, 0]
        );
    }

    #[test]
    fn theScaledSumAndTheSyndromeDifferenceAreTheFormulasOfTheCCode() {
        for parameters in [&crossRSDP128Balanced, &crossRSDPG192Fast] {
            let arithmetic = FieldArithmetic::new(parameters);
            let problem = parameters.problem();
            let prime = problem.prime();
            let mut sequence = SeededSequence::new(12);
            let exponents: Vec<u8> = sequence
                .values(50, problem.restrictedOrder())
                .iter()
                .map(|value| *value as u8)
                .collect();
            let mask: Vec<u16> = sequence
                .values(50, prime)
                .iter()
                .map(|v| *v as u16)
                .collect();
            let challenge = (sequence.next(prime - 1) + 1) as u16;
            let sum = arithmetic.scaledSum(&exponents, challenge, &mask);
            for ((exponent, value), result) in exponents.iter().zip(&mask).zip(&sum) {
                let expected = (u32::from(*value)
                    + problem.restrictedValue(*exponent) * u32::from(challenge))
                    % prime;
                assert_eq!(u32::from(*result) % prime, expected);
                assert!(u32::from(*result) <= prime);
            }
            let syndrome: Vec<u16> = sequence
                .values(50, prime)
                .iter()
                .map(|v| *v as u16)
                .collect();
            let public: Vec<u16> = sequence
                .values(50, 1 << problem.fieldBits())
                .iter()
                .map(|value| *value as u16)
                .collect();
            let difference = arithmetic.syndromeDifference(&syndrome, challenge, &public);
            for ((value, publicValue), result) in syndrome.iter().zip(&public).zip(&difference) {
                let product = u32::from(*publicValue) * u32::from(challenge) % prime;
                let expected = (u32::from(*value) + prime - product) % prime;
                assert_eq!(u32::from(*result) % prime, expected);
            }
        }
    }

    #[test]
    fn theRSDPSyndromeDifferenceOfZeroIsTheSecondFormOfZero() {
        // c s = 0 is negated to 127, and the syndrome 0 plus 127 folds to 127.
        let arithmetic = FieldArithmetic::new(&crossRSDP128Balanced);
        assert_eq!(
            arithmetic.syndromeDifference(&[0, 5], 3, &[0, 0]),
            vec![127, 5]
        );
        assert_eq!(arithmetic.syndromeDifference(&[0], 1, &[1]), vec![126]);
    }
}
