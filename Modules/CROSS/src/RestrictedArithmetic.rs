use crate::{Parameters, Problem};
use alloc::vec::Vec;

/// The arithmetic of a parameter set on restricted vectors, stored as exponents modulo the
/// order z of the restricted group, from `restr_arith.h`.
///
/// For RSDP(G), the restricted vectors of the scheme lie in a subgroup G of n coordinates. An
/// element of G is the product of an information word of m exponents with the generator matrix
/// [W I] of G, whose part W of m rows of n - m exponents the C code keeps.
pub(crate) struct RestrictedArithmetic {
    problem: Problem,
    /// The length n of the code.
    length: usize,
    /// The dimension m of the subgroup of RSDP(G).
    subgroupDimension: usize,
}

impl RestrictedArithmetic {
    /// Makes the arithmetic of a parameter set.
    pub(crate) fn new(parameters: &Parameters) -> Self {
        RestrictedArithmetic {
            problem: parameters.problem(),
            length: parameters.code.length,
            subgroupDimension: parameters.code.subgroupDimension,
        }
    }

    /// The difference `a - b` of two restricted vectors, exponent by exponent with one
    /// reduction step, `fz_vec_sub_n` and `fz_vec_sub_m`. The result keeps z as a second form of
    /// zero.
    pub(crate) fn difference(&self, first: &[u8], second: &[u8]) -> Vec<u8> {
        let problem = self.problem;
        first
            .iter()
            .zip(second)
            .map(|(left, right)| {
                problem.exponentReducedOnce(
                    u32::from(*left) + problem.exponentNegated(u32::from(*right)),
                ) as u8
            })
            .collect()
    }

    /// Replaces the second form of zero of each exponent, `fz_dz_norm_n` and `fz_dz_norm_m`.
    pub(crate) fn normalize(&self, exponents: &mut [u8]) {
        for exponent in exponents.iter_mut() {
            *exponent = self.problem.exponentNormalized(u32::from(*exponent)) as u8;
        }
    }

    /// True when each exponent is below z, `is_fz_vec_in_restr_group_n` and
    /// `is_fz_vec_in_restr_group_m`. The second form of zero is refused.
    pub(crate) fn isInRestrictedGroup(&self, exponents: &[u8]) -> bool {
        let order = self.problem.restrictedOrder();
        exponents
            .iter()
            .all(|exponent| u32::from(*exponent) < order)
    }

    /// The element of G of an information word of m exponents, `fz_inf_w_by_fz_matrix`: the
    /// first n - m exponents are the sums of each exponent of the word times its row of W, with
    /// two reduction steps for each term, and the last m are the word. The result keeps z as a
    /// second form of zero.
    pub(crate) fn subgroupElement(&self, word: &[u8], matrix: &[u8]) -> Vec<u8> {
        let problem = self.problem;
        let width = self.length - self.subgroupDimension;
        let mut element = alloc::vec![0u8; width];
        for (exponent, row) in word.iter().zip(matrix.chunks_exact(width)) {
            for (entry, coefficient) in element.iter_mut().zip(row) {
                *entry = problem.exponentReduced(
                    u32::from(*entry) + u32::from(*exponent) * u32::from(*coefficient),
                ) as u8;
            }
        }
        element.extend_from_slice(word);
        element
    }
}

#[cfg(test)]
mod tests {
    use super::RestrictedArithmetic;
    use crate::parameters::{crossRSDP192Small, crossRSDPG128Fast};
    use crate::testInputs::SeededSequence;

    #[test]
    fn theDifferenceIsTheDifferenceModuloTheOrderWithTheSecondFormOfZero() {
        for parameters in [&crossRSDP192Small, &crossRSDPG128Fast] {
            let arithmetic = RestrictedArithmetic::new(parameters);
            let order = parameters.problem().restrictedOrder();
            let first: Vec<u8> = (0..order)
                .flat_map(|value| vec![value as u8; order as usize])
                .collect();
            let second: Vec<u8> = (0..order)
                .flat_map(|_| (0..order).map(|value| value as u8))
                .collect();
            let difference = arithmetic.difference(&first, &second);
            for ((left, right), result) in first.iter().zip(&second).zip(&difference) {
                let expected = (u32::from(*left) + order - u32::from(*right)) % order;
                assert_eq!(u32::from(*result) % order, expected);
                // A difference of zero is the second form of zero, z.
                if left == right {
                    assert_eq!(u32::from(*result), order);
                }
            }
            let mut normalized = difference.clone();
            arithmetic.normalize(&mut normalized);
            assert!(normalized.iter().all(|value| u32::from(*value) < order));
        }
    }

    #[test]
    fn theGroupCheckRefusesTheSecondFormOfZero() {
        let arithmetic = RestrictedArithmetic::new(&crossRSDP192Small);
        assert!(arithmetic.isInRestrictedGroup(&[0, 1, 6]));
        assert!(!arithmetic.isInRestrictedGroup(&[0, 7, 6]));
        assert!(arithmetic.isInRestrictedGroup(&[]));
        let arithmetic = RestrictedArithmetic::new(&crossRSDPG128Fast);
        assert!(arithmetic.isInRestrictedGroup(&[126, 0]));
        assert!(!arithmetic.isInRestrictedGroup(&[126, 127]));
    }

    #[test]
    fn aSubgroupElementIsTheWordTimesTheGeneratorMatrix() {
        let parameters = &crossRSDPG128Fast;
        let arithmetic = RestrictedArithmetic::new(parameters);
        let (length, dimension) = (parameters.code.length, parameters.code.subgroupDimension);
        let width = length - dimension;
        let mut sequence = SeededSequence::new(13);
        let matrix: Vec<u8> = sequence
            .values(dimension * width, 127)
            .iter()
            .map(|value| *value as u8)
            .collect();
        // A word with the second form of zero as well, as a hostile signature can hold it.
        let word: Vec<u8> = sequence
            .values(dimension, 128)
            .iter()
            .map(|v| *v as u8)
            .collect();
        let element = arithmetic.subgroupElement(&word, &matrix);
        assert_eq!(element.len(), length);
        assert_eq!(&element[width..], &word[..]);
        for column in 0..width {
            let sum: u32 = (0..dimension)
                .map(|row| u32::from(word[row]) * u32::from(matrix[row * width + column]))
                .sum();
            assert_eq!(u32::from(element[column]) % 127, sum % 127, "{column}");
            assert!(element[column] <= 127);
        }
    }
}
