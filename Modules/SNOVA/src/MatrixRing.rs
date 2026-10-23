use crate::fieldArithmetic::FieldArithmetic;
use alloc::vec;
use alloc::vec::Vec;

/// The ring of the `l x l` matrices over GF(16) of one rank, with the powers `S^0` to
/// `S^(l - 1)` of the matrix `S` of SNOVA, as `gen_S_array` of `snova_kernel.h` makes them.
///
/// A matrix is its `l^2` elements, row by row, as `get_gf16m` reads them.
pub(crate) struct MatrixRing {
    /// The rank `l`.
    rank: usize,
    /// `S^0` to `S^(l - 1)`, each in `l^2` elements.
    powers: Vec<u8>,
    /// The spread form of each element of `powers`, `xS` of the C code.
    spreadPowers: Vec<u32>,
}

impl MatrixRing {
    /// Makes the ring of a rank from 2 to 5, with the powers of `S`.
    pub(crate) fn new(rank: usize) -> Self {
        debug_assert!((2..=5).contains(&rank), "SNOVA has no rank {rank}");
        let squaredRank = rank * rank;
        let mut powers = vec![0u8; rank * squaredRank];
        // S^0 is the identity, `be_aI(S[0], 1)`.
        for index in 0..rank {
            powers[index * rank + index] = 1;
        }
        // S^1 is `be_the_S`: the entry `8 - (i + j)`, and 9 in the last place of rank 5.
        for row in 0..rank {
            for column in 0..rank {
                powers[squaredRank + row * rank + column] = (8 - (row + column)) as u8;
            }
        }
        if rank == 5 {
            powers[2 * squaredRank - 1] = 9;
        }
        for power in 2..rank {
            let (lower, upper) = powers.split_at_mut(power * squaredRank);
            Self::multiply(
                rank,
                &lower[(power - 1) * squaredRank..],
                &lower[squaredRank..2 * squaredRank],
                &mut upper[..squaredRank],
            );
        }
        let spreadPowers = powers
            .iter()
            .map(|element| FieldArithmetic::spread(*element))
            .collect();
        MatrixRing {
            rank,
            powers,
            spreadPowers,
        }
    }

    /// Writes the product of two matrices, `gf16m_mul`.
    fn multiply(rank: usize, left: &[u8], right: &[u8], output: &mut [u8]) {
        for row in 0..rank {
            for column in 0..rank {
                let mut sum = 0;
                for inner in 0..rank {
                    sum ^= FieldArithmetic::product(
                        left[row * rank + inner],
                        right[inner * rank + column],
                    );
                }
                output[row * rank + column] = sum;
            }
        }
    }

    /// The power `S^exponent`, for an exponent below the rank.
    pub(crate) fn power(&self, exponent: usize) -> &[u8] {
        let squaredRank = self.rank * self.rank;
        &self.powers[exponent * squaredRank..(exponent + 1) * squaredRank]
    }

    /// The determinant of a matrix, `gf16m_det`: the expansion of the C code for each rank.
    pub(crate) fn determinant(&self, matrix: &[u8]) -> u8 {
        let rank = self.rank;
        let entry = |row: usize, column: usize| matrix[row * rank + column];
        let product = FieldArithmetic::product;
        match rank {
            2 => product(entry(0, 0), entry(1, 1)) ^ product(entry(0, 1), entry(1, 0)),
            3 => {
                product(
                    entry(0, 0),
                    product(entry(1, 1), entry(2, 2)) ^ product(entry(1, 2), entry(2, 1)),
                ) ^ product(
                    entry(0, 1),
                    product(entry(1, 0), entry(2, 2)) ^ product(entry(1, 2), entry(2, 0)),
                ) ^ product(
                    entry(0, 2),
                    product(entry(1, 0), entry(2, 1)) ^ product(entry(1, 1), entry(2, 0)),
                )
            }
            4 => {
                // An entry times a minor of two rows and two columns, the macro
                // `POD(entry, a, b, c, d, e, f, g, h, i, j)` of `gf16_matrix_inline.h`.
                let entryTimesMinor = |a, b, c, d, e, f, g, h, i, j| {
                    product(
                        entry(a, b),
                        product(entry(c, d), entry(e, f)) ^ product(entry(g, h), entry(i, j)),
                    )
                };
                let first = product(
                    entry(0, 0),
                    entryTimesMinor(1, 1, 2, 2, 3, 3, 2, 3, 3, 2)
                        ^ entryTimesMinor(1, 2, 2, 1, 3, 3, 2, 3, 3, 1)
                        ^ entryTimesMinor(1, 3, 2, 1, 3, 2, 2, 2, 3, 1),
                );
                let second = product(
                    entry(0, 1),
                    entryTimesMinor(1, 0, 2, 2, 3, 3, 2, 3, 3, 2)
                        ^ entryTimesMinor(1, 2, 2, 0, 3, 3, 2, 3, 3, 0)
                        ^ entryTimesMinor(1, 3, 2, 0, 3, 2, 2, 2, 3, 0),
                );
                let third = product(
                    entry(0, 2),
                    entryTimesMinor(1, 0, 2, 1, 3, 3, 2, 3, 3, 1)
                        ^ entryTimesMinor(1, 1, 2, 0, 3, 3, 2, 3, 3, 0)
                        ^ entryTimesMinor(1, 3, 2, 0, 3, 1, 2, 1, 3, 0),
                );
                let fourth = product(
                    entry(0, 3),
                    entryTimesMinor(1, 0, 2, 1, 3, 2, 2, 2, 3, 1)
                        ^ entryTimesMinor(1, 1, 2, 0, 3, 2, 2, 2, 3, 0)
                        ^ entryTimesMinor(1, 2, 2, 0, 3, 1, 2, 1, 3, 0),
                );
                first ^ second ^ third ^ fourth
            }
            _ => {
                // `gf16m_det5`: the expansion along the first three rows, with the minors of the
                // three columns of `gf16m_det3` and of the two other columns.
                let minor3 = |first: usize, second: usize, third: usize| {
                    product(
                        entry(0, first),
                        product(entry(1, second), entry(2, third))
                            ^ product(entry(1, third), entry(2, second)),
                    ) ^ product(
                        entry(0, second),
                        product(entry(1, first), entry(2, third))
                            ^ product(entry(1, third), entry(2, first)),
                    ) ^ product(
                        entry(0, third),
                        product(entry(1, first), entry(2, second))
                            ^ product(entry(1, second), entry(2, first)),
                    )
                };
                let minor2 = |first: usize, second: usize| {
                    product(entry(3, first), entry(4, second))
                        ^ product(entry(3, second), entry(4, first))
                };
                product(minor3(0, 1, 2), minor2(3, 4))
                    ^ product(minor3(0, 1, 3), minor2(2, 4))
                    ^ product(minor3(0, 1, 4), minor2(2, 3))
                    ^ product(minor3(0, 2, 3), minor2(1, 4))
                    ^ product(minor3(0, 2, 4), minor2(1, 3))
                    ^ product(minor3(0, 3, 4), minor2(1, 2))
                    ^ product(minor3(1, 2, 3), minor2(0, 4))
                    ^ product(minor3(1, 2, 4), minor2(0, 3))
                    ^ product(minor3(1, 3, 4), minor2(0, 2))
                    ^ product(minor3(2, 3, 4), minor2(0, 1))
            }
        }
    }

    /// Makes a matrix invertible, `be_invertible_by_add_aS`: a matrix with determinant zero
    /// gets `1 S`, `2 S` and so on added in turn, up to `15 S`, until its determinant is not
    /// zero. An invertible matrix stays as it is.
    pub(crate) fn makeInvertible(&self, matrix: &mut [u8]) {
        if self.determinant(matrix) != 0 {
            return;
        }
        let rank = self.rank;
        for factor in 1..16u8 {
            // `be_aS`: the entry `(8 - (i + j)) a`, and `9 a` in the last place of rank 5.
            for row in 0..rank {
                for column in 0..rank {
                    let base = if rank == 5 && row == 4 && column == 4 {
                        9
                    } else {
                        (8 - (row + column)) as u8
                    };
                    matrix[row * rank + column] ^= FieldArithmetic::product(base, factor);
                }
            }
            if self.determinant(matrix) != 0 {
                return;
            }
        }
    }

    /// The last coefficient of an element of F16[S]: the given one when it is not zero, and
    /// else `16 - c0`, or 15 for `c0 = 0`, so that the element is invertible.
    fn lastCoefficient(coefficients: &[u8]) -> u8 {
        let last = coefficients[coefficients.len() - 1];
        if last != 0 {
            last
        } else {
            16 - (coefficients[0] + u8::from(coefficients[0] == 0))
        }
    }

    /// Writes the matrix `c0 S^0 + c1 S^1 + ... + c(l-1) S^(l-1)` of `l` coefficients,
    /// `gen_a_FqS`, with the last coefficient of `lastCoefficient`.
    pub(crate) fn writeSumOfPowers(&self, coefficients: &[u8], output: &mut [u8]) {
        let rank = self.rank;
        output.fill(0);
        for index in 0..rank {
            output[index * rank + index] = coefficients[0];
        }
        for exponent in 1..rank {
            let factor = if exponent == rank - 1 {
                Self::lastCoefficient(coefficients)
            } else {
                coefficients[exponent]
            };
            for (element, power) in output.iter_mut().zip(self.power(exponent)) {
                *element ^= FieldArithmetic::product(*power, factor);
            }
        }
    }

    /// Writes the same matrix as `writeSumOfPowers` with the spread arithmetic and no branch,
    /// `gen_a_FqS_ct`, as the secret matrices of T12 take it.
    pub(crate) fn writeSpreadSumOfPowers(&self, coefficients: &[u8], output: &mut [u8]) {
        let rank = self.rank;
        let squaredRank = rank * rank;
        let mut sums = [0u32; 25];
        let sums = &mut sums[..squaredRank];
        let first = FieldArithmetic::spread(coefficients[0]);
        for index in 0..rank {
            sums[index * rank + index] = first;
        }
        for (exponent, coefficient) in coefficients.iter().enumerate().take(rank - 1).skip(1) {
            let factor = FieldArithmetic::spread(*coefficient);
            for (sum, power) in sums
                .iter_mut()
                .zip(&self.spreadPowers[exponent * squaredRank..])
            {
                *sum ^= factor * power;
            }
        }
        let last = coefficients[rank - 1];
        let isLastNonZero = FieldArithmetic::isNonZeroElement(last);
        let replacement =
            15 + FieldArithmetic::isNonZeroElement(coefficients[0]) - u32::from(coefficients[0]);
        let lastFactor = isLastNonZero * u32::from(last) + (1 - isLastNonZero) * replacement;
        let factor = FieldArithmetic::spread(lastFactor as u8);
        for (sum, power) in sums
            .iter_mut()
            .zip(&self.spreadPowers[(rank - 1) * squaredRank..])
        {
            *sum ^= factor * power;
        }
        for (element, sum) in output.iter_mut().zip(sums.iter()) {
            *element = FieldArithmetic::element(*sum);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MatrixRing;
    use crate::fieldArithmetic::FieldArithmetic;

    /// The elements of a simple seeded sequence, the same for each test run.
    fn seededElements(seed: u64, count: usize) -> Vec<u8> {
        let mut state = seed;
        (0..count)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                ((state >> 37) & 0x0F) as u8
            })
            .collect()
    }

    /// The product of two matrices by the schoolbook method.
    fn schoolbookProduct(rank: usize, left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut product = vec![0u8; rank * rank];
        for row in 0..rank {
            for column in 0..rank {
                for inner in 0..rank {
                    product[row * rank + column] ^= FieldArithmetic::product(
                        left[row * rank + inner],
                        right[inner * rank + column],
                    );
                }
            }
        }
        product
    }

    /// The determinant as the sum over all permutations of the products of their entries. The
    /// field has characteristic 2, so every sign is one.
    fn leibnizDeterminant(rank: usize, matrix: &[u8]) -> u8 {
        fn permutations(remaining: Vec<usize>) -> Vec<Vec<usize>> {
            if remaining.len() <= 1 {
                return vec![remaining];
            }
            let mut all = Vec::new();
            for (index, first) in remaining.iter().enumerate() {
                let mut rest = remaining.clone();
                rest.remove(index);
                for mut tail in permutations(rest) {
                    tail.insert(0, *first);
                    all.push(tail);
                }
            }
            all
        }
        permutations((0..rank).collect())
            .into_iter()
            .map(|permutation| {
                permutation
                    .iter()
                    .enumerate()
                    .fold(1u8, |product, (row, column)| {
                        FieldArithmetic::product(product, matrix[row * rank + column])
                    })
            })
            .fold(0, |sum, term| sum ^ term)
    }

    #[test]
    fn theMatrixSOfEachRankHasTheEntriesOfBeTheS() {
        assert_eq!(MatrixRing::new(2).power(1), &[8, 7, 7, 6]);
        assert_eq!(MatrixRing::new(3).power(1), &[8, 7, 6, 7, 6, 5, 6, 5, 4]);
        assert_eq!(
            MatrixRing::new(4).power(1),
            &[8, 7, 6, 5, 7, 6, 5, 4, 6, 5, 4, 3, 5, 4, 3, 2]
        );
        assert_eq!(
            MatrixRing::new(5).power(1),
            &[
                8, 7, 6, 5, 4, 7, 6, 5, 4, 3, 6, 5, 4, 3, 2, 5, 4, 3, 2, 1, 4, 3, 2, 1, 9
            ]
        );
    }

    #[test]
    fn eachPowerOfSIsThePowerBeforeTimesS() {
        for rank in 2..=5 {
            let ring = MatrixRing::new(rank);
            let mut identity = vec![0u8; rank * rank];
            for index in 0..rank {
                identity[index * rank + index] = 1;
            }
            assert_eq!(ring.power(0), identity.as_slice());
            for exponent in 2..rank {
                assert_eq!(
                    ring.power(exponent),
                    schoolbookProduct(rank, ring.power(exponent - 1), ring.power(1)).as_slice(),
                    "rank {rank}, S^{exponent}"
                );
            }
            // S has an irreducible characteristic polynomial, so each power is invertible.
            for exponent in 0..rank {
                assert_ne!(ring.determinant(ring.power(exponent)), 0);
            }
        }
    }

    #[test]
    fn theDeterminantIsTheSumOverAllPermutations() {
        for rank in 2..=5 {
            let ring = MatrixRing::new(rank);
            let squaredRank = rank * rank;
            let elements = seededElements(rank as u64, 300 * squaredRank);
            let mut zeroCount = 0;
            for matrix in elements.chunks(squaredRank) {
                let determinant = ring.determinant(matrix);
                assert_eq!(
                    determinant,
                    leibnizDeterminant(rank, matrix),
                    "rank {rank}: {matrix:?}"
                );
                zeroCount += usize::from(determinant == 0);
            }
            assert!(zeroCount > 0, "rank {rank} has a singular matrix");
            // Two equal rows give zero.
            let mut repeated = elements[..squaredRank].to_vec();
            repeated.copy_within(0..rank, rank);
            assert_eq!(ring.determinant(&repeated), 0);
        }
    }

    #[test]
    fn aSingularMatrixGetsTheMultiplesOfSAddedUntilItIsInvertible() {
        for rank in 2..=5 {
            let ring = MatrixRing::new(rank);
            let squaredRank = rank * rank;
            let elements = seededElements(10 + rank as u64, 400 * squaredRank);
            let mut singularCount = 0;
            for matrix in elements.chunks(squaredRank) {
                let mut invertible = matrix.to_vec();
                ring.makeInvertible(&mut invertible);
                if leibnizDeterminant(rank, matrix) != 0 {
                    assert_eq!(invertible, matrix);
                    continue;
                }
                singularCount += 1;
                // The sum of 1 S to k S is (1 ^ 2 ^ ... ^ k) S, for the first k that helps.
                let mut expected = matrix.to_vec();
                let mut factorSum = 0u8;
                for factor in 1..16u8 {
                    factorSum ^= factor;
                    expected = matrix.to_vec();
                    for (element, power) in expected.iter_mut().zip(ring.power(1)) {
                        let base = *power;
                        *element ^= FieldArithmetic::product(base, factorSum);
                    }
                    if leibnizDeterminant(rank, &expected) != 0 {
                        break;
                    }
                }
                assert_eq!(invertible, expected, "rank {rank}: {matrix:?}");
                assert_ne!(ring.determinant(&invertible), 0);
            }
            assert!(singularCount > 0, "rank {rank} has a singular matrix");
            // The zero matrix becomes S.
            let mut zero = vec![0u8; squaredRank];
            ring.makeInvertible(&mut zero);
            assert_eq!(zero, ring.power(1));
        }
    }

    #[test]
    fn aSumOfPowersIsTheSumOfTheCoefficientsTimesThePowersOfS() {
        for rank in 2..=5 {
            let ring = MatrixRing::new(rank);
            let squaredRank = rank * rank;
            for coefficients in seededElements(20 + rank as u64, 200 * rank).chunks(rank) {
                let mut expected = vec![0u8; squaredRank];
                for (exponent, coefficient) in coefficients.iter().enumerate() {
                    let factor = if exponent == rank - 1 && *coefficient == 0 {
                        if coefficients[0] == 0 {
                            15
                        } else {
                            16 - coefficients[0]
                        }
                    } else {
                        *coefficient
                    };
                    for (element, power) in expected.iter_mut().zip(ring.power(exponent)) {
                        *element ^= FieldArithmetic::product(*power, factor);
                    }
                }
                let mut output = vec![0xFF; squaredRank];
                ring.writeSumOfPowers(coefficients, &mut output);
                assert_eq!(output, expected, "rank {rank}: {coefficients:?}");
            }
        }
        // A last coefficient of zero becomes 16 - c0, or 15 for c0 = 0.
        let ring = MatrixRing::new(4);
        let mut output = vec![0u8; 16];
        ring.writeSumOfPowers(&[0, 0, 0, 0], &mut output);
        let fifteenTimesS3: Vec<u8> = ring
            .power(3)
            .iter()
            .map(|power| FieldArithmetic::product(*power, 15))
            .collect();
        assert_eq!(output, fifteenTimesS3);
        ring.writeSumOfPowers(&[3, 0, 0, 0], &mut output);
        let mut expected: Vec<u8> = ring
            .power(3)
            .iter()
            .map(|power| FieldArithmetic::product(*power, 13))
            .collect();
        for index in 0..4 {
            expected[index * 5] ^= 3;
        }
        assert_eq!(output, expected);
    }

    #[test]
    fn bothFormsOfTheSumOfPowersAgreeForEveryCoefficientList() {
        for rank in 2..=4 {
            let ring = MatrixRing::new(rank);
            let squaredRank = rank * rank;
            let mut plain = vec![0u8; squaredRank];
            let mut spread = vec![0u8; squaredRank];
            for code in 0..1usize << (4 * rank) {
                let coefficients: Vec<u8> = (0..rank)
                    .map(|index| ((code >> (4 * index)) & 0x0F) as u8)
                    .collect();
                ring.writeSumOfPowers(&coefficients, &mut plain);
                ring.writeSpreadSumOfPowers(&coefficients, &mut spread);
                assert_eq!(plain, spread, "rank {rank}: {coefficients:?}");
            }
        }
        let ring = MatrixRing::new(5);
        let mut plain = vec![0u8; 25];
        let mut spread = vec![0u8; 25];
        let mut lists: Vec<Vec<u8>> = seededElements(5, 5 * 20_000)
            .chunks(5)
            .map(<[u8]>::to_vec)
            .collect();
        // The edges of the last coefficient.
        for first in 0..16 {
            lists.push(vec![first, 1, 2, 3, 0]);
        }
        for coefficients in lists {
            ring.writeSumOfPowers(&coefficients, &mut plain);
            ring.writeSpreadSumOfPowers(&coefficients, &mut spread);
            assert_eq!(plain, spread, "rank 5: {coefficients:?}");
        }
    }
}
