use crate::galoisField::{GaloisField, multiplicativeOrder};

/// The additive FFT over GF(2^8) of the Reed-Solomon decoder, `fft.c` of the reference code.
///
/// The transform follows Gao and Mateer, with the radix conversion of Bernstein, Chou and
/// Schwabe. It evaluates the error locator polynomial at every element of the field, and the
/// roots give the error positions.
pub(crate) struct AdditiveFFT;

/// The number of field elements, `2^m` for the degree `m = 8` of the field.
pub(crate) const fieldSize: usize = 256;

/// Half the number of field elements.
const halfFieldSize: usize = fieldSize / 2;

/// The basis without 1 of the first level, `compute_fft_betas`: `2^7`, `2^6` and so on to 2.
const firstBasis: [u8; 7] = [128, 64, 32, 16, 8, 4, 2];

impl AdditiveFFT {
    /// The values of a polynomial at the 256 field elements, `fft`.
    ///
    /// The polynomial has `2^exponent` coefficients, of which the first `coefficientCount` can
    /// be nonzero. Entry `i` below 128 is the value at the sum of the basis elements that the
    /// bits of `i` select, and entry `128 + i` is the value at that sum plus 1.
    pub(crate) fn evaluations(
        polynomial: &[u8],
        coefficientCount: usize,
        exponent: u32,
    ) -> [u8; fieldSize] {
        let sums = subsetSums::<halfFieldSize>(&firstBasis);
        let half = 1 << (exponent - 1);
        let mut low = [0u8; 16];
        let mut high = [0u8; 16];
        radix(&mut low[..half], &mut high[..half], polynomial, exponent);
        let deltas = firstBasis.map(|element| GaloisField::square(element) ^ element);
        let mut lowValues = [0u8; halfFieldSize];
        let mut highValues = [0u8; halfFieldSize];
        recursiveEvaluations(
            &mut lowValues,
            &mut low[..half],
            coefficientCount.div_ceil(2),
            exponent - 1,
            &deltas,
        );
        recursiveEvaluations(
            &mut highValues,
            &mut high[..half],
            coefficientCount / 2,
            exponent - 1,
            &deltas,
        );
        let mut values = [0u8; fieldSize];
        values[halfFieldSize..].copy_from_slice(&highValues);
        values[0] = lowValues[0];
        values[halfFieldSize] ^= lowValues[0];
        for index in 1..halfFieldSize {
            values[index] = lowValues[index] ^ GaloisField::product(sums[index], highValues[index]);
            values[halfFieldSize + index] ^= values[index];
        }
        values
    }

    /// The error positions of the values of an error locator polynomial,
    /// `fft_retrieve_error_poly`: entry `j` is 1 when `alpha^-j` is a root.
    pub(crate) fn errorPositions(values: &[u8; fieldSize]) -> [u8; fieldSize] {
        let sums = subsetSums::<halfFieldSize>(&firstBasis);
        let mut positions = [0u8; fieldSize];
        positions[0] ^= isZero(values[0]);
        positions[0] ^= isZero(values[halfFieldSize]);
        for index in 1..halfFieldSize {
            let position = multiplicativeOrder - GaloisField::logarithm(sums[index]);
            positions[position] ^= isZero(values[index]);
            let position = multiplicativeOrder - GaloisField::logarithm(sums[index] ^ 1);
            positions[position] ^= isZero(values[halfFieldSize + index]);
        }
        positions
    }
}

/// 1 for a zero value and 0 for any other, with no branch, as `1 ^ ((uint16_t)-w >> 15)`.
fn isZero(value: u8) -> u8 {
    1 ^ (u16::from(value).wrapping_neg() >> 15) as u8
}

/// The sums of the subsets of a set, `compute_subset_sums`: entry `i` is the sum of the elements
/// that the bits of `i` select. `Count` is `2^set.len()`.
fn subsetSums<const Count: usize>(set: &[u8]) -> [u8; Count] {
    let mut sums = [0u8; Count];
    for (index, element) in set.iter().enumerate() {
        let size = 1 << index;
        for low in 0..size {
            sums[size + low] = element ^ sums[low];
        }
    }
    sums
}

/// The radix conversion of a polynomial of `2^exponent` coefficients, `radix`: the halves `low`
/// and `high` with `f(x) = low(x^2 + x) + x high(x^2 + x)`.
fn radix(low: &mut [u8], high: &mut [u8], f: &[u8], exponent: u32) {
    match exponent {
        4 => {
            low[4] = f[8] ^ f[12];
            low[6] = f[12] ^ f[14];
            low[7] = f[14] ^ f[15];
            high[5] = f[11] ^ f[13];
            high[6] = f[13] ^ f[14];
            high[7] = f[15];
            low[5] = f[10] ^ f[12] ^ high[5];
            high[4] = f[9] ^ f[13] ^ low[5];
            low[0] = f[0];
            high[3] = f[7] ^ f[11] ^ f[15];
            low[3] = f[6] ^ f[10] ^ f[14] ^ high[3];
            low[2] = f[4] ^ low[4] ^ low[3] ^ high[3];
            high[1] = f[3] ^ f[5] ^ f[9] ^ f[13] ^ high[3];
            high[2] = f[3] ^ high[1] ^ low[3];
            low[1] = f[2] ^ low[2] ^ high[1];
            high[0] = f[1] ^ low[1];
        }
        3 => {
            low[0] = f[0];
            low[2] = f[4] ^ f[6];
            low[3] = f[6] ^ f[7];
            high[1] = f[3] ^ f[5] ^ f[7];
            high[2] = f[5] ^ f[6];
            high[3] = f[7];
            low[1] = f[2] ^ low[2] ^ high[1];
            high[0] = f[1] ^ low[1];
        }
        2 => {
            low[0] = f[0];
            low[1] = f[2] ^ f[3];
            high[0] = f[1] ^ low[1];
            high[1] = f[3];
        }
        1 => {
            low[0] = f[0];
            high[0] = f[1];
        }
        _ => radixOfManyCoefficients(low, high, f, exponent),
    }
}

/// The radix conversion of a polynomial of 32 or more coefficients, `radix_big`, from two
/// conversions of half the size.
fn radixOfManyCoefficients(low: &mut [u8], high: &mut [u8], f: &[u8], exponent: u32) {
    let quarter = 1 << (exponent - 2);
    let mut upper = [0u8; 16];
    let mut lower = [0u8; 16];
    upper[..quarter].copy_from_slice(&f[3 * quarter..4 * quarter]);
    upper[quarter..2 * quarter].copy_from_slice(&f[3 * quarter..4 * quarter]);
    lower[..2 * quarter].copy_from_slice(&f[..2 * quarter]);
    for index in 0..quarter {
        upper[index] ^= f[2 * quarter + index];
        lower[quarter + index] ^= upper[index];
    }
    let mut upperLow = [0u8; 8];
    let mut upperHigh = [0u8; 8];
    let mut lowerLow = [0u8; 8];
    let mut lowerHigh = [0u8; 8];
    radix(
        &mut upperLow[..quarter],
        &mut upperHigh[..quarter],
        &upper[..2 * quarter],
        exponent - 1,
    );
    radix(
        &mut lowerLow[..quarter],
        &mut lowerHigh[..quarter],
        &lower[..2 * quarter],
        exponent - 1,
    );
    low[..quarter].copy_from_slice(&lowerLow[..quarter]);
    low[quarter..2 * quarter].copy_from_slice(&upperLow[..quarter]);
    high[..quarter].copy_from_slice(&lowerHigh[..quarter]);
    high[quarter..2 * quarter].copy_from_slice(&upperHigh[..quarter]);
}

/// The values of a polynomial at the subset sums of a basis, `fft_rec`.
///
/// `values` holds `2^basis.len()` entries. The polynomial holds `2^exponent` coefficients, of
/// which the first `coefficientCount` can be nonzero, and the twist of the second step changes
/// it in place.
fn recursiveEvaluations(
    values: &mut [u8],
    polynomial: &mut [u8],
    coefficientCount: usize,
    exponent: u32,
    basis: &[u8],
) {
    let basisLength = basis.len();
    // Step 1: a polynomial of degree 1 is a constant plus a multiple of its point.
    if exponent == 1 {
        let products = basis
            .iter()
            .map(|element| GaloisField::product(*element, polynomial[1]));
        values[0] = polynomial[0];
        let mut filled = 1;
        for product in products {
            for index in 0..filled {
                values[filled + index] = values[index] ^ product;
            }
            filled <<= 1;
        }
        return;
    }
    // Step 2: the twist `f(beta_m x)`, unless the last basis element is 1.
    let lastElement = basis[basisLength - 1];
    if lastElement != 1 {
        let mut power = 1u8;
        for coefficient in &mut polynomial[1..1 << exponent] {
            power = GaloisField::product(power, lastElement);
            *coefficient = GaloisField::product(power, *coefficient);
        }
    }
    // Step 3.
    let half = 1 << (exponent - 1);
    let mut low = [0u8; 8];
    let mut high = [0u8; 8];
    radix(&mut low[..half], &mut high[..half], polynomial, exponent);
    // Step 4: the next basis is the basis over its last element, and the deltas of it.
    let mut gammas = [0u8; 6];
    let mut deltas = [0u8; 6];
    let lastInverse = GaloisField::inverse(lastElement);
    let elements = &basis[..basisLength - 1];
    for ((gamma, delta), element) in gammas.iter_mut().zip(deltas.iter_mut()).zip(elements) {
        *gamma = GaloisField::product(*element, lastInverse);
        *delta = GaloisField::square(*gamma) ^ *gamma;
    }
    let nextLength = basisLength - 1;
    let sums = subsetSums::<64>(&gammas[..nextLength]);
    // Step 5.
    let size = 1 << nextLength;
    let mut lowValues = [0u8; 64];
    recursiveEvaluations(
        &mut lowValues[..size],
        &mut low[..half],
        coefficientCount.div_ceil(2),
        exponent - 1,
        &deltas[..nextLength],
    );
    if coefficientCount <= 3 {
        // A polynomial of at most three coefficients has a constant high half.
        values[0] = lowValues[0];
        values[size] = lowValues[0] ^ high[0];
        for index in 1..size {
            values[index] = lowValues[index] ^ GaloisField::product(sums[index], high[0]);
            values[size + index] = values[index] ^ high[0];
        }
    } else {
        let mut highValues = [0u8; 64];
        recursiveEvaluations(
            &mut highValues[..size],
            &mut high[..half],
            coefficientCount / 2,
            exponent - 1,
            &deltas[..nextLength],
        );
        // Step 6.
        values[size..2 * size].copy_from_slice(&highValues[..size]);
        values[0] = lowValues[0];
        values[size] ^= lowValues[0];
        for index in 1..size {
            values[index] = lowValues[index] ^ GaloisField::product(sums[index], highValues[index]);
            values[size + index] ^= values[index];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AdditiveFFT, fieldSize, firstBasis, halfFieldSize, subsetSums};
    use crate::galoisField::GaloisField;

    /// The value of a polynomial at a point by Horner's rule.
    fn value(polynomial: &[u8], point: u8) -> u8 {
        polynomial.iter().rev().fold(0u8, |total, coefficient| {
            GaloisField::product(total, point) ^ coefficient
        })
    }

    /// The point of each entry of the evaluations.
    fn points() -> [u8; fieldSize] {
        let sums = subsetSums::<halfFieldSize>(&firstBasis);
        core::array::from_fn(|index| {
            if index < halfFieldSize {
                sums[index]
            } else {
                sums[index - halfFieldSize] ^ 1
            }
        })
    }

    /// A seeded polynomial whose coefficients above `coefficientCount` are zero.
    fn polynomialFrom(seed: u32, coefficientCount: usize, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|index| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                if index < coefficientCount {
                    (state >> 16) as u8
                } else {
                    0
                }
            })
            .collect()
    }

    #[test]
    fn evaluationsAreTheValuesAtEveryFieldElement() {
        let points = points();
        // The points are every element of the field once.
        let mut sorted = points.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..=255).collect::<Vec<u8>>());
        // The locator polynomials of HQC-1, HQC-3 and HQC-5 have at most 16, 17 and 30
        // coefficients in 16, 32 and 32 places.
        for (coefficientCount, exponent) in [(16, 4u32), (17, 5), (30, 5), (5, 4), (1, 5)] {
            for seed in 0..20 {
                let polynomial = polynomialFrom(seed, coefficientCount, 1 << exponent);
                let values = AdditiveFFT::evaluations(&polynomial, coefficientCount, exponent);
                for (point, actual) in points.iter().zip(values) {
                    assert_eq!(
                        actual,
                        value(&polynomial, *point),
                        "{coefficientCount} coefficients, seed {seed}, point {point}"
                    );
                }
            }
        }
    }

    #[test]
    fn errorPositionsAreTheInverseLogarithmsOfTheRoots() {
        // `(1 + alpha^3 x)(1 + alpha^40 x)(1 + x)` has the roots `alpha^-3`, `alpha^-40` and 1.
        let mut polynomial = vec![1u8];
        for exponent in [3, 40, 0] {
            let factor = GaloisField::power(exponent);
            let mut next = vec![0u8; polynomial.len() + 1];
            for (degree, coefficient) in polynomial.iter().enumerate() {
                next[degree] ^= coefficient;
                next[degree + 1] ^= GaloisField::product(*coefficient, factor);
            }
            polynomial = next;
        }
        polynomial.resize(16, 0);
        let values = AdditiveFFT::evaluations(&polynomial, 16, 4);
        let positions = AdditiveFFT::errorPositions(&values);
        let found: Vec<usize> = (0..fieldSize)
            .filter(|index| positions[*index] == 1)
            .collect();
        assert_eq!(found, vec![0, 3, 40]);
        assert!(positions.iter().all(|position| *position <= 1));
        // A constant polynomial has no root.
        let mut constant = [0u8; 32];
        constant[0] = 7;
        let none = AdditiveFFT::errorPositions(&AdditiveFFT::evaluations(&constant, 1, 5));
        assert!(none.iter().all(|position| *position == 0));
    }

    #[test]
    fn subsetSumsAddTheElementsThatTheBitsSelect() {
        let sums = subsetSums::<8>(&[1, 2, 4]);
        assert_eq!(sums, [0, 1, 2, 3, 4, 5, 6, 7]);
        let sums = subsetSums::<4>(&[0x30, 0x0C]);
        assert_eq!(sums, [0, 0x30, 0x0C, 0x3C]);
    }
}
