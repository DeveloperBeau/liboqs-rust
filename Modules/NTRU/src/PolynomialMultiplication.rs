use crate::{MultiplicationMethod, Parameters};
use alloc::vec;
use alloc::vec::Vec;

/// The product of two polynomials modulo `x^n - 1` with 16-bit coefficients that wrap,
/// `poly_Rq_mul` of `poly_rq_mul.c`.
///
/// The C code pads each factor to `L = 32 ceil(n / 32)` coefficients and splits it into four
/// parts of `M = L / 4`, and each part into four parts of `K = L / 16`. Toom-Cook evaluates
/// the four parts at seven points, and four layers of Karatsuba at nine combinations. Below
/// that, two layers of Karatsuba give nine products of `K` coefficients by the schoolbook
/// method. The port keeps every step, so each 16-bit coefficient of the result is the
/// coefficient of the C code, also in the bits that the division steps of Toom-Cook lose.
pub(crate) struct PolynomialMultiplication;

/// The weights of the four parts of a factor at the evaluation points of `toom4_k2x2_mul`:
/// `0`, `1`, `-1`, `2`, `-2`, `3` and infinity, in the order of the products.
const toomCookPoints: [[u16; 4]; 7] = [
    [1, 0, 0, 0],
    [1, 1, 1, 1],
    [1, 0xFFFF, 1, 0xFFFF],
    [1, 2, 4, 8],
    [1, 0xFFFE, 4, 0xFFF8],
    [1, 3, 9, 27],
    [0, 0, 0, 1],
];

/// The weights of the four parts of a factor for the nine products of `k2x4_mul`: the
/// evaluations `00`, `0inf`, `inf0`, `infinf`, `01`, `1inf`, `10`, `inf1` and `11`, in the
/// order of the products.
const karatsubaPoints: [[u16; 4]; 9] = [
    [1, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1],
    [1, 1, 0, 0],
    [0, 1, 0, 1],
    [1, 0, 1, 0],
    [0, 0, 1, 1],
    [1, 1, 1, 1],
];

/// The inverse of 3 modulo `2^16`.
const inverseOfThree: u16 = 43691;

/// The inverse of 5 modulo `2^16`.
const inverseOfFive: u16 = 52429;

impl PolynomialMultiplication {
    /// The product of two polynomials of `n` coefficients modulo `x^n - 1`, each coefficient
    /// modulo `2^16`, as the method of the set computes it.
    pub(crate) fn product(parameters: &Parameters, left: &[u16], right: &[u16]) -> Vec<u16> {
        let count = parameters.coefficientCount;
        debug_assert_eq!(left.len(), count);
        debug_assert_eq!(right.len(), count);
        let paddedCount = count.div_ceil(32) * 32;
        let mut leftPadded = vec![0u16; paddedCount];
        leftPadded[..count].copy_from_slice(left);
        let mut rightPadded = vec![0u16; paddedCount];
        rightPadded[..count].copy_from_slice(right);
        let full = match parameters.multiplicationMethod {
            MultiplicationMethod::toomCook => Self::toomCookProduct(&leftPadded, &rightPadded),
            MultiplicationMethod::karatsuba => Self::karatsubaProduct(&leftPadded, &rightPadded),
        };
        // The coefficients from n up fold back onto the coefficients from 0, as x^n = 1.
        (0..count)
            .map(|index| full[index].wrapping_add(full[count + index]))
            .collect()
    }

    /// `toom4_k2x2_mul`: the product of two padded factors of `L` coefficients, `2 L`
    /// coefficients.
    fn toomCookProduct(left: &[u16], right: &[u16]) -> Vec<u16> {
        let partLength = left.len() / 16;
        let products: Vec<Vec<u16>> = toomCookPoints
            .iter()
            .map(|weights| Self::evaluatedProduct(left, right, weights))
            .collect();
        let mut result = vec![0u16; 2 * left.len()];
        Self::toomCookInterpolation(&mut result, &products, partLength);
        result
    }

    /// `k2x4_mul`: the product of two padded factors of `L` coefficients, `2 L` coefficients.
    fn karatsubaProduct(left: &[u16], right: &[u16]) -> Vec<u16> {
        let partLength = left.len() / 16;
        let products: Vec<Vec<u16>> = karatsubaPoints
            .iter()
            .map(|weights| Self::evaluatedProduct(left, right, weights))
            .collect();
        let mut result = vec![0u16; 2 * left.len()];
        Self::karatsubaInterpolation(&mut result, &products, partLength);
        result
    }

    /// The nine base products of two layers of Karatsuba of the two factors at one point:
    /// `toom4_k2x2_eval_*` or `k2x4_eval_*` of each factor and then `toom4_k2x2_basemul`.
    fn evaluatedProduct(left: &[u16], right: &[u16], weights: &[u16; 4]) -> Vec<u16> {
        let partLength = left.len() / 16;
        let leftValue = Self::evaluation(left, weights);
        let rightValue = Self::evaluation(right, weights);
        let mut products = vec![0u16; 18 * partLength];
        for (index, product) in products.chunks_exact_mut(2 * partLength).enumerate() {
            let range = index * partLength..(index + 1) * partLength;
            Self::schoolbookProduct(product, &leftValue[range.clone()], &rightValue[range]);
        }
        products
    }

    /// The weighted sum of the four parts of `M` coefficients of a factor, followed by
    /// `k2x2_eval`: `9 K` coefficients.
    fn evaluation(factor: &[u16], weights: &[u16; 4]) -> Vec<u16> {
        let quarterLength = factor.len() / 4;
        let partLength = factor.len() / 16;
        let mut value = vec![0u16; 9 * partLength];
        for (index, coefficient) in value[..quarterLength].iter_mut().enumerate() {
            *coefficient = weights
                .iter()
                .enumerate()
                .fold(0u16, |sum, (part, weight)| {
                    sum.wrapping_add(weight.wrapping_mul(factor[part * quarterLength + index]))
                });
        }
        Self::karatsubaEvaluation(&mut value, partLength);
        value
    }

    /// `k2x2_eval`: from the parts `e`, `f`, `g` and `h` of `K` coefficients, the nine factors
    /// `e`, `f`, `g`, `h`, `e + f`, `f + h`, `g + e`, `h + g` and `e + f + g + h`.
    fn karatsubaEvaluation(value: &mut [u16], partLength: usize) {
        let k = partLength;
        value.copy_within(0..4 * k, 4 * k);
        for index in 0..k {
            value[4 * k + index] = value[4 * k + index].wrapping_add(value[k + index]);
            value[5 * k + index] = value[5 * k + index].wrapping_add(value[3 * k + index]);
            value[6 * k + index] = value[6 * k + index].wrapping_add(value[index]);
            value[7 * k + index] = value[7 * k + index].wrapping_add(value[2 * k + index]);
            value[8 * k + index] = value[5 * k + index].wrapping_add(value[6 * k + index]);
        }
    }

    /// `schoolbook_KxK`: the product of two factors of `K` coefficients, `2 K` coefficients
    /// with the last one zero.
    fn schoolbookProduct(product: &mut [u16], left: &[u16], right: &[u16]) {
        let k = left.len();
        for (index, coefficient) in product[..k].iter_mut().enumerate() {
            *coefficient = left[0].wrapping_mul(right[index]);
        }
        for leftIndex in 1..k {
            for rightIndex in 0..k - 1 {
                product[leftIndex + rightIndex] = product[leftIndex + rightIndex]
                    .wrapping_add(left[leftIndex].wrapping_mul(right[rightIndex]));
            }
            product[leftIndex + k - 1] = left[leftIndex].wrapping_mul(right[k - 1]);
        }
        product[2 * k - 1] = 0;
    }

    /// `k2x2_interpolate`: the product of two factors of `M` coefficients, `2 M` coefficients,
    /// from their nine base products of `18 K` coefficients.
    fn karatsubaCombination(result: &mut [u16], products: &[u16], partLength: usize) {
        let k = partLength;
        result[..2 * k].copy_from_slice(&products[..2 * k]);
        result[2 * k..4 * k].copy_from_slice(&products[2 * k..4 * k]);
        for index in 0..2 * k {
            result[k + index] = result[k + index].wrapping_add(
                products[8 * k + index]
                    .wrapping_sub(products[index])
                    .wrapping_sub(products[2 * k + index]),
            );
        }
        result[4 * k..6 * k].copy_from_slice(&products[4 * k..6 * k]);
        result[6 * k..8 * k].copy_from_slice(&products[6 * k..8 * k]);
        for index in 0..2 * k {
            result[5 * k + index] = result[5 * k + index].wrapping_add(
                products[14 * k + index]
                    .wrapping_sub(products[4 * k + index])
                    .wrapping_sub(products[6 * k + index]),
            );
        }
        let mut middle = vec![0u16; 4 * k];
        middle[..2 * k].copy_from_slice(&products[12 * k..14 * k]);
        middle[2 * k..].copy_from_slice(&products[10 * k..12 * k]);
        for index in 0..2 * k {
            middle[k + index] = middle[k + index].wrapping_add(
                products[16 * k + index]
                    .wrapping_sub(products[12 * k + index])
                    .wrapping_sub(products[10 * k + index]),
            );
        }
        for index in 0..4 * k {
            middle[index] = middle[index]
                .wrapping_sub(result[index])
                .wrapping_sub(result[4 * k + index]);
        }
        for index in 0..4 * k {
            result[2 * k + index] = result[2 * k + index].wrapping_add(middle[index]);
        }
    }

    /// `toom4_k2x2_interpolate`: the product of `2 L` coefficients from the products at the
    /// seven points, with the 32-bit shifts of the C code.
    fn toomCookInterpolation(result: &mut [u16], products: &[Vec<u16>], partLength: usize) {
        let m = 4 * partLength;
        let combined = |index: usize| {
            let mut value = vec![0u16; 2 * m];
            Self::karatsubaCombination(&mut value, &products[index], partLength);
            value
        };
        Self::karatsubaCombination(&mut result[..2 * m], &products[0], partLength);
        let mut atOne = combined(1);
        let atMinusOne = combined(2);
        let mut atTwo = combined(3);
        let atMinusTwo = combined(4);
        Self::karatsubaCombination(&mut result[6 * m..8 * m], &products[6], partLength);
        for index in 0..2 * m {
            let c0 = result[index];
            let c6 = result[6 * m + index];
            // The C code shifts the 32-bit value, so the bits above 16 of a sum or of a
            // negative difference reach the result.
            let mut v0 = ((u32::from(atOne[index]) + u32::from(atMinusOne[index])) >> 1) as u16;
            v0 = v0.wrapping_sub(c0).wrapping_sub(c6);
            let v1 = ((i32::from(atTwo[index]) + i32::from(atMinusTwo[index])
                - 2 * i32::from(c0)
                - 128 * i32::from(c6)) as u32
                >> 3) as u16;
            let c4 = inverseOfThree.wrapping_mul(v1.wrapping_sub(v0));
            result[4 * m + index] = c4;
            result[2 * m + index] = v0.wrapping_sub(c4);
            atOne[index] =
                ((i32::from(atOne[index]) - i32::from(atMinusOne[index])) as u32 >> 1) as u16;
        }
        let mut atThree = combined(5);
        for index in 0..2 * m {
            let c0 = result[index];
            let c2 = result[2 * m + index];
            let c4 = result[4 * m + index];
            let c6 = result[6 * m + index];
            let v0 = atOne[index];
            let v1 = inverseOfThree.wrapping_mul(
                (((i32::from(atTwo[index]) - i32::from(atMinusTwo[index])) as u32 >> 2) as u16)
                    .wrapping_sub(v0),
            );
            let mut v2 = inverseOfThree.wrapping_mul(atThree[index].wrapping_sub(c0).wrapping_sub(
                9u16.wrapping_mul(
                    c2.wrapping_add(9u16.wrapping_mul(c4.wrapping_add(9u16.wrapping_mul(c6)))),
                ),
            ));
            v2 = ((i32::from(v2) - i32::from(v0)) as u32 >> 3) as u16;
            v2 = v2.wrapping_sub(v1);
            atThree[index] = inverseOfFive.wrapping_mul(v2);
            atTwo[index] = v1.wrapping_sub(v2);
            atOne[index] = v0.wrapping_sub(atTwo[index]).wrapping_sub(atThree[index]);
        }
        for index in 0..2 * m {
            result[m + index] = result[m + index].wrapping_add(atOne[index]);
            result[3 * m + index] = result[3 * m + index].wrapping_add(atTwo[index]);
            result[5 * m + index] = result[5 * m + index].wrapping_add(atThree[index]);
        }
    }

    /// `k2x4_interpolate`: the product of `2 L` coefficients from the nine products of the
    /// outer two layers of Karatsuba.
    fn karatsubaInterpolation(result: &mut [u16], products: &[Vec<u16>], partLength: usize) {
        let m = 4 * partLength;
        let combined = |index: usize| {
            let mut value = vec![0u16; 2 * m];
            Self::karatsubaCombination(&mut value, &products[index], partLength);
            value
        };
        let (low, high, sum) = (combined(0), combined(1), combined(4));
        result[..2 * m].copy_from_slice(&low);
        result[2 * m..4 * m].copy_from_slice(&high);
        for index in 0..2 * m {
            result[m + index] = result[m + index].wrapping_add(
                sum[index]
                    .wrapping_sub(low[index])
                    .wrapping_sub(high[index]),
            );
        }
        let (low, high, sum) = (combined(2), combined(3), combined(7));
        result[4 * m..6 * m].copy_from_slice(&low);
        result[6 * m..8 * m].copy_from_slice(&high);
        for index in 0..2 * m {
            result[5 * m + index] = result[5 * m + index].wrapping_add(
                sum[index]
                    .wrapping_sub(low[index])
                    .wrapping_sub(high[index]),
            );
        }
        let (low, high, sum) = (combined(6), combined(5), combined(8));
        let mut middle = vec![0u16; 4 * m];
        middle[..2 * m].copy_from_slice(&low);
        middle[2 * m..].copy_from_slice(&high);
        for index in 0..2 * m {
            middle[m + index] = middle[m + index].wrapping_add(
                sum[index]
                    .wrapping_sub(low[index])
                    .wrapping_sub(high[index]),
            );
        }
        for index in 0..4 * m {
            middle[index] = middle[index]
                .wrapping_sub(result[index])
                .wrapping_sub(result[4 * m + index]);
        }
        for index in 0..4 * m {
            result[2 * m + index] = result[2 * m + index].wrapping_add(middle[index]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PolynomialMultiplication;
    use crate::testInputs::{cAnswer, everySet, sequence, valuesDigest};
    use crate::{MultiplicationMethod, Parameters};

    #[test]
    fn eachProductHasTheBitsOfPolyRqMul() {
        for parameters in everySet() {
            let count = parameters.coefficientCount;
            let product = PolynomialMultiplication::product(
                parameters,
                &sequence(count, 1),
                &sequence(count, 2),
            );
            let name = parameters.description.name;
            assert_eq!(valuesDigest(&product), cAnswer(name, "product"), "{name}");
        }
    }

    /// The low bits of the exact product modulo `x^n - 1` in which a product agrees with it.
    fn exactBits(parameters: &Parameters, left: &[u16], right: &[u16]) -> u32 {
        let count = left.len();
        let product = PolynomialMultiplication::product(parameters, left, right);
        (0..count)
            .map(|index| {
                let exact = (0..count).fold(0u16, |sum, place| {
                    sum.wrapping_add(
                        left[place].wrapping_mul(right[(index + count - place) % count]),
                    )
                });
                (exact ^ product[index]).trailing_zeros().min(16)
            })
            .min()
            .expect("coefficients")
    }

    #[test]
    fn toomCookIsExactModuloTwoToTheThirteenAndKaratsubaModuloTwoToTheSixteen() {
        // The C program found the same numbers of exact bits for 20 seeded pairs.
        for parameters in everySet() {
            let count = parameters.coefficientCount;
            let name = parameters.description.name;
            let bits = exactBits(parameters, &sequence(count, 100), &sequence(count, 1100));
            let expected: u32 = cAnswer(name, "exactBits").parse().expect("a number");
            match parameters.multiplicationMethod {
                MultiplicationMethod::toomCook => {
                    assert_eq!(expected, 13, "{name}");
                    // Each seeded pair has a coefficient whose bit 13 is not exact.
                    assert_eq!(bits, 13, "{name}");
                }
                MultiplicationMethod::karatsuba => {
                    assert_eq!((expected, bits), (16, 16), "{name}");
                }
            }
        }
    }

    /// The coefficients modulo `2^13` for Toom-Cook, and all 16 bits for Karatsuba.
    fn exactPart(parameters: &Parameters, polynomial: Vec<u16>) -> Vec<u16> {
        let mask = match parameters.multiplicationMethod {
            MultiplicationMethod::toomCook => 0x1FFF,
            MultiplicationMethod::karatsuba => 0xFFFF,
        };
        polynomial
            .into_iter()
            .map(|coefficient| coefficient & mask)
            .collect()
    }

    #[test]
    fn theProductOfSmallFactorsIsTheCyclicProductInItsExactBits() {
        // x^(n - 1) times x is x^n = 1, and (1 + x) (1 - x) = 1 - x^2.
        for parameters in everySet() {
            let name = parameters.description.name;
            let count = parameters.coefficientCount;
            let mut left = vec![0u16; count];
            let mut right = vec![0u16; count];
            left[count - 1] = 1;
            right[1] = 1;
            let mut one = vec![0u16; count];
            one[0] = 1;
            let product = PolynomialMultiplication::product(parameters, &left, &right);
            assert_eq!(exactPart(parameters, product.clone()), one, "{name}");
            // Toom-Cook sets bits above 13 even for these factors, as the C code does: its
            // coefficient 0 is 32769.
            assert_eq!(
                product == one,
                parameters.multiplicationMethod == MultiplicationMethod::karatsuba,
                "{name}"
            );
            let mut sum = vec![0u16; count];
            sum[..2].copy_from_slice(&[1, 1]);
            let mut difference = vec![0u16; count];
            difference[..2].copy_from_slice(&[1, 0xFFFF]);
            let mut expected = vec![0u16; count];
            expected[0] = 1;
            expected[2] = 0xFFFF;
            let product = PolynomialMultiplication::product(parameters, &sum, &difference);
            assert_eq!(
                exactPart(parameters, product),
                exactPart(parameters, expected),
                "{name}"
            );
        }
    }
}
