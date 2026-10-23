use crate::Parameters;
use crate::galoisField::GaloisField;
use alloc::vec;
use alloc::vec::Vec;

/// The Goppa polynomial of a secret key: the minimal polynomial over GF(2^m) of a random
/// element of GF((2^m)^t), `genpoly_gen` of `sk_gen.c`, with the product `GF_mul` of `gf.c`.
pub(crate) struct GoppaPolynomial<'parameters> {
    parameters: &'parameters Parameters,
    field: GaloisField,
}

impl<'parameters> GoppaPolynomial<'parameters> {
    /// Makes the generator of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        GoppaPolynomial {
            parameters,
            field: parameters.field(),
        }
    }

    /// The product of two elements of GF((2^m)^t), `GF_mul`: the product of the polynomials,
    /// with each term from `y^t` up replaced by the terms of the field polynomial, from the top
    /// term down.
    pub(crate) fn extensionProduct(&self, left: &[u16], right: &[u16]) -> Vec<u16> {
        let degree = self.parameters.errorWeight;
        let field = self.field;
        let mut product = vec![0u16; 2 * degree - 1];
        for (leftIndex, leftValue) in left.iter().enumerate() {
            for (rightIndex, rightValue) in right.iter().enumerate() {
                product[leftIndex + rightIndex] ^= field.product(*leftValue, *rightValue);
            }
        }
        for index in (degree..2 * degree - 1).rev() {
            let term = product[index];
            for (exponent, coefficient) in self.parameters.reductionTerms {
                // The C code adds a term with the coefficient 1 as it is.
                product[index - degree + exponent] ^= if *coefficient == 1 {
                    term
                } else {
                    field.product(term, *coefficient)
                };
            }
        }
        product.truncate(degree);
        product
    }

    /// The minimal polynomial of an element of GF((2^m)^t), `genpoly_gen`: the `t` coefficients
    /// below the leading 1, or `None` when the powers of the element are not independent.
    ///
    /// The Gaussian elimination over GF(2^m) adds the rows of a column below the diagonal with
    /// masks, and stops when a diagonal value stays zero, as the C code does.
    pub(crate) fn minimalPolynomial(&self, element: &[u16]) -> Option<Vec<u16>> {
        let degree = self.parameters.errorWeight;
        let field = self.field;
        // `matrix[power][row]`, as `mat` of the C code: the powers 0 to t of the element.
        let mut matrix = vec![vec![0u16; degree]; degree + 1];
        matrix[0][0] = 1;
        matrix[1].copy_from_slice(element);
        for power in 2..=degree {
            matrix[power] = self.extensionProduct(&matrix[power - 1], element);
        }
        for column in 0..degree {
            for row in column + 1..degree {
                let mask = GaloisField::zeroMask(matrix[column][column]);
                for entry in matrix[column..].iter_mut() {
                    entry[column] ^= entry[row] & mask;
                }
            }
            if matrix[column][column] == 0 {
                return None;
            }
            let inverse = field.inverse(matrix[column][column]);
            for entry in matrix[column..].iter_mut() {
                entry[column] = field.product(entry[column], inverse);
            }
            for row in (0..degree).filter(|row| *row != column) {
                let factor = matrix[column][row];
                for entry in matrix[column..].iter_mut() {
                    entry[row] ^= field.product(entry[column], factor);
                }
            }
        }
        matrix.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::GoppaPolynomial;
    use crate::parameters::allParameters;
    use crate::testSupport::{SeededWords, digest};

    /// The element of GF((2^m)^t) of a seed, `t` values below `2^m`.
    fn seededElement(seed: u64, degree: usize, mask: u16) -> Vec<u16> {
        let mut words = SeededWords::new(seed);
        (0..degree).map(|_| words.next() as u16 & mask).collect()
    }

    #[test]
    fn theExtensionProductOfOneAndOfTheGeneratorReducesByTheFieldPolynomial() {
        for parameters in allParameters.iter().step_by(2) {
            let generator = GoppaPolynomial::new(parameters);
            let degree = parameters.errorWeight;
            let element = seededElement(3, degree, parameters.field().mask());
            let mut one = vec![0u16; degree];
            one[0] = 1;
            assert_eq!(generator.extensionProduct(&element, &one), element);
            // y^(t - 1) times y is y^t, the sum of the reduction terms.
            let mut top = vec![0u16; degree];
            top[degree - 1] = 1;
            let mut variable = vec![0u16; degree];
            variable[1] = 1;
            let mut expected = vec![0u16; degree];
            for (exponent, coefficient) in parameters.reductionTerms {
                expected[*exponent] = *coefficient;
            }
            assert_eq!(generator.extensionProduct(&top, &variable), expected);
        }
    }

    #[test]
    fn theMinimalPolynomialHasTheElementAsARoot() {
        // g(f) = f^t + g[t - 1] f^(t - 1) + ... + g[0] is zero in GF((2^m)^t).
        for parameters in allParameters.iter().step_by(2) {
            let generator = GoppaPolynomial::new(parameters);
            let degree = parameters.errorWeight;
            let element = seededElement(11, degree, parameters.field().mask());
            let polynomial = generator
                .minimalPolynomial(&element)
                .expect("a random element has a minimal polynomial of degree t");
            let mut power = vec![0u16; degree];
            power[0] = 1;
            let mut total = vec![0u16; degree];
            for coefficient in polynomial.iter().chain([&1]) {
                let mut scaled = vec![0u16; degree];
                scaled[0] = *coefficient;
                for (sum, term) in total
                    .iter_mut()
                    .zip(generator.extensionProduct(&power, &scaled))
                {
                    *sum ^= term;
                }
                power = generator.extensionProduct(&power, &element);
            }
            assert!(total.iter().all(|value| *value == 0));
        }
    }

    #[test]
    fn anElementOfTheBaseFieldHasNoMinimalPolynomialOfDegreeT() {
        // Its powers all lie in GF(2^m), so the second column of the elimination stays zero.
        for parameters in allParameters.iter().step_by(2) {
            let mut element = vec![0u16; parameters.errorWeight];
            element[0] = 7;
            assert_eq!(
                GoppaPolynomial::new(parameters).minimalPolynomial(&element),
                None
            );
        }
    }

    #[test]
    fn productsAndMinimalPolynomialsGiveTheKnownAnswersOfTheCFunctions() {
        // The SHA3-256 of the outputs of `GF_mul` and `genpoly_gen` of the five base sets in
        // liboqs 0.16.0, as little-endian 16-bit values. `GF_mul` multiplies the elements of the
        // seeds 2k and 2k + 1 for k from 0 to 15, and `genpoly_gen` takes the elements of the
        // seeds 100 to 103. A refused element would add the value 0xFFFF.
        let expected = [
            (
                "2d946c8c3df311548ebbbbaaaf3f3bfd76d922926ba2e18d2e7a873c89e2f4cd",
                "f8f6e156c2cc9470a74f635a7e1a8a5bfc840a4a02cd38ec2595af6f0b091e00",
            ),
            (
                "88193b4d062ea5f34d0b0ec223b74b38d85d7950cc56762fdc145f3ee2a394cb",
                "675c07d51beda660b6a60f0acde89d1ce2b917fc26700ce5c2527caa5c3ef708",
            ),
            (
                "d400f71284781784f9d1d440bf7bd7cfac32e36e53ec62445034ba55beed4d3e",
                "0db6968735c9e8e3195ed879881b43f30a039a086c7767f8a95a388c952ad7fa",
            ),
            (
                "b164885f18bdb04875864d3c5583fc5fe0ef25d817c130e32e0f9fd99f15ee1d",
                "676822ccdcb9580d6394c9ec8b6bb6d7ea97caf504427246415a3b2986279dfa",
            ),
            (
                "d400f71284781784f9d1d440bf7bd7cfac32e36e53ec62445034ba55beed4d3e",
                "0db6968735c9e8e3195ed879881b43f30a039a086c7767f8a95a388c952ad7fa",
            ),
        ];
        for (parameters, (productDigest, polynomialDigest)) in
            allParameters.iter().step_by(2).zip(expected)
        {
            let generator = GoppaPolynomial::new(parameters);
            let degree = parameters.errorWeight;
            let mask = parameters.field().mask();
            let mut products = Vec::new();
            for pair in 0..16 {
                let left = seededElement(2 * pair, degree, mask);
                let right = seededElement(2 * pair + 1, degree, mask);
                for value in generator.extensionProduct(&left, &right) {
                    products.extend(value.to_le_bytes());
                }
            }
            let mut polynomials = Vec::new();
            for seed in 100..104 {
                match generator.minimalPolynomial(&seededElement(seed, degree, mask)) {
                    Some(polynomial) => {
                        for value in polynomial {
                            polynomials.extend(value.to_le_bytes());
                        }
                    }
                    None => polynomials.extend(0xFFFFu16.to_le_bytes()),
                }
            }
            let name = parameters.description.name;
            assert_eq!(digest(&products), productDigest, "{name}");
            assert_eq!(digest(&polynomials), polynomialDigest, "{name}");
        }
    }
}
