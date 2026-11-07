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
    use OQSNativeAlgorithmTests::{FuzzRandom, OutputDigest};

    /// The element of GF((2^m)^t) of a seed, `t` values below `2^m`.
    fn seededElement(seed: u64, degree: usize, mask: u16) -> Vec<u16> {
        let mut words = FuzzRandom::seeded(seed);
        (0..degree)
            .map(|_| words.nextWord() as u16 & mask)
            .collect()
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
        // The `OutputDigest` of the outputs of `GF_mul` and `genpoly_gen` of the five base sets
        // in liboqs 0.16.0, as little-endian 16-bit values. `GF_mul` multiplies the elements of
        // the seeds 2k and 2k + 1 for k from 0 to 15, and `genpoly_gen` takes the elements of
        // the seeds 100 to 103. A refused element would add the value 0xFFFF.
        let expected = [
            (
                "5d80dfd032016acc6230355886cb99a3948b8bf43c7f6477604166399b2c7d61",
                "e4748f65bc68daa093b6799091fbb2535f81d68d01210c02ee84045ceddd8cbe",
            ),
            (
                "0e3d7cd93a3db3905cd42082667f839b1dc14b81b3f5f03fd2808d139bb88cad",
                "16a2b85c9654f3b21987c2ccba83e83ed6f4a9b9730546a760ed6073cccd14d0",
            ),
            (
                "3388791bf3df5bac55821274614165c1be4162082701e929082d2d6706783b43",
                "81eb4fd7126675d24fda3e1af92f9d4e1e9f73506fa21ebff42794e344533461",
            ),
            (
                "280c6219b55567aefb1b4ab2a7069eaa589be34ed62e565dc6b4389347c79c68",
                "4f858bff5452a5365b3beb95f544c8158d49bb8ecac8ef2a857e6c9ebed3cf9d",
            ),
            (
                "3388791bf3df5bac55821274614165c1be4162082701e929082d2d6706783b43",
                "81eb4fd7126675d24fda3e1af92f9d4e1e9f73506fa21ebff42794e344533461",
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
            assert_eq!(OutputDigest::of(&products), productDigest, "{name}");
            assert_eq!(OutputDigest::of(&polynomials), polynomialDigest, "{name}");
        }
    }
}
