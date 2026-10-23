use crate::Parameters;
use crate::fieldArithmetic::{FieldArithmetic, coefficientBits};
use crate::messageHashing::MessageHashing;
use crate::nibblePacking::NibblePacking;
use crate::parameters::{digestLength, saltLength};
use crate::signingKey::SigningKey;
use alloc::vec;
use alloc::vec::Vec;

/// The signature of a digest under a signing key, `sign_digest_core_opt` of `snova_opt.h`, with
/// the spread arithmetic and the loop order of the C code.
pub(crate) struct Signer<'parameters> {
    parameters: &'parameters Parameters,
}

/// The last number of an attempt. The counter `num_sign` of the C code is a byte that stops the
/// loop when it reaches 255.
const lastAttempt: u8 = 254;

/// The matrices A, B, Q1 and Q2 in the spread form, each moved to the equation that uses it in
/// the loop of an attempt: the matrices of equation `i` and term `alpha` go to equation
/// `(alpha + i) mod o`, `i_prime` of `snova.c`.
struct SpreadTerms {
    a: Vec<u32>,
    b: Vec<u32>,
    q1: Vec<u32>,
    q2: Vec<u32>,
}

/// The solution of one attempt: the vinegar values and the oil values in the spread form.
struct Solution {
    vinegar: Vec<u8>,
    oil: Vec<u32>,
}

impl<'parameters> Signer<'parameters> {
    /// Makes the signer of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Signer { parameters }
    }

    /// The equation that uses the matrices of an equation and a term, `i_prime_inv` of
    /// `snova.c`: `(o alpha_count - alpha + i) mod o`.
    fn usingEquation(&self, equation: usize, term: usize) -> usize {
        let oilCount = self.parameters.oilCount;
        (oilCount * self.parameters.termCount() - term + equation) % oilCount
    }

    /// Calls an attempt with the numbers 1 to 254 in turn, and returns the first result, as
    /// the loop of `sign_digest_core_opt` does. `None` when every attempt fails.
    fn firstSolvedAttempt<Result>(attempt: impl FnMut(u8) -> Option<Result>) -> Option<Result> {
        (1..=lastAttempt).find_map(attempt)
    }

    /// The signature of a digest with a salt, or `None` when every attempt fails, the return
    /// value -1 of the C code.
    ///
    /// Each attempt draws the vinegar values from SHAKE256 of the secret seed, the digest, the
    /// salt and its number, and solves the linear system of the oil values. An attempt fails
    /// when the system is singular. The signature is the packed variables, then the salt.
    pub(crate) fn signature(
        &self,
        key: &SigningKey,
        digest: &[u8; digestLength],
        salt: &[u8; saltLength],
    ) -> Option<Vec<u8>> {
        let parameters = self.parameters;
        let (vinegarCount, oilCount, rank) = (
            parameters.vinegarCount,
            parameters.oilCount,
            parameters.rank,
        );
        let squaredRank = parameters.squaredRank();
        let signedHash = MessageHashing::signedHash(
            &key.publicSeed,
            digest,
            salt,
            parameters.signedHashLength(),
        );
        let hashElements = NibblePacking::unpacked(&signedHash, oilCount * squaredRank);
        let spreadT12: Vec<u32> = key
            .t12
            .iter()
            .map(|element| FieldArithmetic::spread(*element))
            .collect();
        let terms = self.spreadTerms(key);
        let solution = Self::firstSolvedAttempt(|attempt| {
            self.attemptedSolution(key, digest, salt, attempt, &hashElements, &terms)
        })?;
        // The vinegar variables become `vinegar + T12 oil`, and the oil variables are the
        // oil values.
        let mut variables = vec![0u8; parameters.signatureElementCount()];
        for vinegarIndex in 0..vinegarCount {
            let mut sums = [0u32; 25];
            for oilIndex in 0..oilCount {
                let t12Start = (vinegarIndex * oilCount + oilIndex) * squaredRank;
                for row in 0..rank {
                    for column in 0..rank {
                        for inner in 0..rank {
                            sums[row * rank + column] ^= spreadT12[t12Start + row * rank + inner]
                                * solution.oil[oilIndex * squaredRank + inner * rank + column];
                        }
                    }
                }
            }
            for index in 0..squaredRank {
                variables[vinegarIndex * squaredRank + index] = solution.vinegar
                    [vinegarIndex * squaredRank + index]
                    ^ FieldArithmetic::element(sums[index]);
            }
        }
        for (variable, oil) in variables[vinegarCount * squaredRank..]
            .iter_mut()
            .zip(&solution.oil)
        {
            *variable = FieldArithmetic::element(*oil);
        }
        let mut signature = NibblePacking::packed(&variables);
        signature.extend_from_slice(salt);
        Some(signature)
    }

    /// The spread matrices of the terms of a key, as `sign_digest_core_opt` reorders them.
    fn spreadTerms(&self, key: &SigningKey) -> SpreadTerms {
        let parameters = self.parameters;
        let squaredRank = parameters.squaredRank();
        let termCount = parameters.termCount();
        let oilCount = parameters.oilCount;
        let length = oilCount * termCount * squaredRank;
        let mut terms = SpreadTerms {
            a: vec![0u32; length],
            b: vec![0u32; length],
            q1: vec![0u32; length],
            q2: vec![0u32; length],
        };
        for equation in 0..oilCount {
            for term in 0..termCount {
                let target = ((term + equation) % oilCount * termCount + term) * squaredRank;
                let source = (equation * termCount + term) * squaredRank;
                for index in 0..squaredRank {
                    terms.q1[target + index] = FieldArithmetic::spread(key.q1[source + index]);
                    terms.q2[target + index] = FieldArithmetic::spread(key.q2[source + index]);
                    terms.a[target + index] = FieldArithmetic::spread(key.a[source + index]);
                    terms.b[target + index] = FieldArithmetic::spread(key.b[source + index]);
                }
            }
        }
        terms
    }

    /// One attempt of the loop of `sign_digest_core_opt`: the vinegar values of its number,
    /// the linear system of the oil values, and its solution, or `None` when the system is
    /// singular.
    fn attemptedSolution(
        &self,
        key: &SigningKey,
        digest: &[u8; digestLength],
        salt: &[u8; saltLength],
        attempt: u8,
        hashElements: &[u8],
        terms: &SpreadTerms,
    ) -> Option<Solution> {
        let parameters = self.parameters;
        let (vinegarCount, oilCount, rank) = (
            parameters.vinegarCount,
            parameters.oilCount,
            parameters.rank,
        );
        let equationCount = oilCount;
        let squaredRank = parameters.squaredRank();
        let termCount = parameters.termCount();
        let vinegarBytes = MessageHashing::vinegarBytes(
            &key.secretSeed,
            digest,
            salt,
            attempt,
            (vinegarCount * squaredRank).div_ceil(2),
        );
        let vinegar = NibblePacking::unpacked(&vinegarBytes, vinegarCount * squaredRank);
        let spreadVinegar: Vec<u32> = vinegar
            .iter()
            .map(|element| FieldArithmetic::spread(*element))
            .collect();
        let centralMap = &key.centralMap;

        // The lengths of the rows of the intermediate arrays of the C code.
        let vinegarLength = vinegarCount * rank;
        let oilLength = oilCount * rank;
        let termLength = termCount * rank;
        let mut vinegarPart = vec![0u32; equationCount * squaredRank];
        let mut oilPart = vec![0u32; equationCount * oilCount * squaredRank * squaredRank];
        let mut termProducts = vec![0u32; termCount * vinegarCount * squaredRank];
        let mut left = vec![0u32; termLength * vinegarLength];
        let mut right = vec![0u32; termLength * vinegarLength];
        let mut oilProducts = vec![0u32; termLength * oilLength];
        let mut oilTerms = vec![0u32; oilCount * termCount * squaredRank];
        // The reduced Left and Right and the spread blocks of F in 16 bits, for the dot
        // products, see `FieldArithmetic::narrowed`.
        let mut narrowLeft = vec![0u16; termLength * vinegarLength];
        let mut narrowRight = vec![0u16; termLength * vinegarLength];
        let mut spreadF = vec![0u16; vinegarLength];
        let spread = |element: u8| FieldArithmetic::narrowed(FieldArithmetic::spread(element));
        let dotProduct = |first: &[u16], second: &[u16]| {
            first.iter().zip(second).fold(0, |sum, (left, right)| {
                sum ^ FieldArithmetic::spreadProduct(*left, *right)
            })
        };
        let mut termSums = vec![0u32; termLength];
        let oilIndex = |equation: usize, oil: usize, first: usize, second: usize, third, fourth| {
            ((((equation * oilCount + oil) * rank + first) * rank + second) * rank + third) * rank
                + fourth
        };

        for equation in 0..equationCount {
            let termStart = equation * termCount * squaredRank;
            // Left: A (V' Q1) for each term and vinegar variable, with the products of
            // `V' Q1` masked to their coefficient bits before the second product.
            termProducts.fill(0);
            for term in 0..termCount {
                for variable in 0..vinegarCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                termProducts[(term * vinegarCount + variable) * squaredRank
                                    + row * rank
                                    + column] ^= spreadVinegar
                                    [variable * squaredRank + inner * rank + row]
                                    * terms.q1
                                        [termStart + term * squaredRank + inner * rank + column];
                            }
                        }
                    }
                }
            }
            for value in termProducts.iter_mut() {
                *value &= coefficientBits;
            }
            for term in 0..termCount {
                for variable in 0..vinegarCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                left[term * rank * vinegarLength
                                    + row * vinegarLength
                                    + variable * rank
                                    + column] ^= terms.a
                                    [termStart + term * squaredRank + row * rank + inner]
                                    * termProducts[(term * vinegarCount + variable) * squaredRank
                                        + inner * rank
                                        + column];
                            }
                        }
                    }
                }
            }
            for (value, narrow) in left.iter_mut().zip(narrowLeft.iter_mut()) {
                *value = FieldArithmetic::reduced(*value);
                *narrow = FieldArithmetic::narrowed(*value);
            }

            // Right: (Q2 V) B, stored transposed, by term, column, variable and row.
            termProducts.fill(0);
            for term in 0..termCount {
                for variable in 0..vinegarCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                termProducts[(term * vinegarCount + variable) * squaredRank
                                    + row * rank
                                    + column] ^= terms.q2
                                    [termStart + term * squaredRank + row * rank + inner]
                                    * spreadVinegar[variable * squaredRank + inner * rank + column];
                            }
                        }
                    }
                }
            }
            for value in termProducts.iter_mut() {
                *value &= coefficientBits;
            }
            for term in 0..termCount {
                for variable in 0..vinegarCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                right[term * rank * vinegarLength
                                    + column * vinegarLength
                                    + variable * rank
                                    + row] ^= termProducts[(term * vinegarCount + variable)
                                    * squaredRank
                                    + row * rank
                                    + inner]
                                    * terms.b
                                        [termStart + term * squaredRank + inner * rank + column];
                            }
                        }
                    }
                }
            }
            for (value, narrow) in right.iter_mut().zip(narrowRight.iter_mut()) {
                *value = FieldArithmetic::reduced(*value);
                *narrow = FieldArithmetic::narrowed(*value);
            }

            // The vinegar part: Left F11 Right, into the equation of each term.
            for vinegarColumn in 0..vinegarCount {
                for column in 0..rank {
                    for variable in 0..vinegarCount {
                        for inner in 0..rank {
                            spreadF[variable * rank + inner] = spread(
                                centralMap.f11[((equation * vinegarCount + variable)
                                    * vinegarCount
                                    + vinegarColumn)
                                    * squaredRank
                                    + inner * rank
                                    + column],
                            );
                        }
                    }
                    for (termRow, value) in termSums.iter_mut().enumerate() {
                        *value = dotProduct(
                            &narrowLeft[termRow * vinegarLength..][..vinegarLength],
                            &spreadF,
                        );
                    }
                    for value in termSums.iter_mut() {
                        *value &= coefficientBits;
                    }
                    for term in 0..termCount {
                        let target = self.usingEquation(equation, term);
                        for row in 0..rank {
                            for secondColumn in 0..rank {
                                vinegarPart[target * squaredRank + row * rank + secondColumn] ^=
                                    termSums[term * rank + row]
                                        * right[(term * rank + secondColumn) * vinegarLength
                                            + vinegarColumn * rank
                                            + column];
                            }
                        }
                    }
                }
            }

            // The coefficients of the oil variables from F12: Left F12, reduced, then
            // times Q2 and masked, then the outer product with B.
            oilProducts.fill(0);
            for oil in 0..oilCount {
                for column in 0..rank {
                    for variable in 0..vinegarCount {
                        for inner in 0..rank {
                            spreadF[variable * rank + inner] = spread(
                                centralMap.f12[((equation * vinegarCount + variable) * oilCount
                                    + oil)
                                    * squaredRank
                                    + inner * rank
                                    + column],
                            );
                        }
                    }
                    for termRow in 0..termLength {
                        oilProducts[termRow * oilLength + oil * rank + column] ^= dotProduct(
                            &narrowLeft[termRow * vinegarLength..][..vinegarLength],
                            &spreadF,
                        );
                    }
                }
            }
            for value in oilProducts.iter_mut() {
                *value = FieldArithmetic::reduced(*value);
            }
            oilTerms.fill(0);
            for oil in 0..oilCount {
                for term in 0..termCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                oilTerms[(oil * termCount + term) * squaredRank
                                    + row * rank
                                    + column] ^= oilProducts
                                    [(term * rank + row) * oilLength + oil * rank + inner]
                                    * terms.q2
                                        [termStart + term * squaredRank + inner * rank + column];
                            }
                        }
                    }
                }
            }
            for value in oilTerms.iter_mut() {
                *value &= coefficientBits;
            }
            for oil in 0..oilCount {
                for term in 0..termCount {
                    let target = self.usingEquation(equation, term);
                    let oilTermStart = (oil * termCount + term) * squaredRank;
                    for row in 0..rank {
                        for column in 0..rank {
                            for secondRow in 0..rank {
                                for secondColumn in 0..rank {
                                    oilPart[oilIndex(
                                        target,
                                        oil,
                                        row,
                                        secondColumn,
                                        secondRow,
                                        column,
                                    )] ^= oilTerms[oilTermStart + row * rank + secondRow]
                                        * terms.b[termStart
                                            + term * squaredRank
                                            + secondColumn * rank
                                            + column];
                                }
                            }
                        }
                    }
                }
            }

            // The coefficients of the oil variables from F21: F21 Right, reduced, then Q1
            // times it and masked, then the outer product with A.
            oilProducts.fill(0);
            oilTerms.fill(0);
            for oil in 0..oilCount {
                for row in 0..rank {
                    for variable in 0..vinegarCount {
                        for inner in 0..rank {
                            spreadF[variable * rank + inner] = spread(
                                centralMap.f21[((equation * oilCount + oil) * vinegarCount
                                    + variable)
                                    * squaredRank
                                    + row * rank
                                    + inner],
                            );
                        }
                    }
                    for termColumn in 0..termLength {
                        oilProducts[termColumn * oilLength + oil * rank + row] ^= dotProduct(
                            &narrowRight[termColumn * vinegarLength..][..vinegarLength],
                            &spreadF,
                        );
                    }
                }
            }
            for value in oilProducts.iter_mut() {
                *value = FieldArithmetic::reduced(*value);
            }
            for oil in 0..oilCount {
                for term in 0..termCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                oilTerms[(oil * termCount + term) * squaredRank
                                    + row * rank
                                    + column] ^= oilProducts
                                    [(term * rank + column) * oilLength + oil * rank + inner]
                                    * terms.q1[termStart + term * squaredRank + row * rank + inner];
                            }
                        }
                    }
                }
            }
            for value in oilTerms.iter_mut() {
                *value &= coefficientBits;
            }
            for oil in 0..oilCount {
                for term in 0..termCount {
                    let target = self.usingEquation(equation, term);
                    let oilTermStart = (oil * termCount + term) * squaredRank;
                    for row in 0..rank {
                        for column in 0..rank {
                            for secondRow in 0..rank {
                                for secondColumn in 0..rank {
                                    oilPart[oilIndex(
                                        target,
                                        oil,
                                        row,
                                        secondColumn,
                                        secondRow,
                                        column,
                                    )] ^= terms.a[termStart
                                        + term * squaredRank
                                        + row * rank
                                        + secondColumn]
                                        * oilTerms[oilTermStart + secondRow * rank + column];
                                }
                            }
                        }
                    }
                }
            }
            left.fill(0);
            right.fill(0);
        }

        // The Gauss matrix: the coefficients of the oil variables, and the signed hash minus
        // the vinegar part in the last column.
        let unknownCount = equationCount * squaredRank;
        let width = unknownCount + 1;
        let mut gauss = vec![0u32; unknownCount * width];
        for (index, element) in hashElements.iter().enumerate() {
            gauss[index * width + unknownCount] = FieldArithmetic::spread(*element);
        }
        for equation in 0..equationCount {
            for oil in 0..oilCount {
                for row in 0..rank {
                    for column in 0..rank {
                        for secondRow in 0..rank {
                            for secondColumn in 0..rank {
                                gauss[(equation * squaredRank + row * rank + column) * width
                                    + oil * squaredRank
                                    + secondRow * rank
                                    + secondColumn] = FieldArithmetic::reduced(
                                    oilPart[oilIndex(
                                        equation,
                                        oil,
                                        row,
                                        secondColumn,
                                        secondRow,
                                        column,
                                    )],
                                );
                            }
                        }
                    }
                }
            }
        }
        for index in 0..unknownCount {
            gauss[index * width + unknownCount] ^= FieldArithmetic::reduced(vinegarPart[index]);
        }
        let oil = Self::solved(&mut gauss, unknownCount)?;
        Some(Solution { vinegar, oil })
    }

    /// The solution of a linear system in the spread form, `unknownCount` rows of the
    /// coefficients and the right side, by the elimination in constant time of
    /// `sign_digest_core_opt`, or `None` when the system is singular.
    ///
    /// A zero pivot gets each later row added, while it stays zero. The elimination runs to the
    /// end also for a singular system, as in the C code.
    fn solved(gauss: &mut [u32], unknownCount: usize) -> Option<Vec<u32>> {
        let width = unknownCount + 1;
        let mut isSingular = false;
        for pivot in 0..unknownCount {
            let pivotRow = pivot * width;
            // All ones while the pivot is zero, and zero once it is not, as `swap` of the C
            // code, where `0 - 1` wraps in 32 bits.
            let mut swapMask = FieldArithmetic::isNonZero(gauss[pivotRow + pivot]).wrapping_sub(1);
            for later in pivot + 1..unknownCount {
                let laterRow = later * width;
                for index in pivot..width {
                    gauss[pivotRow + index] ^= gauss[laterRow + index] & swapMask;
                }
                swapMask = FieldArithmetic::isNonZero(gauss[pivotRow + pivot]).wrapping_sub(1);
            }
            isSingular |= swapMask != 0;
            let inverse = FieldArithmetic::inverse(gauss[pivotRow + pivot]);
            for index in pivot..width {
                gauss[pivotRow + index] =
                    FieldArithmetic::reduced(gauss[pivotRow + index] * inverse);
            }
            for later in pivot + 1..unknownCount {
                let laterRow = later * width;
                let factor =
                    FieldArithmetic::isNonZero(gauss[laterRow + pivot]) * gauss[laterRow + pivot];
                for index in pivot..width {
                    gauss[laterRow + index] = FieldArithmetic::reduced(
                        gauss[laterRow + index] ^ (gauss[pivotRow + index] * factor),
                    );
                }
            }
        }
        if isSingular {
            return None;
        }
        // Back substitution.
        let mut solution = vec![0u32; unknownCount];
        for row in (0..unknownCount).rev() {
            let mut sum = 0u32;
            for index in row + 1..unknownCount {
                sum ^= gauss[row * width + index] * solution[index];
            }
            solution[row] = gauss[row * width + unknownCount] ^ FieldArithmetic::reduced(sum);
        }
        Some(solution)
    }
}

#[cfg(test)]
mod tests {
    use super::{Signer, lastAttempt};
    use crate::fieldArithmetic::FieldArithmetic;
    use crate::keyGenerator::KeyGenerator;
    use crate::nibblePacking::NibblePacking;
    use crate::parameters::{everySet, snova24x5x4};
    use crate::verifier::Verifier;
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The digest of `OutputDigest` of the signature of the digest 100 to 163 with the salt
    /// 200 to 215, under the key of the seed 0 to 47, for each set in the order of
    /// `everySet`, from `sign_digest_ssk` or `sign_digest_esk` of the oracle build of
    /// liboqs.
    const knownAnswers: [&str; 12] = [
        "00664b19b8feae38496626ba7c0cd6758b5e2af1965c976e917529f0b323685e",
        "9b4c8f5d480850c49b4426220febf9b68cad53669d437d7e59decb3640193d49",
        "00664b19b8feae38496626ba7c0cd6758b5e2af1965c976e917529f0b323685e",
        "9b4c8f5d480850c49b4426220febf9b68cad53669d437d7e59decb3640193d49",
        "d549b2fe6aa6c6ed7e291e54e14f192928520dd04c0272e256e7538658baa07b",
        "5e66bf429268c030b5a7b13763727acbd17bc8cf33b2e064b7792c5ffa870e68",
        "c8a2f7af22a773a8a729f76d2dc5c249b976e2d6cf9510ffa93709af4b2f979d",
        "3b0d2cdf71e993560c311c3be2a4e7155a5675433da02b969a6c0f71c3b7b803",
        "d06d55f093b52ea099999ad482493ecf8b2173bd14d13e8cfda6f849fca1c212",
        "6f180f0a528ebbce9b4bc014d7747b36e1d0c95943d700df86407999bb99d541",
        "b65354342be29f33edd23a42725354d141bc96f480352c2839c0b76f4fd38c66",
        "b05f9f6a8e588f61dbab7de4de839741de036ca65f79176cc1c98f4ae008b1b5",
    ];

    #[test]
    fn theSignatureOfADigestIsTheSignatureOfTheCFunction() {
        let seeds: [u8; 48] = core::array::from_fn(|index| index as u8);
        let digest: [u8; 64] = core::array::from_fn(|index| 100 + index as u8);
        let salt: [u8; 16] = core::array::from_fn(|index| 200 + index as u8);
        for (parameters, expected) in everySet.into_iter().zip(knownAnswers) {
            let name = parameters.description.name;
            let generator = KeyGenerator::new(parameters);
            let (publicKey, secretKey) = generator.keyPair(&seeds);
            let key = generator.signingKey(&secretKey);
            let signature = Signer::new(parameters)
                .signature(&key, &digest, &salt)
                .expect("a signature");
            assert_eq!(signature.len(), parameters.description.signatureLength);
            assert_eq!(OutputDigest::of(&signature), expected, "{name}");
            assert_eq!(signature[signature.len() - 16..], salt, "{name}");
            // `verify_signture` of the C code accepts it.
            let verifier = Verifier::new(parameters);
            assert!(
                verifier.isValidSignature(&signature, &digest, &publicKey),
                "{name}"
            );
            let mut otherDigest = digest;
            otherDigest[63] ^= 1;
            assert!(
                !verifier.isValidSignature(&signature, &otherDigest, &publicKey),
                "{name}"
            );
        }
    }

    #[test]
    fn theAttemptsAreNumbered1To254AndStopAtTheFirstSuccess() {
        let mut numbers = Vec::new();
        let result = Signer::firstSolvedAttempt(|attempt| {
            numbers.push(attempt);
            (attempt == 3).then_some(attempt)
        });
        assert_eq!((result, numbers), (Some(3), vec![1, 2, 3]));
        let mut numbers = Vec::new();
        let result: Option<u8> = Signer::firstSolvedAttempt(|attempt| {
            numbers.push(attempt);
            None
        });
        assert_eq!(result, None);
        assert_eq!(numbers, (1..=254).collect::<Vec<u8>>());
        assert_eq!(lastAttempt, 254);
    }

    #[test]
    fn aSingularSystemMovesTheSignatureToTheNextAttempt() {
        let parameters = &snova24x5x4;
        let generator = KeyGenerator::new(parameters);
        let (publicKey, secretKey) = generator.keyPair(&[3u8; 48]);
        let key = generator.signingKey(&secretKey);
        let signer = Signer::new(parameters);
        let squaredRank = parameters.squaredRank();
        let digest = [5u8; 64];
        let hashLength = parameters.signedHashLength();
        let terms = signer.spreadTerms(&key);
        // A random system over GF(16) is singular with a probability of about 1/15, so some of
        // the first salts meet a singular first attempt.
        let mut singularCount = 0;
        for saltByte in 0..=255u8 {
            let salt = [saltByte; 16];
            let signedHash =
                super::MessageHashing::signedHash(&key.publicSeed, &digest, &salt, hashLength);
            let hashElements =
                NibblePacking::unpacked(&signedHash, parameters.oilCount * squaredRank);
            let attempt = |number| {
                signer.attemptedSolution(&key, &digest, &salt, number, &hashElements, &terms)
            };
            if attempt(1).is_some() {
                continue;
            }
            singularCount += 1;
            let second = attempt(2).expect("the second attempt solves its system");
            let signature = signer.signature(&key, &digest, &salt).expect("a signature");
            // The oil variables of the signature are the solution of the second attempt.
            let variables = NibblePacking::unpacked(&signature, parameters.signatureElementCount());
            let oil: Vec<u8> = second
                .oil
                .iter()
                .map(|value| FieldArithmetic::element(*value))
                .collect();
            assert_eq!(
                variables[parameters.vinegarCount * squaredRank..],
                oil,
                "salt byte {saltByte}"
            );
            assert!(Verifier::new(parameters).isValidSignature(&signature, &digest, &publicKey));
            if singularCount == 3 {
                break;
            }
        }
        assert!(singularCount > 0, "a salt with a singular first attempt");
    }
}
