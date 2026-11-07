use crate::Parameters;
use crate::fieldArithmetic::{FieldArithmetic, coefficientBits};
use crate::matrixRing::MatrixRing;
use crate::messageHashing::MessageHashing;
use crate::nibblePacking::NibblePacking;
use crate::parameters::{digestLength, publicSeedLength};
use crate::publicMap::PublicMap;
use alloc::vec;
use alloc::vec::Vec;

/// The verification of a signature of a digest, `verify_signture_opt` of `snova_opt.h`, with
/// the spread arithmetic of the C code.
pub(crate) struct Verifier<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> Verifier<'parameters> {
    /// Makes the verifier of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Verifier { parameters }
    }

    /// The public map of a public key evaluated at the variables of a signature, packed as the
    /// signed hash: `verify_signture_opt_core` up to its comparison.
    ///
    /// The public key and the signature have the lengths of the set.
    pub(crate) fn evaluatedPublicMap(&self, signature: &[u8], publicKey: &[u8]) -> Vec<u8> {
        let parameters = self.parameters;
        let (oilCount, rank) = (parameters.oilCount, parameters.rank);
        let equationCount = oilCount;
        let variableCount = parameters.variableCount();
        let squaredRank = parameters.squaredRank();
        let termCount = parameters.termCount();
        let ring = MatrixRing::new(rank);
        let publicSeed: [u8; publicSeedLength] = publicKey[..publicSeedLength]
            .try_into()
            .expect("a public seed");
        let publicMap = PublicMap::generated(parameters, &ring, &publicSeed);
        let p22 = NibblePacking::unpacked(
            &publicKey[publicSeedLength..],
            equationCount * oilCount * oilCount * squaredRank,
        );
        let variables = NibblePacking::unpacked(signature, parameters.signatureElementCount());
        let spreadVariables: Vec<u32> = variables
            .iter()
            .map(|element| FieldArithmetic::spread(*element))
            .collect();

        let mut result = vec![0u32; equationCount * squaredRank];
        let termLength = variableCount * squaredRank;
        let mut left = vec![0u32; termCount * termLength];
        let mut right = vec![0u32; termCount * termLength];
        let mut products = vec![0u32; termLength];
        let mut intermediate = vec![0u32; termCount * squaredRank * variableCount];
        // One row of blocks of P, spread and in 16 bits, see `FieldArithmetic::narrowed`.
        let mut spreadPublic = vec![0u16; squaredRank * variableCount];
        for equation in 0..equationCount {
            left.fill(0);
            right.fill(0);
            for term in 0..termCount {
                // The matrices of the equation that this equation and term use.
                let source = (self.usingEquation(equation, term) * termCount + term) * squaredRank;
                let spread = |matrices: &[u8]| -> [u32; 25] {
                    let mut spread = [0u32; 25];
                    for (value, element) in spread
                        .iter_mut()
                        .zip(&matrices[source..source + squaredRank])
                    {
                        *value = FieldArithmetic::spread(*element);
                    }
                    spread
                };
                let (a, b, q1, q2) = (
                    spread(&publicMap.a),
                    spread(&publicMap.b),
                    spread(&publicMap.q1),
                    spread(&publicMap.q2),
                );
                let termLeft = &mut left[term * termLength..(term + 1) * termLength];
                let termRight = &mut right[term * termLength..(term + 1) * termLength];
                for (variable, ((variableLeft, variableRight), products)) in termLeft
                    .chunks_exact_mut(squaredRank)
                    .zip(termRight.chunks_exact_mut(squaredRank))
                    .zip(products.chunks_exact_mut(squaredRank))
                    .enumerate()
                {
                    let matrix = &spreadVariables[variable * squaredRank..][..squaredRank];
                    // Left: A (U' Q1), with the products of `U' Q1` masked to their
                    // coefficient bits before the second product.
                    products.fill(0);
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                products[row * rank + column] ^=
                                    matrix[inner * rank + row] * q1[inner * rank + column];
                            }
                        }
                    }
                    for value in products.iter_mut() {
                        *value &= coefficientBits;
                    }
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                variableLeft[row * rank + column] ^=
                                    a[row * rank + inner] * products[inner * rank + column];
                            }
                        }
                    }
                    for value in variableLeft.iter_mut() {
                        *value = FieldArithmetic::reduced(*value);
                    }
                    // Right: (Q2 U) B.
                    products.fill(0);
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                products[row * rank + column] ^=
                                    q2[row * rank + inner] * matrix[inner * rank + column];
                            }
                        }
                    }
                    for value in products.iter_mut() {
                        *value &= coefficientBits;
                    }
                    for row in 0..rank {
                        for column in 0..rank {
                            for inner in 0..rank {
                                variableRight[row * rank + column] ^=
                                    products[row * rank + inner] * b[inner * rank + column];
                            }
                        }
                    }
                    for value in variableRight.iter_mut() {
                        *value = FieldArithmetic::reduced(*value);
                    }
                }
            }

            // Left P, masked, then times Right. `intermediate` holds Left P by term, row,
            // column and column variable, and `spreadPublic` one row of blocks of P by row,
            // column and column variable, so each element of Left multiplies one stretch of
            // `spreadPublic` into one stretch of `intermediate`. The C code has a second loop
            // order for l = 4, which exclusive-ors the same products into each value.
            intermediate.fill(0);
            let stretch = rank * variableCount;
            for rowVariable in 0..variableCount {
                for columnVariable in 0..variableCount {
                    let block =
                        self.publicBlock(&publicMap, &p22, equation, rowVariable, columnVariable);
                    for (index, element) in block.iter().enumerate() {
                        spreadPublic[index * variableCount + columnVariable] =
                            FieldArithmetic::narrowed(FieldArithmetic::spread(*element));
                    }
                }
                for term in 0..termCount {
                    let leftMatrix =
                        &left[term * termLength + rowVariable * squaredRank..][..squaredRank];
                    for row in 0..rank {
                        let target = &mut intermediate
                            [(term * squaredRank + row * rank) * variableCount..][..stretch];
                        for inner in 0..rank {
                            let leftValue =
                                FieldArithmetic::narrowed(leftMatrix[row * rank + inner]);
                            let source = &spreadPublic[inner * stretch..][..stretch];
                            for (value, public) in target.iter_mut().zip(source) {
                                *value ^= FieldArithmetic::spreadProduct(leftValue, *public);
                            }
                        }
                    }
                }
            }
            for value in intermediate.iter_mut() {
                *value &= coefficientBits;
            }
            for term in 0..termCount {
                let target = self.usingEquation(equation, term) * squaredRank;
                for row in 0..rank {
                    for column in 0..rank {
                        for inner in 0..rank {
                            for variable in 0..variableCount {
                                result[target + row * rank + column] ^=
                                    intermediate[(term * squaredRank + row * rank + inner)
                                        * variableCount
                                        + variable]
                                        * right[term * termLength
                                            + variable * squaredRank
                                            + inner * rank
                                            + column];
                            }
                        }
                    }
                }
            }
        }
        let elements: Vec<u8> = result
            .iter()
            .map(|value| FieldArithmetic::element(*value))
            .collect();
        NibblePacking::packed(&elements)
    }

    /// The equation whose matrices an equation and a term use, `i_prime_inv` of `snova.c`.
    fn usingEquation(&self, equation: usize, term: usize) -> usize {
        let oilCount = self.parameters.oilCount;
        (oilCount * self.parameters.termCount() - term + equation) % oilCount
    }

    /// The block of the public map of an equation at a row and a column of variables: P11,
    /// P12, P21 or P22.
    fn publicBlock<'map>(
        &self,
        publicMap: &'map PublicMap,
        p22: &'map [u8],
        equation: usize,
        row: usize,
        column: usize,
    ) -> &'map [u8] {
        let parameters = self.parameters;
        let (vinegarCount, oilCount) = (parameters.vinegarCount, parameters.oilCount);
        let squaredRank = parameters.squaredRank();
        let (matrices, index) = match (row < vinegarCount, column < vinegarCount) {
            (true, true) => (
                &publicMap.p11,
                (equation * vinegarCount + row) * vinegarCount + column,
            ),
            (true, false) => (
                &publicMap.p12,
                (equation * vinegarCount + row) * oilCount + column - vinegarCount,
            ),
            (false, true) => (
                &publicMap.p21,
                (equation * oilCount + row - vinegarCount) * vinegarCount + column,
            ),
            (false, false) => {
                return &p22[((equation * oilCount + row - vinegarCount) * oilCount + column
                    - vinegarCount)
                    * squaredRank..][..squaredRank];
            }
        };
        &matrices[index * squaredRank..(index + 1) * squaredRank]
    }

    /// True when a signature of a digest is valid for a public key, `verify_signture` of
    /// `snova.c`. The signature and the public key have the lengths of the set.
    ///
    /// The comparison takes the signed hash of the public seed, the digest and the salt of the
    /// signature. When `o l` is odd, the high half of its last byte is cleared, as the packing of
    /// the evaluation leaves it.
    pub(crate) fn isValidSignature(
        &self,
        signature: &[u8],
        digest: &[u8; digestLength],
        publicKey: &[u8],
    ) -> bool {
        let parameters = self.parameters;
        let salt = &signature[parameters.packedSignatureLength()..];
        let publicSeed: [u8; publicSeedLength] = publicKey[..publicSeedLength]
            .try_into()
            .expect("a public seed");
        let mut signedHash =
            MessageHashing::signedHash(&publicSeed, digest, salt, parameters.signedHashLength());
        if (parameters.oilCount * parameters.rank) % 2 == 1 {
            let last = signedHash.len() - 1;
            signedHash[last] &= 0x0F;
        }
        self.evaluatedPublicMap(signature, publicKey) == signedHash
    }
}
