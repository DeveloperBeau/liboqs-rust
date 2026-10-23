use crate::Parameters;
use crate::centralMap::CentralMap;
use crate::fieldArithmetic::FieldArithmetic;
use crate::matrixRing::MatrixRing;
use crate::nibblePacking::NibblePacking;
use crate::parameters::{publicSeedLength, secretSeedLength};
use crate::publicMap::PublicMap;
use crate::secretKeyForm::SecretKeyForm;
use crate::signingKey::SigningKey;
use OQSNativeSHA3::SHAKE256;
use alloc::vec;
use alloc::vec::Vec;

/// The key generation of one parameter set, `generate_keys_core` of `snova.c`, and the signing
/// key of a secret key.
pub(crate) struct KeyGenerator<'parameters> {
    parameters: &'parameters Parameters,
    ring: MatrixRing,
}

impl<'parameters> KeyGenerator<'parameters> {
    /// Makes the key generation of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        KeyGenerator {
            parameters,
            ring: MatrixRing::new(parameters.rank),
        }
    }

    /// The secret matrices T12 of a secret seed, `gen_seeds_and_T12` of `snova_kernel.h`:
    /// SHAKE256 of the seed gives `l` coefficients for each of the `v x o` matrices, and each
    /// matrix is their element of F16[S] in the form without a branch.
    pub(crate) fn secretMatrices(&self, secretSeed: &[u8; secretSeedLength]) -> Vec<u8> {
        let parameters = self.parameters;
        let rank = parameters.rank;
        let matrixCount = parameters.vinegarCount * parameters.oilCount;
        let coefficientCount = matrixCount * rank;
        let mut bytes = vec![0u8; coefficientCount.div_ceil(2)];
        SHAKE256::hash(secretSeed, &mut bytes);
        let coefficients = NibblePacking::unpacked(&bytes, coefficientCount);
        let squaredRank = parameters.squaredRank();
        let mut t12 = vec![0u8; matrixCount * squaredRank];
        for (matrix, coefficients) in t12
            .chunks_exact_mut(squaredRank)
            .zip(coefficients.chunks_exact(rank))
        {
            self.ring.writeSpreadSumOfPowers(coefficients, matrix);
        }
        t12
    }

    /// The packed blocks P22 of the public key, `gen_P22_opt` of `snova_opt.h`:
    /// `P22 = T12' F12 + P21 T12` for each equation, where `T12'` takes the blocks of T12 in
    /// transposed places, with the spread arithmetic of the C code.
    fn packedP22(&self, t12: &[u8], p21: &[u8], f12: &[u8]) -> Vec<u8> {
        let parameters = self.parameters;
        let (vinegarCount, oilCount, rank) = (
            parameters.vinegarCount,
            parameters.oilCount,
            parameters.rank,
        );
        let squaredRank = parameters.squaredRank();
        let spread = |elements: &[u8]| -> Vec<u32> {
            elements
                .iter()
                .map(|element| FieldArithmetic::spread(*element))
                .collect()
        };
        let spreadT12 = spread(t12);
        let blockLength = vinegarCount * oilCount * squaredRank;
        let mut p22 = vec![0u8; oilCount * oilCount * oilCount * squaredRank];
        let mut sums = vec![0u32; oilCount * oilCount * squaredRank];
        for (equation, p22Blocks) in p22
            .chunks_exact_mut(oilCount * oilCount * squaredRank)
            .enumerate()
        {
            sums.fill(0);
            let spreadF12 = spread(&f12[equation * blockLength..(equation + 1) * blockLength]);
            let spreadP21 = spread(&p21[equation * blockLength..(equation + 1) * blockLength]);
            // T12' F12: the block (j, k) is the sum over i of T12[i][j] F12[i][k].
            for vinegarIndex in 0..vinegarCount {
                for oilRow in 0..oilCount {
                    for oilColumn in 0..oilCount {
                        let sumStart = (oilRow * oilCount + oilColumn) * squaredRank;
                        let f12Start = (vinegarIndex * oilCount + oilColumn) * squaredRank;
                        let t12Start = (vinegarIndex * oilCount + oilRow) * squaredRank;
                        for row in 0..rank {
                            for column in 0..rank {
                                let mut sum = sums[sumStart + row * rank + column];
                                for inner in 0..rank {
                                    sum ^= spreadF12[f12Start + inner * rank + column]
                                        * spreadT12[t12Start + row * rank + inner];
                                }
                                sums[sumStart + row * rank + column] = sum;
                            }
                        }
                    }
                }
            }
            // P21 T12: the block (j, k) is the sum over i of P21[j][i] T12[i][k].
            for oilRow in 0..oilCount {
                for vinegarIndex in 0..vinegarCount {
                    for oilColumn in 0..oilCount {
                        let sumStart = (oilRow * oilCount + oilColumn) * squaredRank;
                        let p21Start = (oilRow * vinegarCount + vinegarIndex) * squaredRank;
                        let t12Start = (vinegarIndex * oilCount + oilColumn) * squaredRank;
                        for row in 0..rank {
                            for column in 0..rank {
                                let mut sum = sums[sumStart + row * rank + column];
                                for inner in 0..rank {
                                    sum ^= spreadP21[p21Start + row * rank + inner]
                                        * spreadT12[t12Start + inner * rank + column];
                                }
                                sums[sumStart + row * rank + column] = sum;
                            }
                        }
                    }
                }
            }
            for (element, sum) in p22Blocks.iter_mut().zip(&sums) {
                *element = FieldArithmetic::element(*sum);
            }
        }
        NibblePacking::packed(&p22)
    }

    /// The public key and the secret key of the 48 bytes of the public seed and the secret
    /// seed, `generate_keys_ssk` or `generate_keys_esk` of `snova.c`.
    ///
    /// The public key is the public seed and the packed blocks P22. The secret key is the seeds,
    /// or the expanded key of `SigningKey::packed`.
    pub(crate) fn keyPair(
        &self,
        seeds: &[u8; publicSeedLength + secretSeedLength],
    ) -> (Vec<u8>, Vec<u8>) {
        let parameters = self.parameters;
        let publicSeed: [u8; publicSeedLength] =
            seeds[..publicSeedLength].try_into().expect("a public seed");
        let secretSeed: [u8; secretSeedLength] =
            seeds[publicSeedLength..].try_into().expect("a secret seed");
        let t12 = self.secretMatrices(&secretSeed);
        let publicMap = PublicMap::generated(parameters, &self.ring, &publicSeed);
        let centralMap = CentralMap::generated(parameters, &publicMap, &t12);
        let mut publicKey = Vec::with_capacity(parameters.description.publicKeyLength);
        publicKey.extend_from_slice(&publicSeed);
        publicKey.extend_from_slice(&self.packedP22(&t12, &publicMap.p21, &centralMap.f12));
        let secretKey = match parameters.secretKeyForm {
            SecretKeyForm::seeds => seeds.to_vec(),
            SecretKeyForm::expanded => SigningKey {
                a: publicMap.a,
                b: publicMap.b,
                q1: publicMap.q1,
                q2: publicMap.q2,
                t12,
                centralMap,
                publicSeed,
                secretSeed,
            }
            .packed(),
        };
        (publicKey, secretKey)
    }

    /// The signing key of the seeds, `sign_expand_ssk` of `snova.c`: the public map of the
    /// public seed, T12 of the secret seed and the central map of both.
    pub(crate) fn expandedKey(
        &self,
        publicSeed: &[u8; publicSeedLength],
        secretSeed: &[u8; secretSeedLength],
    ) -> SigningKey {
        let publicMap = PublicMap::generated(self.parameters, &self.ring, publicSeed);
        let t12 = self.secretMatrices(secretSeed);
        let centralMap = CentralMap::generated(self.parameters, &publicMap, &t12);
        SigningKey {
            a: publicMap.a,
            b: publicMap.b,
            q1: publicMap.q1,
            q2: publicMap.q2,
            t12,
            centralMap,
            publicSeed: *publicSeed,
            secretSeed: *secretSeed,
        }
    }

    /// The signing key of a secret key of the right length: the expansion of its seeds, or the
    /// unpacked expanded key, as `sign_digest_ssk` and `sign_digest_esk` of `snova.c` take it.
    pub(crate) fn signingKey(&self, secretKey: &[u8]) -> SigningKey {
        match self.parameters.secretKeyForm {
            SecretKeyForm::seeds => self.expandedKey(
                secretKey[..publicSeedLength]
                    .try_into()
                    .expect("a public seed"),
                secretKey[publicSeedLength..]
                    .try_into()
                    .expect("a secret seed"),
            ),
            SecretKeyForm::expanded => SigningKey::unpacked(self.parameters, secretKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KeyGenerator;
    use crate::matrixRing::MatrixRing;
    use crate::nibblePacking::NibblePacking;
    use crate::parameters::everySet;
    use crate::publicMap::PublicMap;
    use OQSNativeSHA3::SHA3256;

    fn lowerHex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The SHA3-256 of the public key, the secret key, the expanded public key and the expanded
    /// secret key of the seed 0 to 47 for each set, in the order of `everySet`, from
    /// `generate_keys_ssk` or `generate_keys_esk`, `expand_public_pack` and `expand_secret` of
    /// the oracle build of liboqs.
    const knownAnswers: [[&str; 4]; 12] = [
        [
            "749aec7cd51f65315b1917a10b037e69c4d4f56db6117ae63d6a17a1154eb567",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "18a142132ce8119e92ff27bcbbdc69d2396c2d521ec314e6004505b7c5650514",
            "ccfd2496ee0df3e481f4270effca1c6fd5a6008a2a42546db98efc53e211741c",
        ],
        [
            "e9af94f6ae63121fc630a4055a9b2d9bd9d9a98b225dd5a7da74b621b482aa19",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "62f980f4e2f14e80a2aad94f02c9df43142a4606870bf9ced018b51a662cd92d",
            "5f329a4fdf028d100147b5c691e40a5510fed4ca5a3a2e01b859f43b3d0c8b13",
        ],
        [
            "749aec7cd51f65315b1917a10b037e69c4d4f56db6117ae63d6a17a1154eb567",
            "ccfd2496ee0df3e481f4270effca1c6fd5a6008a2a42546db98efc53e211741c",
            "18a142132ce8119e92ff27bcbbdc69d2396c2d521ec314e6004505b7c5650514",
            "ccfd2496ee0df3e481f4270effca1c6fd5a6008a2a42546db98efc53e211741c",
        ],
        [
            "e9af94f6ae63121fc630a4055a9b2d9bd9d9a98b225dd5a7da74b621b482aa19",
            "5f329a4fdf028d100147b5c691e40a5510fed4ca5a3a2e01b859f43b3d0c8b13",
            "62f980f4e2f14e80a2aad94f02c9df43142a4606870bf9ced018b51a662cd92d",
            "5f329a4fdf028d100147b5c691e40a5510fed4ca5a3a2e01b859f43b3d0c8b13",
        ],
        [
            "d8eb3a43129f85a77abf679f352db594fcd1ee9d565ff3ebfbe10a72f986ee45",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "135947fec04baa10039e10a8c07707e183ca2bbb0bd5e0d2e78e9eec7fd3b3ad",
            "c2068514e42226e7a59e546b214df23c4c0bb4243cfa976a7e09c28a7c968534",
        ],
        [
            "aaf69351db4c3b5b869092e9f2859ce90666911b88ae114c3c1316ab6161f92d",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "a72b1c84255012cb50e59e4bf00b31baf1bbba1dd9195bc2a4e80acb8a7fabd4",
            "36a55b785eae1ccc5423f4410d7ad460db8b95b9ab1e6231f5005da47cf54fc9",
        ],
        [
            "0f40add2a3b865992eca849f28dfcfe4712d11cedb053f5133502c71f422ed75",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "c0d6a72b65104814ba28725d9235832fd6f1eb92250db59c24f4a736f78de76f",
            "c4e736824fee70b8d888ee7b150bd1b74c4cea1554d5da82c7c63165317dc4aa",
        ],
        [
            "e3a8d9fd9035e0c8034be0e49193453511b3e25b47d650b40c86f49ffd310272",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "f8ac14667295c36a1f6eeae02c5b977829edda05fa460ba067fdf50dfd6c44cd",
            "af3e4da33ff431a7ccb0a049a13ddff4a412732c651a4b0bcfcbac70757ee5e5",
        ],
        [
            "afd4a67abe2b3a2a121d5b83d286ff04ef694ff3b57a00595d37b3f198c298bf",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "6d36a8871c32f72dad2bf91c860b9b5d404d6c93315d50d4427a209da62e6763",
            "60cf389bd6fdfefae87230cc7f3b12baaa341a7e38a42fe8f8f8c81da0c65e6a",
        ],
        [
            "9d6102309b17c1c3e5fdaf3e5e4fe1a548be0830d53170274d2fcf6ec4927fdc",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "6175ee4a512759a80c4f93439b7b02cca8ae0448412df0b6c382dd0b159c4273",
            "5180508b9a8685a667b3b44c18bd76c6f53a589f91392cbb5b6491c7a13aff51",
        ],
        [
            "4af9aea878af497951d6cda495015f08039ba02d94e3e26b7b3cf1d405c11a10",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "9e08a6cdbbd60ffade4ccb636bd692dc814b59bc6c7d20d1575be9cd948bb069",
            "df27efc392730f57c33f53ae0178f728a38606a8892ccb17744447b933a8cf96",
        ],
        [
            "aa3654ee2e96e3fa971641863414eccbf2243e78bd7ee1ab49c525ca0b25d075",
            "8e7a856365f79e42004aa1a47a3b83e8e6d0ebdbb602f62793e574139b9f2a17",
            "2750c0a4cb2d0cc560885981099bc786832c75bc4dd4f8d6de7197504bac6826",
            "8b5d2a13075f7bacdb9245eb2d8b250a9b8b0dfb08d1dc1213e4606d535f4bde",
        ],
    ];

    #[test]
    fn keysAndExpandedKeysAreTheKeysOfTheCFunctions() {
        let seeds: [u8; 48] = core::array::from_fn(|index| index as u8);
        for (parameters, expected) in everySet.into_iter().zip(knownAnswers) {
            let name = parameters.description.name;
            let generator = KeyGenerator::new(parameters);
            let (publicKey, secretKey) = generator.keyPair(&seeds);
            assert_eq!(lowerHex(&SHA3256::hash(&publicKey)), expected[0], "{name}");
            assert_eq!(lowerHex(&SHA3256::hash(&secretKey)), expected[1], "{name}");
            // The expanded public key of `pkx_pack`: the public seed, then the elements of P22
            // and of P11, P12, P21, A, B, Q1 and Q2, packed.
            let oilCount = parameters.oilCount;
            let p22 = NibblePacking::unpacked(
                &publicKey[16..],
                oilCount * oilCount * oilCount * parameters.squaredRank(),
            );
            let ring = MatrixRing::new(parameters.rank);
            let map = PublicMap::generated(
                parameters,
                &ring,
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            );
            let elements = [
                p22.as_slice(),
                &map.p11,
                &map.p12,
                &map.p21,
                &map.a,
                &map.b,
                &map.q1,
                &map.q2,
            ]
            .concat();
            let mut expandedPublicKey = seeds[..16].to_vec();
            expandedPublicKey.extend(NibblePacking::packed(&elements));
            assert_eq!(
                lowerHex(&SHA3256::hash(&expandedPublicKey)),
                expected[2],
                "{name}"
            );
            let expandedSecretKey = generator
                .expandedKey(
                    seeds[..16].try_into().expect("16 bytes"),
                    seeds[16..].try_into().expect("32 bytes"),
                )
                .packed();
            assert_eq!(
                lowerHex(&SHA3256::hash(&expandedSecretKey)),
                expected[3],
                "{name}"
            );
        }
    }

    #[test]
    fn theMatricesOfT12AreInvertibleElementsOfF16S() {
        for parameters in [&everySet[0], &everySet[4], &everySet[5], &everySet[9]] {
            let generator = KeyGenerator::new(parameters);
            let squaredRank = parameters.squaredRank();
            let t12 = generator.secretMatrices(&[9u8; 32]);
            assert_eq!(
                t12.len(),
                parameters.vinegarCount * parameters.oilCount * squaredRank
            );
            for matrix in t12.chunks_exact(squaredRank) {
                assert_ne!(generator.ring.determinant(matrix), 0);
            }
            assert_ne!(generator.secretMatrices(&[8u8; 32]), t12);
        }
    }
}
