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
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The digests of `OutputDigest` of the public key, the secret key, the expanded public key
    /// and the expanded secret key of the seed 0 to 47 for each set, in the order of
    /// `everySet`, from `generate_keys_ssk` or `generate_keys_esk`, `expand_public_pack` and
    /// `expand_secret` of the oracle build of liboqs.
    const knownAnswers: [[&str; 4]; 12] = [
        [
            "8f2ed604b71147138bb46decd79e02717d234bda1e4ffec3644f5d8e4d03d049",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "f7f8df080ecd735cc021443e3086332b7e85a08ebd3382331664afbfb6d9fd22",
            "f47f507396fca7b7a480b57e21fd8951c1c2705db95c126067e932fefdac80c6",
        ],
        [
            "10ee6146084bba3e8bb7a4f41616080a652d8d68b78fac3f0ef3416d52318c20",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "8e102c2498db3b205116b18a31118ba639dfd3b6e0b9777dab2fa814b6b6ca40",
            "7aaee91cb8a5d73276ef9eaec486f5f18b563a4e0cf6f4491dfccde38f837734",
        ],
        [
            "8f2ed604b71147138bb46decd79e02717d234bda1e4ffec3644f5d8e4d03d049",
            "f47f507396fca7b7a480b57e21fd8951c1c2705db95c126067e932fefdac80c6",
            "f7f8df080ecd735cc021443e3086332b7e85a08ebd3382331664afbfb6d9fd22",
            "f47f507396fca7b7a480b57e21fd8951c1c2705db95c126067e932fefdac80c6",
        ],
        [
            "10ee6146084bba3e8bb7a4f41616080a652d8d68b78fac3f0ef3416d52318c20",
            "7aaee91cb8a5d73276ef9eaec486f5f18b563a4e0cf6f4491dfccde38f837734",
            "8e102c2498db3b205116b18a31118ba639dfd3b6e0b9777dab2fa814b6b6ca40",
            "7aaee91cb8a5d73276ef9eaec486f5f18b563a4e0cf6f4491dfccde38f837734",
        ],
        [
            "a8e6bd859b79fdf5b378447e5ad7cba5caeb8b26ff55fa63f84f39e6df939e2e",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "735f80e0c1825ce7b3e558b94cb684949795069244f3e2348a98cb84793dd904",
            "0e81f110d8a81c16a653d77beb8c77a11d82d8fb805a82486ec15f573baaf675",
        ],
        [
            "c20eaa163aafd68f693fea1b32f761c3fce8e144a7455375415facf444caedfa",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "18e338821d38b60f8f68caaa3c89a1999fdb98c14cbdd0a9cf8cf4e5f212b240",
            "7258246f1a313572993d615406e3c26b0cce3c60625c56c61cb6e7fa056c501d",
        ],
        [
            "f516bc0826d71f557490d8787504c5b8ae5c8ac02ff1e144f148ba9f08babead",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "c1c9bdd95665b47321d7c78df766ab2f2ab259f5ce4531bfadef64d6ed8c5574",
            "b222016add9781423d4fd4f2f5166ee9e18e832f3f70785990b0760fa7eac4aa",
        ],
        [
            "2a0a50bb736821dae3e2cb4f85975aec4a30f422ea71b3d1bd4c197e6ecc587d",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "dc7cd6e54c3b4ab3d7abe8f8a8984dfbb0cd67a2dd0ec4f5cab44547971fa960",
            "81b7cc4f12b45443e7d20b0bcfdd0583cc27765678fb07ba50548abd802ab0a7",
        ],
        [
            "81d3350430cc8be681ce25a12c3a450392931351455e5648c315d3d50cebe22c",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "bc89aa7313d7e54b8860884e4de9094333993ca47231f62a062143712961e2fa",
            "72abd44ede73fc948947b185696ab328c1e722f1e2c75b54f1613e22f12a5b88",
        ],
        [
            "b98001cf55da757326b41f97a80d8d0a3d4b05c01a77e11d2e9083af631e502a",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "44fe73aeda3bb49caa843f0509da33eb9f2db691c865370c2bad16e1870bba63",
            "c996598d9e55971b1d046713aec4115245ebebbdf607bc889665336c436afa36",
        ],
        [
            "b761142a1396455e3e2e584359ad6fbe917078c552cbe0edd24b522643997462",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "e6be4b744343cd9b492f4dd3a0a45ff0c09bc02782eb6f0d0c859c11cc568209",
            "f35b7d430daaaa1cc85127aa8ad04d4c43543e1b2edaa93562058db89c4397bc",
        ],
        [
            "fb7fe3698f7cfc1b200389f0774504a818412e74d4be26f9e9cb21afc862a4f8",
            "aa0e95005b8b23241332edb390a53d75747e97444b2db8d04c3cbac3bebe8c3b",
            "f899c43224f5b6dc052ec9e4afcf1cd59937dbf976fa73744888cbad3256b54c",
            "2be1a8c58bda5de2e78bb62f88b6f0ba741c42731dd11cdfea4bb5b6f63ca2e5",
        ],
    ];

    #[test]
    fn keysAndExpandedKeysAreTheKeysOfTheCFunctions() {
        let seeds: [u8; 48] = core::array::from_fn(|index| index as u8);
        for (parameters, expected) in everySet.into_iter().zip(knownAnswers) {
            let name = parameters.description.name;
            let generator = KeyGenerator::new(parameters);
            let (publicKey, secretKey) = generator.keyPair(&seeds);
            assert_eq!(OutputDigest::of(&publicKey), expected[0], "{name}");
            assert_eq!(OutputDigest::of(&secretKey), expected[1], "{name}");
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
            assert_eq!(OutputDigest::of(&expandedPublicKey), expected[2], "{name}");
            let expandedSecretKey = generator
                .expandedKey(
                    seeds[..16].try_into().expect("16 bytes"),
                    seeds[16..].try_into().expect("32 bytes"),
                )
                .packed();
            assert_eq!(OutputDigest::of(&expandedSecretKey), expected[3], "{name}");
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
