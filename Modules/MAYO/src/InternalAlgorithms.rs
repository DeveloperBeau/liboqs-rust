use crate::Parameters;
use crate::parameters::publicSeedLength;
use crate::{field, linearSystem, matrixProducts, packedVectors};
use OQSNativeAES::AES128;
use OQSNativeSHA3::SHAKE256;
use alloc::vec;
use alloc::vec::Vec;

/// The solver of the linear system of a signature attempt, as `sample_solution`: the matrix,
/// the right-hand side, the randomizer, the number of unknowns and the number of rows, and the
/// solution or `None`.
pub(crate) type Solver<'solver> =
    &'solver mut dyn FnMut(&mut [u8], &[u8], &[u8], usize, usize) -> Option<Vec<u8>>;

/// The algorithms of one MAYO parameter set, as `mayo.c` of the MAYO team computes them: the
/// public key of a secret seed, the signature of a message with given randomness, and the
/// verification of a signature.
pub(crate) struct InternalAlgorithms<'parameters> {
    parameters: &'parameters Parameters,
}

/// The parts of a secret key that a signature uses, as `mayo_expand_sk` gives them.
pub(crate) struct ExpandedSecretKey {
    /// The upper triangular matrix P1 of packed vectors.
    p1: Vec<u64>,
    /// The matrix `L = (P1 + P1^T) O + P2` of packed vectors.
    l: Vec<u64>,
    /// The oil space O: v rows of o elements.
    oil: Vec<u8>,
}

/// The public map of a public key, as `mayo_expand_pk` gives it: P1 and P2 from the public
/// seed, and the upper triangle of P3 from the key.
pub(crate) struct ExpandedPublicKey {
    /// The upper triangular matrix P1 of packed vectors.
    p1: Vec<u64>,
    /// The matrix P2 of packed vectors.
    p2: Vec<u64>,
    /// The upper triangle of P3 in row order, as the public key holds it.
    p3: Vec<u64>,
}

impl<'parameters> InternalAlgorithms<'parameters> {
    /// Makes the algorithms of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        InternalAlgorithms { parameters }
    }

    /// P1 and P2 of a public seed, as `expand_P1_P2`: the AES-128 counter-mode stream of the
    /// seed with a zero vector of 12 bytes, as `AES_128_CTR` of `aes_ctr.h`, read as packed
    /// vectors.
    fn expandedP1P2(&self, publicSeed: &[u8; publicSeedLength]) -> (Vec<u64>, Vec<u64>) {
        let parameters = self.parameters;
        let vectorBytes = parameters.vectorBytes();
        let mut bytes = vec![0u8; (parameters.p1Count() + parameters.p2Count()) * vectorBytes];
        AES128::new(publicSeed).fillCounterKeystream(&[0u8; 12], &mut bytes);
        let mut p1 = packedVectors::unpacked(&bytes, vectorBytes, parameters.limbCount());
        let p2 = p1.split_off(parameters.p1Count() * parameters.limbCount());
        (p1, p2)
    }

    /// The public seed and the oil space O of a secret seed: SHAKE256 of the seed gives the
    /// public seed and the bytes of O.
    fn seedExpansion(&self, secretSeed: &[u8]) -> ([u8; publicSeedLength], Vec<u8>) {
        let parameters = self.parameters;
        let mut expanded = vec![0u8; publicSeedLength + parameters.oilBytes()];
        SHAKE256::hash(secretSeed, &mut expanded);
        let mut oil = vec![0u8; parameters.vinegarCount() * parameters.oilCount];
        field::decode(&expanded[publicSeedLength..], &mut oil);
        let publicSeed = expanded[..publicSeedLength].try_into().expect("16 bytes");
        (publicSeed, oil)
    }

    /// The compact public key of a secret seed, as `mayo_keypair_compact` after its random
    /// request: the public seed and the packed upper triangle of `P3 = O^T (P1 O + P2)`.
    pub(crate) fn publicKey(&self, secretSeed: &[u8]) -> Vec<u8> {
        let parameters = self.parameters;
        let limbCount = parameters.limbCount();
        let (publicSeed, oil) = self.seedExpansion(secretSeed);
        let (p1, mut p2) = self.expandedP1P2(&publicSeed);
        let p3 = matrixProducts::oilProducts(parameters, &p1, &mut p2, &oil);
        let upper = matrixProducts::upperTriangle(&p3, parameters.oilCount, limbCount);
        let mut publicKey = vec![0u8; parameters.description.publicKeyLength];
        publicKey[..publicSeedLength].copy_from_slice(&publicSeed);
        packedVectors::pack(
            &upper,
            limbCount,
            parameters.vectorBytes(),
            &mut publicKey[publicSeedLength..],
        );
        publicKey
    }

    /// The expanded secret key of a secret seed, as `mayo_expand_sk`.
    pub(crate) fn expandedSecretKey(&self, secretSeed: &[u8]) -> ExpandedSecretKey {
        let parameters = self.parameters;
        let (publicSeed, oil) = self.seedExpansion(secretSeed);
        let (p1, mut l) = self.expandedP1P2(&publicSeed);
        matrixProducts::addSymmetrizedTimesMatrix(
            &p1,
            &oil,
            &mut l,
            parameters.vinegarCount(),
            parameters.oilCount,
            parameters.limbCount(),
        );
        ExpandedSecretKey { p1, l, oil }
    }

    /// The expanded public key of a public key of the right length, as `mayo_expand_pk`.
    pub(crate) fn expandedPublicKey(&self, publicKey: &[u8]) -> ExpandedPublicKey {
        let parameters = self.parameters;
        let publicSeed = publicKey[..publicSeedLength].try_into().expect("16 bytes");
        let (p1, p2) = self.expandedP1P2(publicSeed);
        let p3 = packedVectors::unpacked(
            &publicKey[publicSeedLength..],
            parameters.vectorBytes(),
            parameters.limbCount(),
        );
        ExpandedPublicKey { p1, p2, p3 }
    }

    /// The value of the whipped public map at the k vectors of a signature, as
    /// `eval_public_map`: the right-hand side of `S P S^T` with a zero target.
    fn evaluation(&self, key: &ExpandedPublicKey, elements: &[u8]) -> Vec<u8> {
        let parameters = self.parameters;
        let mut forms =
            matrixProducts::quadraticForms(parameters, &key.p1, &key.p2, &key.p3, elements);
        linearSystem::rightHandSide(parameters, &mut forms, &vec![0u8; parameters.equationCount])
    }

    /// The target t of a message digest and a salt: SHAKE256 of the two, decoded.
    fn target(&self, digestAndSalt: &[u8]) -> Vec<u8> {
        let parameters = self.parameters;
        let mut targetBytes = vec![0u8; parameters.vectorBytes()];
        SHAKE256::hash(digestAndSalt, &mut targetBytes);
        let mut target = vec![0u8; parameters.equationCount];
        field::decode(&targetBytes, &mut target);
        target
    }

    /// The signature of a message under a secret seed of the right length, with the
    /// randomness of the salt, as `mayo_sign_signature` after its random request.
    ///
    /// The salt is SHAKE256 of the digest of the message, the randomness and the seed. Attempt
    /// c, from 0 to 255, hashes the digest, the salt, the seed and the byte c into k vinegar
    /// vectors and a randomizer, and solves the linear system with the solver. Returns `None`
    /// when no attempt finds a solution, as the `MAYO_ERR` of the C code.
    pub(crate) fn signature(
        &self,
        message: &[u8],
        secretSeed: &[u8],
        randomness: &[u8],
        solver: Solver<'_>,
    ) -> Option<Vec<u8>> {
        let parameters = self.parameters;
        let key = self.expandedSecretKey(secretSeed);
        let (digestLength, saltLength) = (parameters.digestLength, parameters.saltLength);
        let saltEnd = digestLength + saltLength;
        let seedEnd = saltEnd + parameters.secretSeedLength;
        // The digest, the randomness and later the salt, the seed and the counter byte, as the
        // buffer `tmp` of the C code.
        let mut hashInput = vec![0u8; seedEnd + 1];
        SHAKE256::hash(message, &mut hashInput[..digestLength]);
        hashInput[digestLength..saltEnd].copy_from_slice(randomness);
        hashInput[saltEnd..seedEnd].copy_from_slice(secretSeed);
        let mut salt = vec![0u8; saltLength];
        SHAKE256::hash(&hashInput[..seedEnd], &mut salt);
        hashInput[digestLength..saltEnd].copy_from_slice(&salt);
        let target = self.target(&hashInput[..saltEnd]);
        let (vinegarCount, vectorCount) = (parameters.vinegarCount(), parameters.vectorCount);
        let vinegarBytes = parameters.vinegarBytes();
        let unknownCount = vectorCount * parameters.oilCount;
        let mut attemptBytes = vec![0u8; vectorCount * vinegarBytes + parameters.randomizerBytes()];
        let mut vinegar = vec![0u8; vectorCount * vinegarCount];
        for counter in 0..=u8::MAX {
            hashInput[seedEnd] = counter;
            SHAKE256::hash(&hashInput, &mut attemptBytes);
            for (index, vector) in vinegar.chunks_exact_mut(vinegarCount).enumerate() {
                field::decode(&attemptBytes[index * vinegarBytes..], vector);
            }
            let (mut vinegarL, mut vinegarP1Vinegar) =
                matrixProducts::vinegarProducts(parameters, &vinegar, &key.l, &key.p1);
            let rightHandSide =
                linearSystem::rightHandSide(parameters, &mut vinegarP1Vinegar, &target);
            let mut matrix = linearSystem::systemMatrix(parameters, &mut vinegarL);
            let mut randomizer = vec![0u8; unknownCount + 1];
            field::decode(
                &attemptBytes[vectorCount * vinegarBytes..],
                &mut randomizer[..unknownCount],
            );
            if let Some(solution) = solver(
                &mut matrix,
                &rightHandSide,
                &randomizer,
                unknownCount,
                parameters.equationCount,
            ) {
                return Some(self.signatureBytes(&key, &vinegar, &solution, &salt));
            }
        }
        None
    }

    /// The bytes of a signature: the k vectors `s_i = (v_i + O x_i, x_i)` and the salt.
    fn signatureBytes(
        &self,
        key: &ExpandedSecretKey,
        vinegar: &[u8],
        solution: &[u8],
        salt: &[u8],
    ) -> Vec<u8> {
        let parameters = self.parameters;
        let (variableCount, oilCount) = (parameters.variableCount, parameters.oilCount);
        let vinegarCount = parameters.vinegarCount();
        let mut elements = vec![0u8; parameters.vectorCount * variableCount];
        let mut oilProduct = vec![0u8; vinegarCount];
        for (index, vector) in elements.chunks_exact_mut(variableCount).enumerate() {
            let oilPart = &solution[index * oilCount..(index + 1) * oilCount];
            field::matrixTimesVector(&key.oil, oilPart, &mut oilProduct);
            let vinegarVector = &vinegar[index * vinegarCount..(index + 1) * vinegarCount];
            for ((value, vinegarValue), product) in
                vector.iter_mut().zip(vinegarVector).zip(&oilProduct)
            {
                *value = vinegarValue ^ product;
            }
            vector[vinegarCount..].copy_from_slice(oilPart);
        }
        let signatureLength = parameters.description.signatureLength;
        let saltStart = signatureLength - parameters.saltLength;
        let mut signature = vec![0u8; signatureLength];
        field::encode(&elements, &mut signature[..saltStart]);
        signature[saltStart..].copy_from_slice(salt);
        signature
    }

    /// The value of the public map of a public key at the vectors of a signature, and the
    /// target of the digest of a message and the salt of the signature, both of m elements, as
    /// `mayo_verify` computes them. The signature and the key have the right lengths.
    fn valueAndTarget(
        &self,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let parameters = self.parameters;
        let key = self.expandedPublicKey(publicKey);
        let digestLength = parameters.digestLength;
        let mut digestAndSalt = vec![0u8; digestLength + parameters.saltLength];
        SHAKE256::hash(message, &mut digestAndSalt[..digestLength]);
        let saltStart = signature.len() - parameters.saltLength;
        digestAndSalt[digestLength..].copy_from_slice(&signature[saltStart..]);
        let target = self.target(&digestAndSalt);
        let mut elements = vec![0u8; parameters.vectorCount * parameters.variableCount];
        field::decode(signature, &mut elements);
        (self.evaluation(&key, &elements), target)
    }

    /// True when a signature and a public key, both of the right length, are valid for a
    /// message, as `mayo_verify`: the value of the public map at the vectors of the signature
    /// equals the target in each of the m elements.
    pub(crate) fn isValidSignature(
        &self,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> bool {
        let (value, target) = self.valueAndTarget(signature, message, publicKey);
        value == target
    }
}

#[cfg(test)]
mod tests {
    use super::{ExpandedPublicKey, InternalAlgorithms};
    use crate::echelonForm::sampledSolution;
    use crate::parameters::{Parameters, mayo1, mayo2, mayo3, mayo5};
    use crate::testInputs::{digest, digestOfBytes, inputBytes, inputNibbles};

    /// The digests that the C code of the MAYO team gives for the inputs of the labels, each
    /// built for its set: P1, L and O of `mayo_expand_sk`, the public map of `mayo_expand_pk`,
    /// `S P S^T` of `m_calculate_PS_SPS` and the value of `eval_public_map`.
    const knownAnswers: [(&Parameters, [&str; 6]); 4] = [
        (
            &mayo1,
            [
                "3438adf32d28baf7489681455f0c01642d0df1faad3d955a091b3c6153d9520f",
                "fbc30a825dae62458adbaf42f1c673e0225f41f280c16a0e00f60faf0d5c5992",
                "02ea9d72601c6852cbaa71545b75e998097ba355c6dc8ffddeb60666d6982b5f",
                "7d4f98c18370a0a9f612390a571999907b1cdb9cf96560b757128d929b6b003e",
                "935c1d9bc02ed301fa170e74afdfbedbd616f2964b9c05614863a2ad7d86aa0e",
                "de399e3f8c804b07a94d4233e3f3f23ff5e6b1072f935ddd31b9216b6a97e557",
            ],
        ),
        (
            &mayo2,
            [
                "851fcf95bb06f82621d27ee77a0305b10ec87c15abe7c863013e8b102ccbcc29",
                "4bb1b5a5c487ced01f67e4ec66f99f5120d2f09bcab0ff7a1c58be19fa6614e7",
                "f72f1d6ec04e79118d60366c0a32917435a564b72a519538499ab27d31d97c12",
                "7d52270627057c5ef4c665981b21c968ec817fa65b20f5c50335c8d783a89a49",
                "eb42eedd1a15676dcb23d3a55bc9fe12300c7afe2fc3b029a58532eb53a6baed",
                "bf8df75cc40eccd44ebe7652f316f6badbda35746f95204a4e22ae5801016399",
            ],
        ),
        (
            &mayo3,
            [
                "fe9049489e19e485df6aaf81ea4434ae72e64ee1e11a2096a3a59f87424f33b2",
                "0daf3f97712af67c95001fd2f992d7807d0b0558ade91a7a99de763c9e7e48c5",
                "83027a7141c3c7bc1a025c837a7f6ce1e068cf0b677888fa66b344a40d43169f",
                "b8a5f908921847b454885e62457b9da03e132fca13f5de45562d53d60ce1fa78",
                "fe142f577da7f11ce43158d474af0f35ad0707e7cd37a9d3f6807c23dfda7b87",
                "75c01c2785cb54a664d9bebcb0a69bae0c90f47542ef28727e168498b6e04987",
            ],
        ),
        (
            &mayo5,
            [
                "424ed45d8847f493b3a043a676d20c321ed64b6a540d07863307b7ab252c51f9",
                "218146f8dbd38a766fbf194aea28c7ada4ee1e626b13daefb252d0fd927f7947",
                "82dc7f504e6a336b6c87f82e3bae6e8639fac994aa6bb97940d781b60316961e",
                "75a481f218b6fb6b591cef2191beba335bae01464401e053da23f168db93fdca",
                "8504eb846fb71fd1848435a8c5a25682a284e3ad5ca32499dedc406ae804caae",
                "76222e15d5840a7d0a8579add352bff7d4e9f7252db28ae47808272f8183f2ee",
            ],
        ),
    ];

    const parameterSets: [&Parameters; 4] = [&mayo1, &mayo2, &mayo3, &mayo5];

    fn words(key: &ExpandedPublicKey) -> Vec<u64> {
        [key.p1.as_slice(), &key.p2, &key.p3].concat()
    }

    #[test]
    fn expandedKeysAreTheExpandedKeysOfTheCCode() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let algorithms = InternalAlgorithms::new(parameters);
            let seed = inputBytes(name, "expandedSecretKey", parameters.secretSeedLength);
            let secretKey = algorithms.expandedSecretKey(&seed);
            assert_eq!(digest(&secretKey.p1), answers[0], "{name}, P1");
            assert_eq!(digest(&secretKey.l), answers[1], "{name}, L");
            assert_eq!(digestOfBytes(&secretKey.oil), answers[2], "{name}, O");
            let publicKey = inputBytes(
                name,
                "expandedPublicKey",
                parameters.description.publicKeyLength,
            );
            let publicMap = algorithms.expandedPublicKey(&publicKey);
            assert_eq!(digest(&words(&publicMap)), answers[3], "{name}, P");
        }
    }

    #[test]
    fn publicMapGivesTheValueOfTheCCode() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let algorithms = InternalAlgorithms::new(parameters);
            let publicKey = inputBytes(
                name,
                "expandedPublicKey",
                parameters.description.publicKeyLength,
            );
            let key = algorithms.expandedPublicKey(&publicKey);
            let elements = inputNibbles(
                name,
                "publicMap s",
                parameters.vectorCount * parameters.variableCount,
            );
            let forms = crate::matrixProducts::quadraticForms(
                parameters, &key.p1, &key.p2, &key.p3, &elements,
            );
            assert_eq!(digest(&forms), answers[4], "{name}, S P S^T");
            assert_eq!(
                digestOfBytes(&algorithms.evaluation(&key, &elements)),
                answers[5],
                "{name}, P*(s)"
            );
        }
    }

    #[test]
    fn eachOfThe256AttemptsHashesItsOwnCounter() {
        for parameters in parameterSets {
            let algorithms = InternalAlgorithms::new(parameters);
            let seed = vec![7u8; parameters.secretSeedLength];
            let randomness = vec![9u8; parameters.saltLength];
            let mut randomizers: Vec<Vec<u8>> = Vec::new();
            let signature = algorithms.signature(
                b"message",
                &seed,
                &randomness,
                &mut |_, _, randomizer, _, _| {
                    randomizers.push(randomizer.to_vec());
                    None
                },
            );
            assert_eq!(signature, None, "{}", parameters.description.name);
            assert_eq!(randomizers.len(), 256);
            randomizers.sort_unstable();
            randomizers.dedup();
            assert_eq!(randomizers.len(), 256);
        }
    }

    #[test]
    fn aLaterAttemptGivesAnotherValidSignatureWithTheSameSalt() {
        for parameters in parameterSets {
            let name = parameters.description.name;
            let algorithms = InternalAlgorithms::new(parameters);
            let seed = vec![3u8; parameters.secretSeedLength];
            let publicKey = algorithms.publicKey(&seed);
            let randomness = vec![4u8; parameters.saltLength];
            let first = algorithms
                .signature(b"message", &seed, &randomness, &mut sampledSolution)
                .expect("a signature");
            let mut attempt = 0;
            let later = algorithms
                .signature(
                    b"message",
                    &seed,
                    &randomness,
                    &mut |matrix, target, randomizer, unknownCount, rowCount| {
                        attempt += 1;
                        if attempt <= 3 {
                            return None;
                        }
                        sampledSolution(matrix, target, randomizer, unknownCount, rowCount)
                    },
                )
                .expect("a signature");
            assert_eq!(attempt, 4, "{name}");
            assert_ne!(first, later, "{name}");
            let saltStart = first.len() - parameters.saltLength;
            assert_eq!(first[saltStart..], later[saltStart..], "{name}");
            assert!(
                algorithms.isValidSignature(&first, b"message", &publicKey),
                "{name}"
            );
            assert!(
                algorithms.isValidSignature(&later, b"message", &publicKey),
                "{name}"
            );
            assert!(
                !algorithms.isValidSignature(&later, b"messagf", &publicKey),
                "{name}"
            );
        }
    }

    #[test]
    fn aSignatureWhoseValueDiffersFromTheTargetInOneElementIsRefused() {
        // A solution for the right-hand side with one element changed gives vectors whose value
        // differs from the target in that element alone, so the comparison must cover each
        // element. A random change gives a value that differs in nearly every element.
        for parameters in parameterSets {
            let name = parameters.description.name;
            let algorithms = InternalAlgorithms::new(parameters);
            let seed = vec![5u8; parameters.secretSeedLength];
            let publicKey = algorithms.publicKey(&seed);
            let randomness = vec![6u8; parameters.saltLength];
            let equationCount = parameters.equationCount;
            for place in [
                None,
                Some(0),
                Some(equationCount / 2),
                Some(equationCount - 1),
            ] {
                let signature = algorithms
                    .signature(
                        b"message",
                        &seed,
                        &randomness,
                        &mut |matrix, target, randomizer, unknownCount, rowCount| {
                            let mut changed = target.to_vec();
                            if let Some(place) = place {
                                changed[place] ^= 1;
                            }
                            sampledSolution(matrix, &changed, randomizer, unknownCount, rowCount)
                        },
                    )
                    .expect("a signature");
                let (value, target) = algorithms.valueAndTarget(&signature, b"message", &publicKey);
                let differences: Vec<usize> = (0..equationCount)
                    .filter(|index| value[*index] != target[*index])
                    .collect();
                assert_eq!(differences, Vec::from_iter(place), "{name}, {place:?}");
                assert_eq!(
                    algorithms.isValidSignature(&signature, b"message", &publicKey),
                    place.is_none(),
                    "{name}, {place:?}"
                );
            }
        }
    }
}
