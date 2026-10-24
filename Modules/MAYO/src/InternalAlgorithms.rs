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
    use crate::testInputs::{digest, digestOfBytes, inputBytes, inputNibbles, seed};

    /// The digests that the C code of the MAYO team gives for the inputs 1 to 3 of each set, each
    /// built for its set: P1, L and O of `mayo_expand_sk` for the input 1, the public map of
    /// `mayo_expand_pk` for the input 2, and `S P S^T` of `m_calculate_PS_SPS` and the value of
    /// `eval_public_map` for that map and the input 3.
    const knownAnswers: [(&Parameters, [&str; 6]); 4] = [
        (
            &mayo1,
            [
                "f4ef62a746f9e8ad3b89e6fcd66e8a9039ca2b42cf6f979e5c247684d46e8d8a",
                "6caef30413ea7c37b0691f81653f683dcc990ba2064692fd1f8d096816a4327f",
                "d7a12dbca51ebb5fd9a61d562260147fdb73e00e777e260e20c81eb4c1e29197",
                "124a925a15706cedd8d0d8dcd9e447a381971287d02de07a74919efe8f018a7d",
                "78c26e5abe6da61da93220d6eec9abee07eb802f74332f5a141ddb5bc9ddb966",
                "f64810b11a23dea71b13864ac68358bfcfc4e797237305fc787469ef8f2145ce",
            ],
        ),
        (
            &mayo2,
            [
                "140d5be47e46922d589c5eb88e11eb4f7c5a13c433ecf227bb0dda838c46ac59",
                "0ce39333f5942dae1015a366f85b12507e010c2fba5bc4d35037048334b1eb43",
                "7e4fc33f2309552712c40704c5cc78f44073aec895e60e808fae8a5062bd2c5c",
                "2ecb0175ff923c0a466aa16c52b37e44882c1f7eb4baae1f3c0b2e5be6b7b712",
                "2283cae532a4325491b04caf9f2600c1b8f1e352d656c195af7437fa6339dc26",
                "3cf8fbb6b42b9e76093302e0112b546521ed75558e9a4634a0708b236c58c31b",
            ],
        ),
        (
            &mayo3,
            [
                "29a93226094a7b7ea3f2ada19598e633e0d0718286909630149dd7bd7bdd1618",
                "522be9ad68f28b1bf535718535d4dda5be86f670096d53bde5be297b82ce6a7c",
                "5546e57086f20347248407d9d40ade2bca8587b65c7b70c6cbd347ea94efab7a",
                "c1871245f210647f3b56517f85f46c55a4e2006584a86e66a5ceeb25ad5e98d4",
                "59f0aa8e9de032903f452fa57f6a87f139690b7f831efce46aa7af652bd8f9b0",
                "16b3c6c123f728319323762e83a3e0e60d6860dae7bcdacd2e8d6ce615144e63",
            ],
        ),
        (
            &mayo5,
            [
                "cff98907ab79b1273f40d5996b9d79b724003ed1f5d7f90b8fa9e6b2a00d22cd",
                "418f95c41512577fdc48b3e8d725f90eb0ec680997bc37308a7e2bce88d90d6e",
                "48e59ff8106f2b4f7615eca43d829d7bfd486c9ead52c1846347aaab0220d07b",
                "36d2e425900f29ac5b3b9112f10922594d10d0993d182e68654af81db7649f04",
                "d1a7da44f09207d0461cca7ae87f704d4825c6053f5ced0dc30021b304bdf82d",
                "97cbd80ab55675314777a9fef332386a54e5a23524944850777c206d6b16d3e4",
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
            let seeds = [seed(parameters, 1), seed(parameters, 2)];
            let secretSeed = inputBytes(seeds[0], parameters.secretSeedLength);
            let secretKey = algorithms.expandedSecretKey(&secretSeed);
            assert_eq!(digest(&secretKey.p1), answers[0], "{name}, P1, {seeds:?}");
            assert_eq!(digest(&secretKey.l), answers[1], "{name}, L, {seeds:?}");
            assert_eq!(
                digestOfBytes(&secretKey.oil),
                answers[2],
                "{name}, O, {seeds:?}"
            );
            let publicKey = inputBytes(seeds[1], parameters.description.publicKeyLength);
            let publicMap = algorithms.expandedPublicKey(&publicKey);
            assert_eq!(
                digest(&words(&publicMap)),
                answers[3],
                "{name}, P, {seeds:?}"
            );
        }
    }

    #[test]
    fn publicMapGivesTheValueOfTheCCode() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let algorithms = InternalAlgorithms::new(parameters);
            let seeds = [seed(parameters, 2), seed(parameters, 3)];
            let publicKey = inputBytes(seeds[0], parameters.description.publicKeyLength);
            let key = algorithms.expandedPublicKey(&publicKey);
            let elements =
                inputNibbles(seeds[1], parameters.vectorCount * parameters.variableCount);
            let forms = crate::matrixProducts::quadraticForms(
                parameters, &key.p1, &key.p2, &key.p3, &elements,
            );
            assert_eq!(digest(&forms), answers[4], "{name}, S P S^T, {seeds:?}");
            assert_eq!(
                digestOfBytes(&algorithms.evaluation(&key, &elements)),
                answers[5],
                "{name}, P*(s), {seeds:?}"
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
