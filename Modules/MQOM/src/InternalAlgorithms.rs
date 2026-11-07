use crate::extensionField::{lifted, nibble};
use crate::parameters::nonceLength;
use crate::{EquationSystem, LineCommitment, PIOP, Parameters, XOF};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::RangeInclusive;

/// The algorithms of MQOM of one parameter set with given randomness, as `keygen.c` and
/// `sign.c` compute them: the key pair of a seed, the signature of a message with a salt and a
/// root seed, and the verification of a signature.
pub(crate) struct InternalAlgorithms<'parameters> {
    parameters: &'parameters Parameters,
}

/// The parts of a signature of the length of its set, in the order that `Sign` writes them:
/// the salt, com1, com2, the τ serialized slopes alpha1, the opening and the nonce.
struct SignatureParts<'signature> {
    salt: &'signature [u8],
    commitment: &'signature [u8],
    alphaCommitment: &'signature [u8],
    serializedSlopes: &'signature [u8],
    opening: &'signature [u8],
    nonce: &'signature [u8],
}

impl<'signature> SignatureParts<'signature> {
    /// The parts of a signature of the length of a parameter set, as `Verify_default` parses
    /// them.
    fn of(parameters: &Parameters, signature: &'signature [u8]) -> Self {
        let (salt, rest) = signature.split_at(parameters.seedLength());
        let (commitment, rest) = rest.split_at(parameters.digestLength());
        let (alphaCommitment, rest) = rest.split_at(parameters.digestLength());
        let (serializedSlopes, rest) =
            rest.split_at(parameters.repetitionCount * parameters.maskBytes());
        let (opening, rest) = rest.split_at(parameters.openingLength());
        // The nonce is at the fixed place of `MQOM2_SIG_SIZE - 4`.
        let nonce = &rest[..nonceLength];
        SignatureParts {
            salt,
            commitment,
            alphaCommitment,
            serializedSlopes,
            opening,
            nonce,
        }
    }
}

impl<'parameters> InternalAlgorithms<'parameters> {
    /// Makes the algorithms of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        InternalAlgorithms { parameters }
    }

    /// The XOF of a domain byte and the parts of an input, of the length of a digest.
    fn digest(&self, domain: u8, parts: &[&[u8]]) -> Vec<u8> {
        let mut function = XOF::new(self.parameters);
        function.absorb(&[domain]);
        for part in parts {
            function.absorb(part);
        }
        let mut digest = vec![0u8; self.parameters.digestLength()];
        function.finalize().squeeze(&mut digest);
        digest
    }

    /// The images y_i of the secret x under the equations: `x^T A_i x + b_i^T x`, as the loop
    /// of `KeyGen` computes them.
    fn image(&self, equations: &EquationSystem, variables: &[u8]) -> Vec<u16> {
        let parameters = self.parameters;
        let field = parameters.extensionField;
        let lifted: Vec<u16> = (0..parameters.variableCount)
            .map(|index| u16::from(lifted(nibble(variables, index))))
            .collect();
        let innerProduct = |left: &[u16], right: &[u16]| {
            left.iter()
                .zip(right)
                .fold(0u16, |sum, (a, b)| sum ^ field.product(*a, *b))
        };
        (0..parameters.equationCount())
            .map(|equation| {
                let quadratic = (0..parameters.variableCount).fold(0u16, |sum, row| {
                    let rowProduct = innerProduct(equations.row(equation, row), &lifted);
                    sum ^ field.product(lifted[row], rowProduct)
                });
                quadratic ^ innerProduct(&lifted, equations.linearTerms(equation))
            })
            .collect()
    }

    /// The key pair of a seed of 2 λ / 8 bytes, as `KeyGen` computes it: the XOF of the byte
    /// 0x00 and the seed gives x and then the equation seed. The public key is the equation
    /// seed and y, and the secret key is the public key and x.
    pub(crate) fn keyPair(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let parameters = self.parameters;
        let mut function = XOF::new(parameters);
        function.absorb(&[0x00]);
        function.absorb(seed);
        let mut reader = function.finalize();
        let mut variables = vec![0u8; parameters.variableBytes()];
        reader.squeeze(&mut variables);
        let mut equationSeed = vec![0u8; parameters.digestLength()];
        reader.squeeze(&mut equationSeed);
        let equations = EquationSystem::expanded(parameters, &equationSeed);
        let image = self.image(&equations, &variables);
        let mut publicKey = equationSeed;
        publicKey.extend_from_slice(&parameters.extensionField.encoded(&image));
        let mut secretKey = publicKey.clone();
        secretKey.extend_from_slice(&variables);
        (publicKey, secretKey)
    }

    /// The hidden leaves of a challenge hash and a nonce, and whether the nonce meets the
    /// proof of work, as one attempt of `SampleChallenge` and the check of `Verify_default`
    /// read them: the XOF of the byte 0x05, the hash and the nonce gives τ little-endian 16-bit
    /// values cut to the tree depth, and then one value whose w low bits must be zero.
    fn challenge(&self, hash: &[u8], nonce: &[u8]) -> (Vec<u16>, bool) {
        let parameters = self.parameters;
        let repetitionCount = parameters.repetitionCount;
        let mut stream = vec![0u8; 2 * repetitionCount + 2];
        XOF::hash(parameters, &[&[0x05], hash, nonce], &mut stream);
        let values: Vec<u16> = stream
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let leafMask = (1u16 << parameters.treeDepth) - 1;
        let workMask = (1u16 << parameters.workBits) - 1;
        let hiddenLeaves = values[..repetitionCount]
            .iter()
            .map(|value| value & leafMask)
            .collect();
        (hiddenLeaves, values[repetitionCount] & workMask == 0)
    }

    /// The first nonce of a range that meets the proof of work, and its hidden leaves, as
    /// `SampleChallenge` searches them from the nonce 0 up. `None` when no nonce of the range
    /// meets it. A signature searches every 32-bit nonce, where the C code would search on
    /// forever.
    fn sampledChallenge(
        &self,
        hash: &[u8],
        nonces: RangeInclusive<u32>,
    ) -> Option<(Vec<u16>, [u8; nonceLength])> {
        nonces.into_iter().find_map(|nonce| {
            let nonce = nonce.to_le_bytes();
            let (hiddenLeaves, isAccepted) = self.challenge(hash, &nonce);
            isAccepted.then_some((hiddenLeaves, nonce))
        })
    }

    /// The commitment com2 of the lines of P_alpha: the XOF of the byte 0x03, the τ constant
    /// terms alpha0 and the τ serialized slopes alpha1.
    fn alphaCommitment(&self, constantTerms: &[Vec<u16>], serializedSlopes: &[u8]) -> Vec<u8> {
        let field = self.parameters.extensionField;
        let serializedConstantTerms: Vec<u8> = constantTerms
            .iter()
            .flat_map(|terms| field.encoded(terms))
            .collect();
        self.digest(0x03, &[&serializedConstantTerms, serializedSlopes])
    }

    /// The hash of the challenge, as `Sign` and `Verify_default` compute it: the XOF of the
    /// byte 0x04, the public key, com1, com2 and the hash of the message, which is the XOF of
    /// the byte 0x02 and the message.
    fn challengeHash(
        &self,
        publicKey: &[u8],
        commitment: &[u8],
        alphaCommitment: &[u8],
        message: &[u8],
    ) -> Vec<u8> {
        let messageHash = self.digest(0x02, &[message]);
        self.digest(
            0x04,
            &[publicKey, commitment, alphaCommitment, &messageHash],
        )
    }

    /// The signature of a message under a secret key of the right length, with a salt and a
    /// root seed of λ / 8 bytes each, as `Sign` of `sign.c` computes it, with the nonces of a
    /// range for the proof of work.
    ///
    /// Returns `None` when no nonce of the range meets the proof of work of `SampleChallenge`.
    pub(crate) fn signature(
        &self,
        secretKey: &[u8],
        message: &[u8],
        salt: &[u8],
        rootSeed: &[u8],
        nonces: RangeInclusive<u32>,
    ) -> Option<Vec<u8>> {
        self.signatureWithChallenge(secretKey, message, salt, rootSeed, |hash| {
            self.sampledChallenge(hash, nonces)
        })
    }

    /// The signature that `signature` makes, with the hidden leaves and the nonce that
    /// `challengeOf` gives for the hash of the challenge in place of the nonce search. `None`
    /// when it gives none.
    fn signatureWithChallenge(
        &self,
        secretKey: &[u8],
        message: &[u8],
        salt: &[u8],
        rootSeed: &[u8],
        challengeOf: impl FnOnce(&[u8]) -> Option<(Vec<u16>, [u8; nonceLength])>,
    ) -> Option<Vec<u8>> {
        let parameters = self.parameters;
        let publicKeyLength = parameters.description.publicKeyLength;
        let publicKey = &secretKey[..publicKeyLength];
        let equationSeed = &secretKey[..parameters.digestLength()];
        let variables = &secretKey[publicKeyLength..];
        let lines = LineCommitment::committed(parameters, rootSeed, salt, variables);
        let equations = EquationSystem::expanded(parameters, equationSeed);
        let (constantTerms, slopes) =
            PIOP::new(parameters).alphas(&lines.commitment, &lines.lines, variables, &equations);
        let serializedSlopes: Vec<u8> = slopes
            .iter()
            .flat_map(|terms| parameters.extensionField.encoded(terms))
            .collect();
        let alphaCommitment = self.alphaCommitment(&constantTerms, &serializedSlopes);
        let hash = self.challengeHash(publicKey, &lines.commitment, &alphaCommitment, message);
        let (hiddenLeaves, nonce) = challengeOf(&hash)?;
        let mut signature = Vec::with_capacity(parameters.description.signatureLength);
        signature.extend_from_slice(salt);
        signature.extend_from_slice(&lines.commitment);
        signature.extend_from_slice(&alphaCommitment);
        signature.extend_from_slice(&serializedSlopes);
        signature.extend_from_slice(&lines.opening(parameters, &hiddenLeaves));
        signature.extend_from_slice(&nonce);
        Some(signature)
    }

    /// True when a signature of the right length is valid for a message and a public key of
    /// the right length, as `Verify_default` decides: the challenge of its nonce meets the
    /// proof of work, and its proof is valid for the hidden leaves of the challenge.
    pub(crate) fn isValidSignature(
        &self,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> bool {
        let parts = SignatureParts::of(self.parameters, signature);
        let hash = self.challengeHash(publicKey, parts.commitment, parts.alphaCommitment, message);
        let (hiddenLeaves, isAccepted) = self.challenge(&hash, parts.nonce);
        isAccepted && self.isValidProof(&parts, publicKey, &hiddenLeaves)
    }

    /// True when the opening and the slopes of a signature prove the hidden leaves of a
    /// challenge, as the steps of `Verify_default` after the proof of work decide: the
    /// opening gives com1 back, and the recomputed alpha0 and the slopes alpha1 give com2 back.
    fn isValidProof(&self, parts: &SignatureParts, publicKey: &[u8], hiddenLeaves: &[u16]) -> bool {
        let parameters = self.parameters;
        let digestLength = parameters.digestLength();
        let field = parameters.extensionField;
        let Some((variableEvaluations, maskEvaluations)) = LineCommitment::evaluations(
            parameters,
            parts.salt,
            parts.commitment,
            parts.opening,
            hiddenLeaves,
        ) else {
            return false;
        };
        let slopes: Vec<Vec<u16>> = parts
            .serializedSlopes
            .chunks_exact(parameters.maskBytes())
            .map(|bytes| field.decoded(bytes))
            .collect();
        let equations = EquationSystem::expanded(parameters, &publicKey[..digestLength]);
        let image = field.decoded(&publicKey[digestLength..]);
        let constantTerms = PIOP::new(parameters).recomputedConstantTerms(
            parts.commitment,
            &slopes,
            hiddenLeaves,
            &variableEvaluations,
            &maskEvaluations,
            &equations,
            &image,
        );
        self.alphaCommitment(&constantTerms, parts.serializedSlopes) == parts.alphaCommitment
    }
}

#[cfg(test)]
mod tests {
    use super::{InternalAlgorithms, SignatureParts};
    use crate::LineCommitment;
    use crate::parameters::{
        mqom2Cat1GF16FastR3, mqom2Cat1GF16ShortR5, mqom2Cat3GF16FastR5, mqom2Cat5GF16ShortR3,
    };
    use crate::testInputs::{cAnswer, everySet, sequenceBytes};
    use OQSNativeAlgorithmTests::OutputDigest;

    #[test]
    fn theKeysTheChallengeAndTheSignatureAreThoseOfTheCFunctions() {
        // `KeyGen` of a seeded seed, `SampleChallenge` of a seeded hash, and `Sign` of a seeded
        // message of 100 bytes with a seeded salt and root seed, which `Verify_default` accepts.
        for parameters in everySet() {
            let name = parameters.description.name;
            let seedLength = parameters.seedLength();
            let algorithms = InternalAlgorithms::new(parameters);
            let (publicKey, secretKey) =
                algorithms.keyPair(&sequenceBytes(parameters.digestLength(), 10));
            assert_eq!(
                OutputDigest::of(&publicKey),
                cAnswer(name, "publicKey"),
                "{name}"
            );
            assert_eq!(
                OutputDigest::of(&secretKey),
                cAnswer(name, "secretKey"),
                "{name}"
            );
            let (hiddenLeaves, nonce) = algorithms
                .sampledChallenge(&sequenceBytes(parameters.digestLength(), 26), 0..=u32::MAX)
                .expect("a nonce");
            let mut challenge: Vec<u8> = hiddenLeaves
                .iter()
                .flat_map(|leaf| leaf.to_le_bytes())
                .collect();
            challenge.extend_from_slice(&nonce);
            assert_eq!(
                OutputDigest::of(&challenge),
                cAnswer(name, "challenge"),
                "{name}"
            );
            let message = sequenceBytes(100, 27);
            let signature = algorithms
                .signature(
                    &secretKey,
                    &message,
                    &sequenceBytes(seedLength, 28),
                    &sequenceBytes(seedLength, 29),
                    0..=u32::MAX,
                )
                .expect("a signature");
            assert_eq!(
                OutputDigest::of(&signature),
                cAnswer(name, "signature"),
                "{name}"
            );
            assert_eq!(cAnswer(name, "verification"), "0");
            assert!(
                algorithms.isValidSignature(&signature, &message, &publicKey),
                "{name}"
            );
        }
    }

    #[test]
    fn eachCheckOfTheVerificationRefusesAChangeThatReachesIt() {
        // One set of each cipher, each field and each proof. Each change keeps the earlier
        // checks passing, so the check of its own step refuses it.
        for parameters in [
            &mqom2Cat1GF16FastR3,
            &mqom2Cat1GF16ShortR5,
            &mqom2Cat3GF16FastR5,
            &mqom2Cat5GF16ShortR3,
        ] {
            let name = parameters.description.name;
            let seedLength = parameters.seedLength();
            let digestLength = parameters.digestLength();
            let algorithms = InternalAlgorithms::new(parameters);
            let (publicKey, secretKey) = algorithms.keyPair(&sequenceBytes(digestLength, 30));
            let message = sequenceBytes(33, 31);
            let signature = algorithms
                .signature(
                    &secretKey,
                    &message,
                    &sequenceBytes(seedLength, 32),
                    &sequenceBytes(seedLength, 33),
                    0..=u32::MAX,
                )
                .expect("a signature");
            assert!(algorithms.isValidSignature(&signature, &message, &publicKey));
            let salt = &signature[..seedLength];
            let commitment = &signature[seedLength..seedLength + digestLength];
            let slopesStart = seedLength + 2 * digestLength;
            let openingStart = slopesStart + parameters.repetitionCount * parameters.maskBytes();
            let nonceStart = signature.len() - 4;
            let hash = algorithms.digest(
                0x04,
                &[
                    &publicKey,
                    commitment,
                    &signature[seedLength + digestLength..slopesStart],
                    &algorithms.digest(0x02, &[&message]),
                ],
            );
            let signedNonce = u32::from_le_bytes(signature[nonceStart..].try_into().expect("4"));
            let (signedLeaves, isAccepted) = algorithms.challenge(&hash, &signature[nonceStart..]);
            assert!(isAccepted, "{name}");
            let withNonce = |nonce: u32| {
                let mut changed = signature.clone();
                changed[nonceStart..].copy_from_slice(&nonce.to_le_bytes());
                changed
            };
            // The proof of work: the next nonce that fails it.
            let failing = (signedNonce + 1..)
                .find(|nonce| !algorithms.challenge(&hash, &nonce.to_le_bytes()).1)
                .expect("a failing nonce");
            assert!(
                !algorithms.isValidSignature(&withNonce(failing), &message, &publicKey),
                "{name}: nonce {failing}"
            );
            // The line commitment: the next nonce that meets the proof of work hides other
            // leaves, whose evaluations the opening does not give.
            let (other, otherLeaves) = (signedNonce + 1..)
                .find_map(|nonce| {
                    let (leaves, isAccepted) = algorithms.challenge(&hash, &nonce.to_le_bytes());
                    isAccepted.then_some((nonce, leaves))
                })
                .expect("another nonce");
            assert_ne!(otherLeaves, signedLeaves, "{name}");
            assert!(
                !algorithms.isValidSignature(&withNonce(other), &message, &publicKey),
                "{name}: nonce {other}"
            );
            let opening = &signature[openingStart..nonceStart];
            assert!(
                LineCommitment::evaluations(parameters, salt, commitment, opening, &otherLeaves)
                    .is_none()
            );
            // The line commitment again: a changed path, opened commitment or partial delta
            // keeps the challenge and changes the commitment of the opening.
            let pathEnd =
                openingStart + parameters.repetitionCount * parameters.treeDepth * seedLength;
            let commitmentsEnd = pathEnd + parameters.repetitionCount * digestLength;
            for position in [
                openingStart,
                pathEnd - 1,
                pathEnd,
                commitmentsEnd,
                nonceStart - 1,
            ] {
                let mut changed = signature.clone();
                changed[position] ^= 0x01;
                let changedOpening = &changed[openingStart..nonceStart];
                assert!(
                    LineCommitment::evaluations(
                        parameters,
                        salt,
                        commitment,
                        changedOpening,
                        &signedLeaves
                    )
                    .is_none(),
                    "{name}: byte {position}"
                );
                assert!(
                    !algorithms.isValidSignature(&changed, &message, &publicKey),
                    "{name}: byte {position}"
                );
            }
            // The commitment of P_alpha: a changed slope alpha1 keeps the challenge and the
            // opening, and changes the recomputed com2.
            for position in [slopesStart, openingStart - 1] {
                let mut changed = signature.clone();
                changed[position] ^= 0x80;
                assert!(
                    LineCommitment::evaluations(
                        parameters,
                        salt,
                        commitment,
                        opening,
                        &signedLeaves
                    )
                    .is_some()
                );
                assert!(
                    !algorithms.isValidSignature(&changed, &message, &publicKey),
                    "{name}: byte {position}"
                );
            }
        }
    }

    #[test]
    fn aNonceThatFailsTheProofOfWorkIsRefusedAlthoughItsProofIsValid() {
        // A signer that takes the first nonce whose challenge fails the proof of work makes a
        // signature whose opening and slopes prove the hidden leaves of that nonce. Only the
        // check of the w bits refuses it.
        for parameters in [
            &mqom2Cat1GF16FastR3,
            &mqom2Cat1GF16ShortR5,
            &mqom2Cat3GF16FastR5,
            &mqom2Cat5GF16ShortR3,
        ] {
            let name = parameters.description.name;
            let seedLength = parameters.seedLength();
            let algorithms = InternalAlgorithms::new(parameters);
            let (publicKey, secretKey) =
                algorithms.keyPair(&sequenceBytes(parameters.digestLength(), 34));
            let message = sequenceBytes(21, 35);
            let salt = sequenceBytes(seedLength, 36);
            let rootSeed = sequenceBytes(seedLength, 37);
            let failingChallenge = |hash: &[u8]| {
                (0..=u32::MAX).find_map(|nonce| {
                    let nonce = nonce.to_le_bytes();
                    let (hiddenLeaves, isAccepted) = algorithms.challenge(hash, &nonce);
                    (!isAccepted).then_some((hiddenLeaves, nonce))
                })
            };
            let signature = algorithms
                .signatureWithChallenge(&secretKey, &message, &salt, &rootSeed, failingChallenge)
                .expect("a signature");
            let parts = SignatureParts::of(parameters, &signature);
            let hash = algorithms.challengeHash(
                &publicKey,
                parts.commitment,
                parts.alphaCommitment,
                &message,
            );
            let (hiddenLeaves, isAccepted) = algorithms.challenge(&hash, parts.nonce);
            assert!(!isAccepted, "{name}");
            assert!(
                algorithms.isValidProof(&parts, &publicKey, &hiddenLeaves),
                "{name}"
            );
            assert!(
                !algorithms.isValidSignature(&signature, &message, &publicKey),
                "{name}"
            );
            // The same inputs with the first nonce that meets the proof of work sign validly.
            let valid = algorithms
                .signature(&secretKey, &message, &salt, &rootSeed, 0..=u32::MAX)
                .expect("a signature");
            assert!(
                algorithms.isValidSignature(&valid, &message, &publicKey),
                "{name}"
            );
        }
    }
}
