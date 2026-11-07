use crate::echelonForm::sampledSolution;
use crate::internalAlgorithms::{InternalAlgorithms, Solver};
use crate::parameters::{Parameters, mayo1, mayo2, mayo3, mayo5};
use OQSNativeDomain::{InputLength, RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, SignatureDescription};
use alloc::vec;
use alloc::vec::Vec;

/// MAYO, the oil and vinegar signature scheme of round 2 of the NIST call for additional
/// signatures, with one parameter set.
///
/// The four parameter sets are `MAYO::mayo1`, `MAYO::mayo2`, `MAYO::mayo3` and `MAYO::mayo5`.
/// Each gives the bytes of the liboqs algorithm of the same name, whose C code is the portable
/// implementation of the MAYO team. The secret key is a seed. A key pair draws the seed in one
/// random request, and a signature draws the randomness of its salt in one request of the
/// length of the salt, as liboqs does. MAYO signs without a context string.
pub struct MAYO {
    parameters: &'static Parameters,
}

impl MAYO {
    /// MAYO-1, at the NIST level 1.
    pub const mayo1: MAYO = MAYO { parameters: &mayo1 };

    /// MAYO-2, at the NIST level 1, with shorter signatures and a longer public key than
    /// MAYO-1.
    pub const mayo2: MAYO = MAYO { parameters: &mayo2 };

    /// MAYO-3, at the NIST level 3.
    pub const mayo3: MAYO = MAYO { parameters: &mayo3 };

    /// MAYO-5, at the NIST level 5.
    pub const mayo5: MAYO = MAYO { parameters: &mayo5 };

    fn internalAlgorithms(&self) -> InternalAlgorithms<'static> {
        InternalAlgorithms::new(self.parameters)
    }

    /// The signature of a message under a secret key, with the solver of the linear systems.
    /// The length of the secret key is checked before the random request.
    fn signature(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
        solver: Solver<'_>,
    ) -> Result<Vec<u8>, OQSError> {
        let secretKey =
            InputLength::checked(secretKey, self.parameters.description.secretKeyLength)?;
        let mut randomness = vec![0u8; self.parameters.saltLength];
        random.fillRandomBytes(&mut randomness);
        self.internalAlgorithms()
            .signature(message, secretKey, &randomness, solver)
            .ok_or(OQSError::operationFailed)
    }
}

impl Signing for MAYO {
    fn description(&self) -> &'static SignatureDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seed = vec![0u8; self.parameters.secretSeedLength];
        random.fillRandomBytes(&mut seed);
        let publicKey = self.internalAlgorithms().publicKey(&seed);
        Ok(KeyPair {
            publicKey,
            secretKey: SecretBytes::new(seed),
        })
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        self.signature(message, secretKey, random, &mut sampledSolution)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        let description = &self.parameters.description;
        signature.len() == description.signatureLength
            && publicKey.len() == description.publicKeyLength
            && self
                .internalAlgorithms()
                .isValidSignature(signature, message, publicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::MAYO;
    use OQSNativeDomain::{RandomGenerating, Signing};
    use OQSNativeEntities::OQSError;

    /// A random source that gives the byte 5 to each request.
    struct FiveRandom;

    impl RandomGenerating for FiveRandom {
        fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
            bytes.fill(5);
        }
    }

    #[test]
    fn aSignatureWithNoSolutionInAnyAttemptIsAnOperationFailure() {
        for scheme in [&MAYO::mayo1, &MAYO::mayo2, &MAYO::mayo3, &MAYO::mayo5] {
            let keyPair = scheme.generateKeyPair(&mut FiveRandom).expect("key pair");
            let mut attempts = 0;
            let result = scheme.signature(
                b"message",
                keyPair.secretKey.bytes(),
                &mut FiveRandom,
                &mut |_, _, _, _, _| {
                    attempts += 1;
                    None
                },
            );
            assert_eq!(result, Err(OQSError::operationFailed));
            assert_eq!(attempts, 256);
            assert!(
                scheme
                    .sign(b"message", keyPair.secretKey.bytes(), &mut FiveRandom)
                    .is_ok()
            );
        }
    }
}
