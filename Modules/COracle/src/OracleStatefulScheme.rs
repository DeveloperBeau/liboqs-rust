use crate::{COracle, OracleRandomness};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, StatefulSignatureDescription};

/// A stateful signature scheme of the C library behind the Rust capability interface.
///
/// The secret key is the serialized key of `OQS_SIG_STFL_SECRET_KEY_serialize`. Each signature
/// deserializes it, signs, and takes the advanced key that the C library gives to its store
/// callback. The parity harness checks itself against this scheme.
pub struct OracleStatefulScheme {
    description: &'static StatefulSignatureDescription,
}

impl OracleStatefulScheme {
    /// The C scheme of a liboqs name, or `None` when the C library does not know it.
    pub fn named(name: &str) -> Option<Self> {
        let description =
            COracle::new(OracleRandomness::nist([0; 48])).statefulSignatureDescription(name)?;
        // A test makes a few schemes, so each description lives for the rest of the process,
        // as the trait asks.
        Some(OracleStatefulScheme {
            description: Box::leak(Box::new(description)),
        })
    }
}

impl StatefulSigning for OracleStatefulScheme {
    fn description(&self) -> &'static StatefulSignatureDescription {
        self.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        COracle::new(OracleRandomness::source(random))
            .generateStatefulKeyPair(self.description.name)
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &mut SecretBytes,
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        let (signature, advanced) = COracle::new(OracleRandomness::nist([0; 48])).signStateful(
            self.description.name,
            message,
            secretKey.bytes(),
        )?;
        // The C library advances the key before it stores it, so the key in memory never signs
        // twice with one state, even when the store fails.
        *secretKey = advanced;
        self.releaseSignature(signature, secretKey.bytes(), persisting)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        COracle::new(OracleRandomness::nist([0; 48])).isValidStatefulSignature(
            self.description.name,
            signature,
            message,
            publicKey,
        )
    }

    fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        COracle::new(OracleRandomness::nist([0; 48]))
            .remainingSignatureCount(self.description.name, secretKey)
    }

    fn totalSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        COracle::new(OracleRandomness::nist([0; 48]))
            .totalSignatureCount(self.description.name, secretKey)
    }
}
