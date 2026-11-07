use crate::{COracle, OracleRandomness};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SignatureDescription};

/// A signature scheme of the C library behind the Rust capability interface.
///
/// The C code reads its random bytes from the source that each call passes, so the scheme is
/// the C algorithm with Rust randomness. The parity harness checks itself against it.
pub struct OracleSignatureScheme {
    description: &'static SignatureDescription,
}

impl OracleSignatureScheme {
    /// The C scheme of a liboqs name, or `None` when the C library does not know it.
    pub fn named(name: &str) -> Option<Self> {
        let description =
            COracle::new(OracleRandomness::nist([0; 48])).signatureDescription(name)?;
        // A test makes a few schemes, so each description lives for the rest of the process,
        // as the trait asks.
        Some(OracleSignatureScheme {
            description: Box::leak(Box::new(description)),
        })
    }
}

impl Signing for OracleSignatureScheme {
    fn description(&self) -> &'static SignatureDescription {
        self.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        COracle::new(OracleRandomness::source(random))
            .generateSignatureKeyPair(self.description.name)
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        COracle::new(OracleRandomness::source(random)).sign(
            self.description.name,
            message,
            secretKey,
        )
    }

    fn signWithContext(
        &self,
        message: &[u8],
        context: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        COracle::new(OracleRandomness::source(random)).signWithContext(
            self.description.name,
            message,
            context,
            secretKey,
        )
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        COracle::new(OracleRandomness::nist([0; 48])).isValidSignature(
            self.description.name,
            signature,
            message,
            publicKey,
        )
    }

    fn isValidSignatureWithContext(
        &self,
        signature: &[u8],
        message: &[u8],
        context: &[u8],
        publicKey: &[u8],
    ) -> bool {
        COracle::new(OracleRandomness::nist([0; 48])).isValidSignatureWithContext(
            self.description.name,
            signature,
            message,
            context,
            publicKey,
        )
    }
}
