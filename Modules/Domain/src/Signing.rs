use crate::RandomGenerating;
use OQSNativeEntities::{KeyPair, OQSError, SignatureDescription};
use alloc::vec::Vec;

/// The capability of a signature scheme: one parameter set of one family.
///
/// Inputs and outputs use the byte formats of liboqs. The two forms of signing and of
/// verification match `OQS_SIG_sign` and `OQS_SIG_sign_with_ctx_str` of liboqs.
pub trait Signing: Sync {
    /// The fixed facts of the scheme.
    fn description(&self) -> &'static SignatureDescription;

    /// Generates a key pair with random bytes from a source.
    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError>;

    /// Signs a message with a secret key, as `OQS_SIG_sign` does.
    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError>;

    /// Signs a message under a context string, as `OQS_SIG_sign_with_ctx_str` does.
    ///
    /// A scheme without context support signs only with an empty context, and then gives the
    /// signature of `sign`. A scheme with context support overrides this method.
    fn signWithContext(
        &self,
        message: &[u8],
        context: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        if context.is_empty() {
            self.sign(message, secretKey, random)
        } else {
            Err(OQSError::contextNotSupported)
        }
    }

    /// True when a signature of a message is valid for a public key, as `OQS_SIG_verify` says.
    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool;

    /// True when a signature of a message under a context string is valid for a public key,
    /// as `OQS_SIG_verify_with_ctx_str` says.
    ///
    /// A scheme without context support accepts only an empty context. A scheme with context
    /// support overrides this method.
    fn isValidSignatureWithContext(
        &self,
        signature: &[u8],
        message: &[u8],
        context: &[u8],
        publicKey: &[u8],
    ) -> bool {
        context.is_empty() && self.isValidSignature(signature, message, publicKey)
    }
}

#[cfg(test)]
mod tests {
    use crate::Signing;
    use crate::testDoubles::{CountingRandom, FixedScheme};
    use OQSNativeEntities::OQSError;

    #[test]
    fn emptyContextGivesThePlainSignature() {
        let scheme = FixedScheme;
        let mut random = CountingRandom::default();
        let plain = scheme.sign(b"message", &[1], &mut random).expect("plain");
        let withContext = scheme
            .signWithContext(b"message", b"", &[1], &mut random)
            .expect("context");
        assert_eq!(plain, withContext);
    }

    #[test]
    fn nonEmptyContextIsRejectedWithoutContextSupport() {
        let scheme = FixedScheme;
        let mut random = CountingRandom::default();
        assert_eq!(
            scheme.signWithContext(b"message", b"ctx", &[1], &mut random),
            Err(OQSError::contextNotSupported)
        );
    }

    #[test]
    fn verificationWithContextAcceptsOnlyAnEmptyContext() {
        let scheme = FixedScheme;
        let mut random = CountingRandom::default();
        let signature = scheme
            .sign(b"message", &[1], &mut random)
            .expect("signature");
        assert!(scheme.isValidSignatureWithContext(&signature, b"message", b"", &[1]));
        assert!(!scheme.isValidSignatureWithContext(&signature, b"message", b"ctx", &[1]));
        assert!(!scheme.isValidSignatureWithContext(&signature, b"other", b"", &[1]));
    }
}
