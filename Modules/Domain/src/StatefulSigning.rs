use crate::{KeyStatePersisting, RandomGenerating};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, StatefulSignatureDescription};
use alloc::vec::Vec;

/// The capability of a stateful hash-based signature scheme, such as XMSS or LMS.
///
/// Each signature uses one one-time key of the secret key. The secret key advances with each
/// signature, and a second use of the same state breaks the scheme.
pub trait StatefulSigning: Sync {
    /// The fixed facts of the scheme.
    fn description(&self) -> &'static StatefulSignatureDescription;

    /// Generates a key pair with random bytes from a source.
    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError>;

    /// Signs a message, advances the secret key and saves the advanced key through
    /// `persisting`. The signature comes back only when the save succeeds.
    fn sign(
        &self,
        message: &[u8],
        secretKey: &mut SecretBytes,
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError>;

    /// True when a signature of a message is valid for a public key.
    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool;

    /// The number of signatures that a secret key can still make.
    fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError>;

    /// The number of signatures that a secret key can make over its whole life.
    fn totalSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError>;

    /// Saves an advanced secret key and then releases its signature.
    ///
    /// This is the one place of the rule "persist before release". A scheme calls it as the
    /// last step of `sign`.
    fn releaseSignature(
        &self,
        signature: Vec<u8>,
        advancedSecretKey: &[u8],
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        persisting
            .persist(advancedSecretKey)
            .map_err(|_| OQSError::persistenceFailed)?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::StatefulSigning;
    use crate::testDoubles::{CountingScheme, RecordingStore};
    use OQSNativeEntities::{OQSError, SecretBytes};

    #[test]
    fn signatureIsReleasedAfterTheAdvancedKeyIsSaved() {
        let scheme = CountingScheme;
        let mut secretKey = SecretBytes::new(vec![0]);
        let mut store = RecordingStore::accepting();
        let signature = scheme
            .sign(b"message", &mut secretKey, &mut store)
            .expect("signature");
        assert_eq!(signature, vec![0]);
        assert_eq!(store.saved, vec![vec![1]]);
        assert_eq!(secretKey.bytes(), &[1]);
    }

    #[test]
    fn failedSaveReleasesNoSignature() {
        let scheme = CountingScheme;
        let mut secretKey = SecretBytes::new(vec![0]);
        let mut store = RecordingStore::refusing();
        assert_eq!(
            scheme.sign(b"message", &mut secretKey, &mut store),
            Err(OQSError::persistenceFailed)
        );
        assert!(store.saved.is_empty());
    }
}
