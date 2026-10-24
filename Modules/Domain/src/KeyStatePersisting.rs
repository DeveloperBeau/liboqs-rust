use OQSNativeEntities::OQSError;

/// The capability to save the advanced state of a stateful secret key before a signature is
/// released.
pub trait KeyStatePersisting {
    /// Saves the bytes of an advanced secret key durably, or returns an error.
    fn persist(&mut self, secretKey: &[u8]) -> Result<(), OQSError>;
}
