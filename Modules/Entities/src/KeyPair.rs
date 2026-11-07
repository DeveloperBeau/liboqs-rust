use crate::SecretBytes;
use alloc::vec::Vec;

/// A public key and the secret key that belongs to it.
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// The public key, in the byte format of liboqs.
    pub publicKey: Vec<u8>,
    /// The secret key, in the byte format of liboqs.
    pub secretKey: SecretBytes,
}
