use crate::SecretBytes;
use alloc::vec::Vec;

/// The result of a key encapsulation: a ciphertext for the holder of the secret key, and the
/// shared secret that the ciphertext carries.
#[derive(Clone, Debug)]
pub struct Encapsulation {
    /// The ciphertext, in the byte format of liboqs.
    pub ciphertext: Vec<u8>,
    /// The shared secret.
    pub sharedSecret: SecretBytes,
}
