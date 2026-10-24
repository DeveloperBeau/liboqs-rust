/// The fixed facts of one key encapsulation mechanism, as the liboqs `OQS_KEM` structure gives
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KEMDescription {
    /// The liboqs name of the algorithm, such as `ML-KEM-768`.
    pub name: &'static str,
    /// The version of the specification that the implementation follows.
    pub algorithmVersion: &'static str,
    /// The NIST security level that the designers claim, from 1 to 5.
    pub claimedNISTLevel: u8,
    /// True when the mechanism claims security against chosen-ciphertext attacks (IND-CCA).
    pub isINDCCASecure: bool,
    /// The length of a public key in bytes.
    pub publicKeyLength: usize,
    /// The length of a secret key in bytes.
    pub secretKeyLength: usize,
    /// The length of a ciphertext in bytes.
    pub ciphertextLength: usize,
    /// The length of a shared secret in bytes.
    pub sharedSecretLength: usize,
    /// The length of the seed of key generation from a seed, or zero without that form.
    pub keyPairSeedLength: usize,
    /// The length of the seed of encapsulation from a seed, or zero without that form.
    pub encapsulationSeedLength: usize,
}
