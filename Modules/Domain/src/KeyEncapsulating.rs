use crate::RandomGenerating;
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};

/// The capability of a key encapsulation mechanism: one parameter set of one family.
///
/// Inputs and outputs use the byte formats of liboqs, so a key or a ciphertext from the C
/// library works here and the other way around.
pub trait KeyEncapsulating: Sync {
    /// The fixed facts of the mechanism.
    fn description(&self) -> &'static KEMDescription;

    /// Generates a key pair with random bytes from a source.
    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError>;

    /// Generates a key pair from a seed, as liboqs `keypair_derand` does.
    ///
    /// A mechanism without that form returns `OQSError::seedNotSupported`.
    fn generateKeyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, OQSError> {
        let _ = seed;
        Err(OQSError::seedNotSupported)
    }

    /// Makes a shared secret and a ciphertext that carries it to the holder of a public key.
    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError>;

    /// Encapsulates with a seed in place of random bytes, as liboqs `encaps_derand` does.
    ///
    /// A mechanism without that form returns `OQSError::seedNotSupported`.
    fn encapsulateWithSeed(
        &self,
        publicKey: &[u8],
        seed: &[u8],
    ) -> Result<Encapsulation, OQSError> {
        let _ = (publicKey, seed);
        Err(OQSError::seedNotSupported)
    }

    /// Recovers the shared secret from a ciphertext with the secret key.
    ///
    /// A mechanism with implicit rejection returns a pseudorandom secret for a changed
    /// ciphertext, as the C library does, and not an error.
    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError>;
}

#[cfg(test)]
mod tests {
    use crate::KeyEncapsulating;
    use crate::testDoubles::{CountingRandom, FixedMechanism};
    use OQSNativeEntities::OQSError;

    #[test]
    fn seedFormsAreNotSupportedUnlessAMechanismProvidesThem() {
        let mechanism = FixedMechanism;
        assert_eq!(
            mechanism.generateKeyPairFromSeed(&[0; 64]).err(),
            Some(OQSError::seedNotSupported)
        );
        assert_eq!(
            mechanism.encapsulateWithSeed(&[0; 4], &[0; 32]).err(),
            Some(OQSError::seedNotSupported)
        );
    }

    #[test]
    fn aMechanismWorksThroughTheTraitObject() {
        let mechanism: &dyn KeyEncapsulating = &FixedMechanism;
        let mut random = CountingRandom::default();
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let secret = mechanism
            .decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())
            .expect("decapsulation");
        assert_eq!(secret.bytes(), encapsulation.sharedSecret.bytes());
        assert_eq!(mechanism.description().name, "Fixed-KEM");
    }
}
