use crate::{COracle, OracleRandomness};
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};

/// A KEM of the C library behind the Rust capability interface.
///
/// The C code reads its random bytes from the source that each call passes, so the mechanism
/// is the C algorithm with Rust randomness. The parity harness checks itself against it.
pub struct OracleMechanism {
    description: &'static KEMDescription,
}

impl OracleMechanism {
    /// The C mechanism of a liboqs name, or `None` when the C library does not know it.
    pub fn named(name: &str) -> Option<Self> {
        let description = COracle::new(OracleRandomness::nist([0; 48])).kemDescription(name)?;
        // A test makes a few mechanisms, so each description lives for the rest of the process,
        // as the trait asks.
        Some(OracleMechanism {
            description: Box::leak(Box::new(description)),
        })
    }
}

impl KeyEncapsulating for OracleMechanism {
    fn description(&self) -> &'static KEMDescription {
        self.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        COracle::new(OracleRandomness::source(random)).generateKEMKeyPair(self.description.name)
    }

    fn generateKeyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, OQSError> {
        COracle::new(OracleRandomness::nist([0; 48]))
            .generateKEMKeyPairFromSeed(self.description.name, seed)
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        COracle::new(OracleRandomness::source(random)).encapsulate(self.description.name, publicKey)
    }

    fn encapsulateWithSeed(
        &self,
        publicKey: &[u8],
        seed: &[u8],
    ) -> Result<Encapsulation, OQSError> {
        COracle::new(OracleRandomness::nist([0; 48])).encapsulateWithSeed(
            self.description.name,
            publicKey,
            seed,
        )
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        COracle::new(OracleRandomness::nist([0; 48])).decapsulate(
            self.description.name,
            ciphertext,
            secretKey,
        )
    }
}
