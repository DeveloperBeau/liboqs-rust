//! Small implementations of the capability traits, for the tests of the default methods.

use crate::{KeyEncapsulating, KeyStatePersisting, RandomGenerating, Signing, StatefulSigning};
use OQSNativeEntities::{
    Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes, SignatureDescription,
    StatefulSignatureDescription,
};
use alloc::vec::Vec;

/// A random source that gives the bytes 0, 1, 2 and so on.
#[derive(Default)]
pub struct CountingRandom {
    next: u8,
}

impl RandomGenerating for CountingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        for byte in bytes.iter_mut() {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }
}

const fixedMechanismDescription: KEMDescription = KEMDescription {
    name: "Fixed-KEM",
    algorithmVersion: "test",
    claimedNISTLevel: 1,
    isINDCCASecure: false,
    publicKeyLength: 1,
    secretKeyLength: 1,
    ciphertextLength: 1,
    sharedSecretLength: 1,
    keyPairSeedLength: 0,
    encapsulationSeedLength: 0,
};

/// A mechanism whose shared secret is the secret key, carried in the clear. Tests only.
pub struct FixedMechanism;

impl KeyEncapsulating for FixedMechanism {
    fn description(&self) -> &'static KEMDescription {
        &fixedMechanismDescription
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut secret = [0u8; 1];
        random.fillRandomBytes(&mut secret);
        Ok(KeyPair {
            publicKey: secret.to_vec(),
            secretKey: SecretBytes::new(secret.to_vec()),
        })
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        _: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        Ok(Encapsulation {
            ciphertext: publicKey.to_vec(),
            sharedSecret: SecretBytes::new(publicKey.to_vec()),
        })
    }

    fn decapsulate(&self, ciphertext: &[u8], _: &[u8]) -> Result<SecretBytes, OQSError> {
        Ok(SecretBytes::new(ciphertext.to_vec()))
    }
}

const fixedSchemeDescription: SignatureDescription = SignatureDescription {
    name: "Fixed-SIG",
    algorithmVersion: "test",
    claimedNISTLevel: 1,
    isEUFCMASecure: false,
    isSUFCMASecure: false,
    supportsContext: false,
    publicKeyLength: 1,
    secretKeyLength: 1,
    signatureLength: 1,
};

/// A scheme whose signature is the length of the message. Tests only.
pub struct FixedScheme;

impl Signing for FixedScheme {
    fn description(&self) -> &'static SignatureDescription {
        &fixedSchemeDescription
    }

    fn generateKeyPair(&self, _: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        Ok(KeyPair {
            publicKey: vec![1],
            secretKey: SecretBytes::new(vec![1]),
        })
    }

    fn sign(
        &self,
        message: &[u8],
        _: &[u8],
        _: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        Ok(vec![message.len() as u8])
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], _: &[u8]) -> bool {
        signature == [message.len() as u8]
    }
}

const countingSchemeDescription: StatefulSignatureDescription = StatefulSignatureDescription {
    objectIdentifier: 0,
    name: "Counting-STFL",
    algorithmVersion: "test",
    isEUFCMASecure: false,
    isSUFCMASecure: false,
    publicKeyLength: 1,
    secretKeyLength: 1,
    signatureLength: 1,
};

/// A stateful scheme whose secret key is a counter and whose signature is the counter value.
pub struct CountingScheme;

impl StatefulSigning for CountingScheme {
    fn description(&self) -> &'static StatefulSignatureDescription {
        &countingSchemeDescription
    }

    fn generateKeyPair(&self, _: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        Ok(KeyPair {
            publicKey: vec![0],
            secretKey: SecretBytes::new(vec![0]),
        })
    }

    fn sign(
        &self,
        _: &[u8],
        secretKey: &mut SecretBytes,
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        let signature = vec![secretKey.bytes()[0]];
        secretKey.mutableBytes()[0] += 1;
        self.releaseSignature(signature, secretKey.bytes(), persisting)
    }

    fn isValidSignature(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
        true
    }

    fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        Ok(255 - u64::from(secretKey[0]))
    }

    fn totalSignatureCount(&self, _: &[u8]) -> Result<u64, OQSError> {
        Ok(255)
    }
}

/// A key store that records each save, or refuses every save.
pub struct RecordingStore {
    pub saved: Vec<Vec<u8>>,
    isRefusing: bool,
}

impl RecordingStore {
    pub fn accepting() -> Self {
        RecordingStore {
            saved: Vec::new(),
            isRefusing: false,
        }
    }

    pub fn refusing() -> Self {
        RecordingStore {
            saved: Vec::new(),
            isRefusing: true,
        }
    }
}

impl KeyStatePersisting for RecordingStore {
    fn persist(&mut self, secretKey: &[u8]) -> Result<(), OQSError> {
        if self.isRefusing {
            return Err(OQSError::operationFailed);
        }
        self.saved.push(secretKey.to_vec());
        Ok(())
    }
}
