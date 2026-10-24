use crate::parameters::{Parameters, kyber512, kyber768, kyber1024};
use crate::publicKeyEncryption::PublicKeyEncryption;
use OQSNativeDomain::{InputLength, KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};
use OQSNativeSHA3::{SHA3256, SHA3512, SHAKE256};
use alloc::vec::Vec;

/// Kyber of round 3 of the NIST process, the predecessor of ML-KEM, as liboqs ships it.
///
/// The three parameter sets are `Kyber::kyber512`, `Kyber::kyber768` and `Kyber::kyber1024`.
/// Each gives the bytes of the liboqs algorithm of the same name, whose C code is the reference
/// code of the Kyber team. Kyber shares the lattice arithmetic of ML-KEM and differs in its
/// hashes: key generation hashes the seed without the rank byte, encapsulation hashes its
/// random message, and the shared secret is a hash of the key and of the ciphertext hash.
/// A key pair draws two requests of 32 random bytes and an encapsulation one, as the C code
/// does. Kyber checks neither the public key nor the secret key.
pub struct Kyber {
    parameters: &'static Parameters,
}

impl Kyber {
    /// Kyber512, security category 1.
    pub const kyber512: Kyber = Kyber {
        parameters: &kyber512,
    };

    /// Kyber768, security category 3.
    pub const kyber768: Kyber = Kyber {
        parameters: &kyber768,
    };

    /// Kyber1024, security category 5.
    pub const kyber1024: Kyber = Kyber {
        parameters: &kyber1024,
    };

    fn publicKeyEncryption(&self) -> PublicKeyEncryption<'static> {
        PublicKeyEncryption::new(self.parameters)
    }

    /// The shared secret of round 3: `SHAKE256(key || H(ciphertext))`, 32 bytes.
    fn sharedSecret(key: &[u8], ciphertext: &[u8]) -> SecretBytes {
        let mut sponge = SHAKE256::new();
        sponge.absorb(key);
        sponge.absorb(&SHA3256::hash(ciphertext));
        let mut secret = [0u8; 32];
        sponge.finalize().squeeze(&mut secret);
        SecretBytes::new(secret.to_vec())
    }
}

impl KeyEncapsulating for Kyber {
    fn description(&self) -> &'static KEMDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seed = [0u8; 32];
        random.fillRandomBytes(&mut seed);
        let (publicKey, pkeSecretKey) = self.publicKeyEncryption().keyPair(&seed);
        let mut rejectionSeed = [0u8; 32];
        random.fillRandomBytes(&mut rejectionSeed);
        let mut secretKey = Vec::with_capacity(self.parameters.description.secretKeyLength);
        secretKey.extend_from_slice(&pkeSecretKey);
        secretKey.extend_from_slice(&publicKey);
        secretKey.extend_from_slice(&SHA3256::hash(&publicKey));
        secretKey.extend_from_slice(&rejectionSeed);
        Ok(KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        })
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        let publicKey =
            InputLength::checked(publicKey, self.parameters.description.publicKeyLength)?;
        let mut randomMessage = [0u8; 32];
        random.fillRandomBytes(&mut randomMessage);
        // The reference code does not release the bytes of the random source.
        let message = SHA3256::hash(&randomMessage);
        let mut hash = SHA3512::new();
        hash.absorb(&message);
        hash.absorb(&SHA3256::hash(publicKey));
        let expanded = hash.finalize();
        let randomness: [u8; 32] = expanded[32..].try_into().expect("32 bytes");
        let ciphertext = self
            .publicKeyEncryption()
            .encrypt(publicKey, &message, &randomness);
        let sharedSecret = Self::sharedSecret(&expanded[..32], &ciphertext);
        Ok(Encapsulation {
            ciphertext,
            sharedSecret,
        })
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let description = &self.parameters.description;
        let ciphertext = InputLength::checked(ciphertext, description.ciphertextLength)?;
        let secretKey = InputLength::checked(secretKey, description.secretKeyLength)?;
        let pkeLength = 384 * self.parameters.rank;
        let publicKey = &secretKey[pkeLength..pkeLength + description.publicKeyLength];
        let publicKeyHash = &secretKey[secretKey.len() - 64..secretKey.len() - 32];
        let rejectionSeed = &secretKey[secretKey.len() - 32..];
        let encryption = self.publicKeyEncryption();
        let message = encryption.decrypt(&secretKey[..pkeLength], ciphertext);
        let mut hash = SHA3512::new();
        hash.absorb(&message);
        hash.absorb(publicKeyHash);
        let expanded = hash.finalize();
        let randomness: [u8; 32] = expanded[32..].try_into().expect("32 bytes");
        let reencrypted = encryption.encrypt(publicKey, &message, &randomness);
        // The choice of the key depends on a secret value, so it uses a mask, not a branch.
        let differences = reencrypted
            .iter()
            .zip(ciphertext)
            .fold(0u8, |accumulated, (left, right)| {
                accumulated | (left ^ right)
            });
        let isDifferentMask = !((u16::from(differences).wrapping_sub(1) >> 8) as u8);
        let mut key = [0u8; 32];
        key.copy_from_slice(&expanded[..32]);
        for (byte, replacement) in key.iter_mut().zip(rejectionSeed) {
            *byte ^= isDifferentMask & (*byte ^ replacement);
        }
        Ok(Self::sharedSecret(&key, ciphertext))
    }
}
