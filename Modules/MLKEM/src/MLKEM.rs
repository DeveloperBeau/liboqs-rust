use crate::parameters::{Parameters, mlkem512, mlkem768, mlkem1024};
use crate::polynomial::Polynomial;
use crate::publicKeyEncryption::PublicKeyEncryption;
use OQSNativeDomain::{InputLength, KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};
use OQSNativeSHA3::{SHA3256, SHA3512, SHAKE256};
use alloc::vec::Vec;

/// ML-KEM, the module-lattice key encapsulation mechanism of FIPS 203, with one parameter set.
///
/// The three parameter sets are `MLKEM::mlkem512`, `MLKEM::mlkem768` and `MLKEM::mlkem1024`.
/// Each gives the bytes of the liboqs algorithm of the same name. A key pair draws 64 random
/// bytes in one request and an encapsulation draws 32, as liboqs does. Encapsulation checks
/// the modulus of the public key and decapsulation checks the hash of the public key in the
/// secret key, FIPS 203, Section 7, and each failed check is `OQSError::operationFailed`.
pub struct MLKEM {
    parameters: &'static Parameters,
}

impl MLKEM {
    /// ML-KEM-512, security category 1.
    pub const mlkem512: MLKEM = MLKEM {
        parameters: &mlkem512,
    };

    /// ML-KEM-768, security category 3.
    pub const mlkem768: MLKEM = MLKEM {
        parameters: &mlkem768,
    };

    /// ML-KEM-1024, security category 5.
    pub const mlkem1024: MLKEM = MLKEM {
        parameters: &mlkem1024,
    };

    fn publicKeyEncryption(&self) -> PublicKeyEncryption<'static> {
        PublicKeyEncryption::new(self.parameters)
    }

    /// `ML-KEM.KeyGen_internal` of FIPS 203, Algorithm 16, from the seed `d || z`.
    fn keyPair(&self, seed: &[u8; 64]) -> KeyPair {
        let pkeSeed: [u8; 32] = seed[..32].try_into().expect("32 bytes");
        let (publicKey, pkeSecretKey) = self.publicKeyEncryption().keyPair(&pkeSeed);
        let mut secretKey = Vec::with_capacity(self.parameters.description.secretKeyLength);
        secretKey.extend_from_slice(&pkeSecretKey);
        secretKey.extend_from_slice(&publicKey);
        secretKey.extend_from_slice(&SHA3256::hash(&publicKey));
        secretKey.extend_from_slice(&seed[32..]);
        KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        }
    }

    /// `ML-KEM.Encaps_internal` of FIPS 203, Algorithm 17, after the modulus check of the
    /// public key.
    fn encapsulation(
        &self,
        publicKey: &[u8],
        message: &[u8; 32],
    ) -> Result<Encapsulation, OQSError> {
        let publicKey =
            InputLength::checked(publicKey, self.parameters.description.publicKeyLength)?;
        if !Polynomial::isCanonicalEncoding(&publicKey[..publicKey.len() - 32]) {
            return Err(OQSError::operationFailed);
        }
        let mut hash = SHA3512::new();
        hash.absorb(message);
        hash.absorb(&SHA3256::hash(publicKey));
        let expanded = hash.finalize();
        let randomness: [u8; 32] = expanded[32..].try_into().expect("32 bytes");
        let ciphertext = self
            .publicKeyEncryption()
            .encrypt(publicKey, message, &randomness);
        Ok(Encapsulation {
            ciphertext,
            sharedSecret: SecretBytes::new(expanded[..32].to_vec()),
        })
    }

    /// `ML-KEM.Decaps_internal` of FIPS 203, Algorithm 18, after the hash check of the secret
    /// key.
    fn decapsulation(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let description = &self.parameters.description;
        let ciphertext = InputLength::checked(ciphertext, description.ciphertextLength)?;
        let secretKey = InputLength::checked(secretKey, description.secretKeyLength)?;
        let pkeLength = 384 * self.parameters.rank;
        let publicKey = &secretKey[pkeLength..pkeLength + description.publicKeyLength];
        let publicKeyHash = &secretKey[secretKey.len() - 64..secretKey.len() - 32];
        let rejectionSeed = &secretKey[secretKey.len() - 32..];
        if SHA3256::hash(publicKey) != *publicKeyHash {
            return Err(OQSError::operationFailed);
        }
        let encryption = self.publicKeyEncryption();
        let message = encryption.decrypt(&secretKey[..pkeLength], ciphertext);
        let mut hash = SHA3512::new();
        hash.absorb(&message);
        hash.absorb(publicKeyHash);
        let expanded = hash.finalize();
        let randomness: [u8; 32] = expanded[32..].try_into().expect("32 bytes");
        let mut rejectionSponge = SHAKE256::new();
        rejectionSponge.absorb(rejectionSeed);
        rejectionSponge.absorb(ciphertext);
        let mut sharedSecret = [0u8; 32];
        rejectionSponge.finalize().squeeze(&mut sharedSecret);
        let reencrypted = encryption.encrypt(publicKey, &message, &randomness);
        // The choice of the secret depends on a secret value, so it uses a mask, not a branch.
        let differences = reencrypted
            .iter()
            .zip(ciphertext)
            .fold(0u8, |accumulated, (left, right)| {
                accumulated | (left ^ right)
            });
        let isEqualMask = (u16::from(differences).wrapping_sub(1) >> 8) as u8;
        for (byte, candidate) in sharedSecret.iter_mut().zip(&expanded[..32]) {
            *byte ^= isEqualMask & (*byte ^ candidate);
        }
        Ok(SecretBytes::new(sharedSecret.to_vec()))
    }
}

impl KeyEncapsulating for MLKEM {
    fn description(&self) -> &'static KEMDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seed = [0u8; 64];
        random.fillRandomBytes(&mut seed);
        Ok(self.keyPair(&seed))
    }

    fn generateKeyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, OQSError> {
        let seed: &[u8; 64] = InputLength::checked(seed, 64)?
            .try_into()
            .expect("64 bytes");
        Ok(self.keyPair(seed))
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        InputLength::checked(publicKey, self.parameters.description.publicKeyLength)?;
        let mut message = [0u8; 32];
        random.fillRandomBytes(&mut message);
        self.encapsulation(publicKey, &message)
    }

    fn encapsulateWithSeed(
        &self,
        publicKey: &[u8],
        seed: &[u8],
    ) -> Result<Encapsulation, OQSError> {
        let message: &[u8; 32] = InputLength::checked(seed, 32)?
            .try_into()
            .expect("32 bytes");
        self.encapsulation(publicKey, message)
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        self.decapsulation(ciphertext, secretKey)
    }
}
