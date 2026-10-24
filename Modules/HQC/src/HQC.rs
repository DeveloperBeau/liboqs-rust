use crate::Parameters;
use crate::hashFunctions::HashFunctions;
use crate::parameters::{hqc1, hqc3, hqc5, saltLength, seedLength, sharedSecretLength};
use crate::publicKeyEncryption::PublicKeyEncryption;
use OQSNativeDomain::{InputLength, KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};
use alloc::vec::Vec;

/// HQC, the Hamming Quasi-Cyclic key encapsulation mechanism, with one parameter set.
///
/// The three parameter sets are `HQC::hqc1`, `HQC::hqc3` and `HQC::hqc5`. Each gives the bytes
/// of the liboqs algorithm of the same name, whose C code is the reference code of the HQC
/// team. A key pair draws one request of 32 random bytes. An encapsulation draws two requests,
/// the message of `k` bytes and then the salt of 16 bytes, as the C code does. Decapsulation
/// encrypts again and gives the rejection secret `J` for any ciphertext that differs, with no
/// error, as the C code does. liboqs gives HQC no seeded forms.
pub struct HQC {
    parameters: &'static Parameters,
}

impl HQC {
    /// HQC-1, NIST security category 1.
    pub const hqc1: HQC = HQC { parameters: &hqc1 };

    /// HQC-3, NIST security category 3.
    pub const hqc3: HQC = HQC { parameters: &hqc3 };

    /// HQC-5, NIST security category 5.
    pub const hqc5: HQC = HQC { parameters: &hqc5 };

    fn publicKeyEncryption(&self) -> PublicKeyEncryption<'static> {
        PublicKeyEncryption::new(self.parameters)
    }

    /// `crypto_kem_keypair` after the random request: the key pair of the seed `seed_kem`.
    ///
    /// The secret key is the public key, the decryption key, `sigma` and `seed_kem`.
    fn keyPair(&self, seed: &[u8; seedLength]) -> KeyPair {
        let parameters = self.parameters;
        let mut expander = HashFunctions::expander(seed);
        let mut encryptionSeed = [0u8; seedLength];
        expander.squeeze(&mut encryptionSeed);
        let mut sigma = alloc::vec![0u8; parameters.messageLength];
        expander.squeeze(&mut sigma);
        let (publicKey, decryptionKey) = self.publicKeyEncryption().keyPair(&encryptionSeed);
        let mut secretKey = Vec::with_capacity(parameters.description.secretKeyLength);
        secretKey.extend_from_slice(&publicKey);
        secretKey.extend_from_slice(&decryptionKey);
        secretKey.extend_from_slice(&sigma);
        secretKey.extend_from_slice(seed);
        KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        }
    }
}

impl KeyEncapsulating for HQC {
    fn description(&self) -> &'static KEMDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seed = [0u8; seedLength];
        random.fillRandomBytes(&mut seed);
        Ok(self.keyPair(&seed))
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        let publicKey =
            InputLength::checked(publicKey, self.parameters.description.publicKeyLength)?;
        let mut message = alloc::vec![0u8; self.parameters.messageLength];
        random.fillRandomBytes(&mut message);
        let mut salt = [0u8; saltLength];
        random.fillRandomBytes(&mut salt);
        let publicKeyHash = HashFunctions::publicKeyHash(publicKey);
        let expanded = HashFunctions::sharedSecretAndRandomness(&publicKeyHash, &message, &salt);
        let theta: [u8; seedLength] = expanded[sharedSecretLength..].try_into().expect("32 bytes");
        let mut ciphertext = self
            .publicKeyEncryption()
            .encrypt(publicKey, &message, &theta);
        ciphertext.extend_from_slice(&salt);
        Ok(Encapsulation {
            ciphertext,
            sharedSecret: SecretBytes::new(expanded[..sharedSecretLength].to_vec()),
        })
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let parameters = self.parameters;
        let description = &parameters.description;
        let ciphertext = InputLength::checked(ciphertext, description.ciphertextLength)?;
        let secretKey = InputLength::checked(secretKey, description.secretKeyLength)?;
        let (publicKey, rest) = secretKey.split_at(description.publicKeyLength);
        let (decryptionKey, rest) = rest.split_at(seedLength);
        let sigma = &rest[..parameters.messageLength];
        let byteCount = parameters.vectorByteCount();
        let (encodedU, rest) = ciphertext.split_at(byteCount);
        let (encodedV, salt) = rest.split_at(parameters.codewordByteCount());
        let encryption = self.publicKeyEncryption();
        let message = encryption.decrypt(decryptionKey, encodedU, encodedV);
        let publicKeyHash = HashFunctions::publicKeyHash(publicKey);
        let expanded = HashFunctions::sharedSecretAndRandomness(&publicKeyHash, &message, salt);
        let theta: [u8; seedLength] = expanded[sharedSecretLength..].try_into().expect("32 bytes");
        let mut reencrypted = encryption.encrypt(publicKey, &message, &theta);
        reencrypted.extend_from_slice(salt);
        let mut sharedSecret = HashFunctions::rejectionSecret(&publicKeyHash, sigma, ciphertext);
        // The choice of the secret depends on a secret value, so it uses a mask, not a branch.
        let differences = reencrypted
            .iter()
            .zip(ciphertext)
            .fold(0u8, |accumulated, (left, right)| {
                accumulated | (left ^ right)
            });
        let isEqualMask = (u16::from(differences).wrapping_sub(1) >> 8) as u8;
        for (byte, candidate) in sharedSecret.iter_mut().zip(&expanded[..sharedSecretLength]) {
            *byte ^= isEqualMask & (*byte ^ candidate);
        }
        Ok(SecretBytes::new(sharedSecret.to_vec()))
    }
}
