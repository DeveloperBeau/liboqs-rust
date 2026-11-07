use crate::parameters::{
    eFrodoKEM640AES, eFrodoKEM640SHAKE, eFrodoKEM976AES, eFrodoKEM976SHAKE, eFrodoKEM1344AES,
    eFrodoKEM1344SHAKE, frodoKEM640AES, frodoKEM640SHAKE, frodoKEM976AES, frodoKEM976SHAKE,
    frodoKEM1344AES, frodoKEM1344SHAKE,
};
use crate::{ConstantTime, MatrixArithmetic, Packing, Parameters};
use OQSNativeDomain::{InputLength, KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};
use alloc::vec;
use alloc::vec::Vec;

/// FrodoKEM, the key encapsulation mechanism of the learning with errors problem, with one
/// parameter set.
///
/// The twelve sets are the liboqs algorithms of the same names, from `FrodoKEM::frodoKEM640AES`
/// to `FrodoKEM::eFrodoKEM1344SHAKE`, and each gives their bytes. A key pair draws one request
/// of random bytes and an encapsulation draws one, as the C code does. The ephemeral sets of
/// eFrodoKEM put no salt in a ciphertext. FrodoKEM checks neither key, and a changed ciphertext
/// gives the implicit-rejection secret, so only an input of a wrong length is an error. liboqs
/// gives FrodoKEM no seeded forms, so both seeded methods return `OQSError::seedNotSupported`.
pub struct FrodoKEM {
    parameters: &'static Parameters,
}

/// The first byte of the hash input of the noise matrices of a key pair.
const keyPairNoiseDomain: u8 = 0x5F;

/// The first byte of the hash input of the noise matrices of an encapsulation.
const encapsulationNoiseDomain: u8 = 0x96;

/// The matrices of an encryption, and the key `k` of its shared secret.
struct Encryption {
    /// The matrix `B'`, not reduced.
    ciphertextMatrix: Vec<u16>,
    /// The matrix `C`, reduced modulo `q`.
    messageMatrix: Vec<u16>,
    /// The key `k` of the shared secret.
    key: SecretBytes,
}

impl FrodoKEM {
    /// FrodoKEM-640-AES, security category 1.
    pub const frodoKEM640AES: FrodoKEM = FrodoKEM {
        parameters: &frodoKEM640AES,
    };

    /// FrodoKEM-640-SHAKE, security category 1.
    pub const frodoKEM640SHAKE: FrodoKEM = FrodoKEM {
        parameters: &frodoKEM640SHAKE,
    };

    /// FrodoKEM-976-AES, security category 3.
    pub const frodoKEM976AES: FrodoKEM = FrodoKEM {
        parameters: &frodoKEM976AES,
    };

    /// FrodoKEM-976-SHAKE, security category 3.
    pub const frodoKEM976SHAKE: FrodoKEM = FrodoKEM {
        parameters: &frodoKEM976SHAKE,
    };

    /// FrodoKEM-1344-AES, security category 5.
    pub const frodoKEM1344AES: FrodoKEM = FrodoKEM {
        parameters: &frodoKEM1344AES,
    };

    /// FrodoKEM-1344-SHAKE, security category 5.
    pub const frodoKEM1344SHAKE: FrodoKEM = FrodoKEM {
        parameters: &frodoKEM1344SHAKE,
    };

    /// eFrodoKEM-640-AES, the ephemeral form of FrodoKEM-640-AES, security category 1.
    pub const eFrodoKEM640AES: FrodoKEM = FrodoKEM {
        parameters: &eFrodoKEM640AES,
    };

    /// eFrodoKEM-640-SHAKE, the ephemeral form of FrodoKEM-640-SHAKE, security category 1.
    pub const eFrodoKEM640SHAKE: FrodoKEM = FrodoKEM {
        parameters: &eFrodoKEM640SHAKE,
    };

    /// eFrodoKEM-976-AES, the ephemeral form of FrodoKEM-976-AES, security category 3.
    pub const eFrodoKEM976AES: FrodoKEM = FrodoKEM {
        parameters: &eFrodoKEM976AES,
    };

    /// eFrodoKEM-976-SHAKE, the ephemeral form of FrodoKEM-976-SHAKE, security category 3.
    pub const eFrodoKEM976SHAKE: FrodoKEM = FrodoKEM {
        parameters: &eFrodoKEM976SHAKE,
    };

    /// eFrodoKEM-1344-AES, the ephemeral form of FrodoKEM-1344-AES, security category 5.
    pub const eFrodoKEM1344AES: FrodoKEM = FrodoKEM {
        parameters: &eFrodoKEM1344AES,
    };

    /// eFrodoKEM-1344-SHAKE, the ephemeral form of FrodoKEM-1344-SHAKE, security category 5.
    pub const eFrodoKEM1344SHAKE: FrodoKEM = FrodoKEM {
        parameters: &eFrodoKEM1344SHAKE,
    };

    /// The noise values of the hash of a domain byte and a seed: each little-endian 16-bit
    /// value of the hash output becomes a sample of the error distribution.
    fn noise(&self, domain: u8, seed: &[u8], count: usize) -> Vec<u16> {
        let parameters = self.parameters;
        let mut bytes = SecretBytes::zeroed(2 * count);
        parameters
            .hashFunction
            .hash(&[&[domain], seed], bytes.mutableBytes());
        let mut values = vec![0u16; count];
        Packing::decodeLittleEndian(bytes.bytes(), &mut values);
        parameters.errorDistribution.sample(&mut values);
        values
    }

    /// The encryption of the message of a hash input `pkh || mu || salt` under a public key:
    /// the shared step of `crypto_kem_enc` and of the re-encryption of `crypto_kem_dec`.
    fn encryption(&self, publicKey: &[u8], hashInput: &[u8]) -> Encryption {
        let parameters = self.parameters;
        let secretLength = parameters.description.sharedSecretLength;
        let mut hashOutput = SecretBytes::zeroed(parameters.noiseSeedLength + secretLength);
        parameters
            .hashFunction
            .hash(&[hashInput], hashOutput.mutableBytes());
        let (noiseSeed, key) = hashOutput.bytes().split_at(parameters.noiseSeedLength);
        let count = parameters.matrixValueCount();
        let width = Parameters::shortDimension;
        let noise = self.noise(
            encapsulationNoiseDomain,
            noiseSeed,
            2 * count + width * width,
        );
        let (ephemeralSecret, errors) = noise.split_at(count);
        let (firstError, secondError) = errors.split_at(count);
        let arithmetic = MatrixArithmetic::new(parameters);
        let matrixSeed: &[u8; Parameters::matrixSeedLength] = publicKey
            [..Parameters::matrixSeedLength]
            .try_into()
            .expect("the matrix seed");
        let ciphertextMatrix = arithmetic.ciphertextMatrix(matrixSeed, ephemeralSecret, firstError);
        let publicKeyMatrix = Packing::unpacked(
            &publicKey[Parameters::matrixSeedLength..],
            parameters.modulusBits,
        );
        let mask = arithmetic.encryptionMask(&publicKeyMatrix, ephemeralSecret, secondError);
        let message = &hashInput[secretLength..secretLength + parameters.messageLength()];
        let messageMatrix = arithmetic.sum(&mask, &arithmetic.encoded(message));
        Encryption {
            ciphertextMatrix,
            messageMatrix,
            key: SecretBytes::new(key.to_vec()),
        }
    }
}

impl KeyEncapsulating for FrodoKEM {
    fn description(&self) -> &'static KEMDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let parameters = self.parameters;
        let description = &parameters.description;
        let secretLength = description.sharedSecretLength;
        // One request for the rejection value `s`, the noise seed and the seed of the matrix
        // seed, as `crypto_kem_keypair` draws them.
        let mut randomness = SecretBytes::zeroed(
            secretLength + parameters.noiseSeedLength + Parameters::matrixSeedLength,
        );
        random.fillRandomBytes(randomness.mutableBytes());
        let (rejectionValue, seeds) = randomness.bytes().split_at(secretLength);
        let (noiseSeed, matrixSeedInput) = seeds.split_at(parameters.noiseSeedLength);
        let mut matrixSeed = [0u8; Parameters::matrixSeedLength];
        parameters
            .hashFunction
            .hash(&[matrixSeedInput], &mut matrixSeed);
        let count = parameters.matrixValueCount();
        let noise = self.noise(keyPairNoiseDomain, noiseSeed, 2 * count);
        let (secret, error) = noise.split_at(count);
        let publicKeyMatrix =
            MatrixArithmetic::new(parameters).publicKeyMatrix(&matrixSeed, secret, error);
        let mut publicKey = vec![0u8; description.publicKeyLength];
        publicKey[..Parameters::matrixSeedLength].copy_from_slice(&matrixSeed);
        Packing::pack(
            &publicKeyMatrix,
            parameters.modulusBits,
            &mut publicKey[Parameters::matrixSeedLength..],
        );
        let mut secretKey = Vec::with_capacity(description.secretKeyLength);
        secretKey.extend_from_slice(rejectionValue);
        secretKey.extend_from_slice(&publicKey);
        secretKey.extend_from_slice(&Packing::littleEndianBytes(secret));
        let mut publicKeyHash = vec![0u8; secretLength];
        parameters
            .hashFunction
            .hash(&[&publicKey], &mut publicKeyHash);
        secretKey.extend_from_slice(&publicKeyHash);
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
        let parameters = self.parameters;
        let description = &parameters.description;
        let publicKey = InputLength::checked(publicKey, description.publicKeyLength)?;
        let secretLength = description.sharedSecretLength;
        // The hash input `pkh || mu || salt`.
        let mut hashInput =
            SecretBytes::zeroed(secretLength + parameters.messageLength() + parameters.saltLength);
        let (publicKeyHash, randomPart) = hashInput.mutableBytes().split_at_mut(secretLength);
        parameters.hashFunction.hash(&[publicKey], publicKeyHash);
        // One request for the message and the salt, as `crypto_kem_enc` draws them.
        random.fillRandomBytes(randomPart);
        let encryption = self.encryption(publicKey, hashInput.bytes());
        let matrixLength = parameters.packedMatrixLength();
        let mut ciphertext = vec![0u8; description.ciphertextLength];
        let (packedMatrix, rest) = ciphertext.split_at_mut(matrixLength);
        let (packedMessageMatrix, salt) = rest.split_at_mut(parameters.packedMessageMatrixLength());
        Packing::pack(
            &encryption.ciphertextMatrix,
            parameters.modulusBits,
            packedMatrix,
        );
        Packing::pack(
            &encryption.messageMatrix,
            parameters.modulusBits,
            packedMessageMatrix,
        );
        let input = hashInput.bytes();
        salt.copy_from_slice(&input[input.len() - parameters.saltLength..]);
        let mut sharedSecret = SecretBytes::zeroed(secretLength);
        parameters.hashFunction.hash(
            &[&ciphertext, encryption.key.bytes()],
            sharedSecret.mutableBytes(),
        );
        Ok(Encapsulation {
            ciphertext,
            sharedSecret,
        })
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let parameters = self.parameters;
        let description = &parameters.description;
        let ciphertext = InputLength::checked(ciphertext, description.ciphertextLength)?;
        let secretKey = InputLength::checked(secretKey, description.secretKeyLength)?;
        let secretLength = description.sharedSecretLength;
        let (rejectionValue, rest) = secretKey.split_at(secretLength);
        let (publicKey, rest) = rest.split_at(description.publicKeyLength);
        let (secretBytes, publicKeyHash) = rest.split_at(2 * parameters.matrixValueCount());
        let mut secret = vec![0u16; parameters.matrixValueCount()];
        Packing::decodeLittleEndian(secretBytes, &mut secret);
        let matrixLength = parameters.packedMatrixLength();
        let messageMatrixEnd = matrixLength + parameters.packedMessageMatrixLength();
        let ciphertextMatrix =
            Packing::unpacked(&ciphertext[..matrixLength], parameters.modulusBits);
        let messageMatrix = Packing::unpacked(
            &ciphertext[matrixLength..messageMatrixEnd],
            parameters.modulusBits,
        );
        let arithmetic = MatrixArithmetic::new(parameters);
        let noisyMessage = arithmetic.difference(
            &messageMatrix,
            &arithmetic.decryptionMask(&ciphertextMatrix, &secret),
        );
        // The hash input `pkh || mu' || salt`, with the salt of the ciphertext.
        let messageLength = parameters.messageLength();
        let mut hashInput =
            SecretBytes::zeroed(secretLength + messageLength + parameters.saltLength);
        let (hashPart, rest) = hashInput.mutableBytes().split_at_mut(secretLength);
        let (messagePart, saltPart) = rest.split_at_mut(messageLength);
        hashPart.copy_from_slice(publicKeyHash);
        messagePart.copy_from_slice(&arithmetic.decoded(&noisyMessage));
        saltPart.copy_from_slice(&ciphertext[messageMatrixEnd..]);
        let mut encryption = self.encryption(publicKey, hashInput.bytes());
        // The C code reduces the matrix `B'` of the re-encryption before the comparison.
        arithmetic.reduce(&mut encryption.ciphertextMatrix);
        // The choice of the key depends on a secret value, so it uses a mask, not a branch.
        let selector =
            ConstantTime::mismatchSelector(&ciphertextMatrix, &encryption.ciphertextMatrix)
                | ConstantTime::mismatchSelector(&messageMatrix, &encryption.messageMatrix);
        let mut key = SecretBytes::zeroed(secretLength);
        ConstantTime::select(
            encryption.key.bytes(),
            rejectionValue,
            selector,
            key.mutableBytes(),
        );
        let mut sharedSecret = SecretBytes::zeroed(secretLength);
        parameters
            .hashFunction
            .hash(&[ciphertext, key.bytes()], sharedSecret.mutableBytes());
        Ok(sharedSecret)
    }
}
