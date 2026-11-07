use crate::controlBits::ControlBits;
use crate::decryption::Decryption;
use crate::encryption::Encryption;
use crate::goppaPolynomial::GoppaPolynomial;
use crate::parameters::{
    Parameters, classicMcEliece348864, classicMcEliece348864f, classicMcEliece460896,
    classicMcEliece460896f, classicMcEliece6688128, classicMcEliece6688128f,
    classicMcEliece6960119, classicMcEliece6960119f, classicMcEliece8192128,
    classicMcEliece8192128f,
};
use crate::parityCheckMatrix::{GeneratedKey, ParityCheckMatrix};
use OQSNativeDomain::{InputLength, KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};
use OQSNativeSHA3::SHAKE256;
use alloc::vec;
use alloc::vec::Vec;

/// Classic McEliece, the code-based key encapsulation mechanism of round 4 of the NIST process,
/// with one parameter set, as the code of the Classic McEliece team in liboqs gives it.
///
/// The ten parameter sets are the constants of this type, such as
/// `ClassicMcEliece::classicMcEliece348864`. Each gives the bytes of the liboqs algorithm of the
/// same name. A key pair draws 32 random bytes in one request and expands them with SHAKE256,
/// and an attempt that fails takes the next seed of the expansion, with no new request. An
/// encapsulation draws one request for each attempt of the error vector, until an attempt is
/// valid. The decapsulation does not encrypt again: it checks the weight and the double
/// syndrome of the decoded error vector, and hashes the secret value `s` in place of the error
/// vector when a check fails. The `f` sets compute the public key in semi-systematic form.
/// liboqs gives Classic McEliece no seeded forms. The 6960119 sets refuse a public key or a
/// ciphertext whose padding bits are not zero, as the C code does.
pub struct ClassicMcEliece {
    parameters: &'static Parameters,
}

impl ClassicMcEliece {
    /// Classic-McEliece-348864, security category 1.
    pub const classicMcEliece348864: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece348864,
    };

    /// Classic-McEliece-348864f, security category 1, with the semi-systematic form.
    pub const classicMcEliece348864f: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece348864f,
    };

    /// Classic-McEliece-460896, security category 3.
    pub const classicMcEliece460896: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece460896,
    };

    /// Classic-McEliece-460896f, security category 3, with the semi-systematic form.
    pub const classicMcEliece460896f: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece460896f,
    };

    /// Classic-McEliece-6688128, security category 5.
    pub const classicMcEliece6688128: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece6688128,
    };

    /// Classic-McEliece-6688128f, security category 5, with the semi-systematic form.
    pub const classicMcEliece6688128f: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece6688128f,
    };

    /// Classic-McEliece-6960119, security category 5.
    pub const classicMcEliece6960119: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece6960119,
    };

    /// Classic-McEliece-6960119f, security category 5, with the semi-systematic form.
    pub const classicMcEliece6960119f: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece6960119f,
    };

    /// Classic-McEliece-8192128, security category 5.
    pub const classicMcEliece8192128: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece8192128,
    };

    /// Classic-McEliece-8192128f, security category 5, with the semi-systematic form.
    pub const classicMcEliece8192128f: ClassicMcEliece = ClassicMcEliece {
        parameters: &classicMcEliece8192128f,
    };

    /// The key pair of the 32 bytes of the random request, `crypto_kem_keypair`.
    ///
    /// Each attempt expands the byte 64 and the seed with SHAKE256 into the secret value `s`,
    /// the 32-bit values of the permutation, the element of GF((2^m)^t) of the Goppa
    /// polynomial and the seed of the next attempt, read from the end. An attempt fails when
    /// the element has no minimal polynomial of degree `t` or when the matrix has no public
    /// key, and then the next attempt starts.
    fn keyPair(&self, seed: &[u8; 32]) -> KeyPair {
        let parameters = self.parameters;
        let field = parameters.field();
        let weight = parameters.errorWeight;
        let size = parameters.fieldSize();
        let mut input = [0u8; 33];
        input[0] = 64;
        input[1..].copy_from_slice(seed);
        let mut expanded = vec![0u8; parameters.expandedSeedLength()];
        loop {
            SHAKE256::hash(&input, &mut expanded);
            let attemptSeed: [u8; 32] = input[1..].try_into().expect("32 bytes");
            let nextSeedStart = expanded.len() - Parameters::seedLength;
            input[1..].copy_from_slice(&expanded[nextSeedStart..]);
            let elementStart = nextSeedStart - 2 * weight;
            let element: Vec<u16> = expanded[elementStart..nextSeedStart]
                .chunks_exact(2)
                .map(|pair| field.loaded(pair))
                .collect();
            let Some(goppaPolynomial) =
                GoppaPolynomial::new(parameters).minimalPolynomial(&element)
            else {
                continue;
            };
            let orderStart = elementStart - 4 * size;
            let orderValues: Vec<u32> = expanded[orderStart..elementStart]
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
                .collect();
            let Some(GeneratedKey {
                publicKey,
                permutation,
                pivots,
            }) = ParityCheckMatrix::generatedKey(parameters, &goppaPolynomial, &orderValues)
            else {
                continue;
            };
            let mut secretKey = Vec::with_capacity(parameters.description.secretKeyLength);
            secretKey.extend_from_slice(&attemptSeed);
            secretKey.extend_from_slice(&pivots.to_le_bytes());
            for coefficient in &goppaPolynomial {
                secretKey.extend_from_slice(&coefficient.to_le_bytes());
            }
            secretKey.extend(ControlBits::ofPermutation(
                &permutation,
                parameters.fieldBits,
            ));
            secretKey.extend_from_slice(&expanded[..parameters.errorVectorLength()]);
            return KeyPair {
                publicKey,
                secretKey: SecretBytes::new(secretKey),
            };
        }
    }

    /// True when the padding bits of each row of a public key are zero, `check_pk_padding` of
    /// the 6960119 sets. The other sets have no padding bits.
    fn hasZeroPublicKeyPadding(&self, publicKey: &[u8]) -> bool {
        let parameters = self.parameters;
        if parameters.rowTail() == 0 {
            return true;
        }
        let rowLength = parameters.publicKeyRowLength();
        let lastBytes = publicKey
            .chunks_exact(rowLength)
            .fold(0u8, |total, row| total | row[rowLength - 1]);
        let usedBits = (parameters.codeLength - parameters.rowCount()) % 8;
        lastBytes >> usedBits == 0
    }

    /// True when the padding bits of the last byte of a ciphertext are zero, `check_c_padding`
    /// of the 6960119 sets. The other sets have no padding bits.
    fn hasZeroCiphertextPadding(&self, ciphertext: &[u8]) -> bool {
        let tail = self.parameters.rowTail();
        tail == 0 || ciphertext[ciphertext.len() - 1] >> tail == 0
    }

    /// The SHAKE256 of a byte, `n / 8` bytes and a ciphertext, 32 bytes: the shared secret of
    /// the byte 1 and an error vector, or of the byte 0 and the secret value `s`.
    fn sharedSecret(prefix: u8, vector: &[u8], ciphertext: &[u8]) -> SecretBytes {
        let mut sponge = SHAKE256::new();
        sponge.absorb(&[prefix]);
        sponge.absorb(vector);
        sponge.absorb(ciphertext);
        let mut secret = vec![0u8; Parameters::sharedSecretLength];
        sponge.finalize().squeeze(&mut secret);
        SecretBytes::new(secret)
    }
}

impl KeyEncapsulating for ClassicMcEliece {
    fn description(&self) -> &'static KEMDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seed = [0u8; Parameters::seedLength];
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
        let isPaddingZero = self.hasZeroPublicKeyPadding(publicKey);
        // The C code draws the error vector before it reports the padding.
        let encryption = Encryption::new(self.parameters);
        let error = encryption.randomErrorVector(random);
        if !isPaddingZero {
            return Err(OQSError::operationFailed);
        }
        let ciphertext = encryption.syndrome(publicKey, &error);
        let sharedSecret = Self::sharedSecret(1, &error, &ciphertext);
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
        if !self.hasZeroCiphertextPadding(ciphertext) {
            return Err(OQSError::operationFailed);
        }
        let decrypted = Decryption::new(parameters).decrypted(
            &secretKey[parameters.goppaPolynomialRange().start..],
            ciphertext,
        );
        // The choice of the hashed vector depends on a secret value, so it uses a mask, not a
        // branch: the mask is 0xFF for an accepted error vector and 0 for a refused one.
        let mask = (u16::from(decrypted.failure).wrapping_sub(1) >> 8) as u8;
        let rejectionValue = &secretKey[parameters.rejectionValueRange()];
        let vector: Vec<u8> = rejectionValue
            .iter()
            .zip(&decrypted.error)
            .map(|(rejectionByte, errorByte)| (!mask & rejectionByte) + (mask & errorByte))
            .collect();
        Ok(Self::sharedSecret(mask & 1, &vector, ciphertext))
    }
}
