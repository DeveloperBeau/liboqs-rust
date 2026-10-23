use crate::decoder::{Decoder, ErrorVector};
use crate::parameters::{Parameters, bikeL1, bikeL3, bikeL5};
use crate::polynomialRing::PolynomialRing;
use crate::sampler::Sampler;
use OQSNativeDomain::{InputLength, KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};
use OQSNativeSHA3::SHA3384;
use alloc::vec;

/// BIKE, the bit flipping key encapsulation of round 4 of the NIST process, with one parameter
/// set, as the additional implementation of the BIKE team in liboqs gives it.
///
/// The three parameter sets are `BIKE::bikeL1`, `BIKE::bikeL3` and `BIKE::bikeL5`. Each gives the
/// bytes of the liboqs algorithm of the same name. A key pair and an encapsulation each draw 64
/// random bytes in one request, as the C code does, and an encapsulation uses only the first 32.
/// Decapsulation decodes the ciphertext with the Black-Gray-Flip decoder, rebuilds the error
/// vector from the message, and gives the secret of the rejection seed `sigma` when the two
/// differ. liboqs claims IND-CPA security for BIKE and gives it no seeded forms. Neither key is
/// checked, as in the C code.
pub struct BIKE {
    parameters: &'static Parameters,
}

impl BIKE {
    /// BIKE-L1, security category 1.
    pub const bikeL1: BIKE = BIKE {
        parameters: &bikeL1,
    };

    /// BIKE-L3, security category 3.
    pub const bikeL3: BIKE = BIKE {
        parameters: &bikeL3,
    };

    /// BIKE-L5, security category 5.
    pub const bikeL5: BIKE = BIKE {
        parameters: &bikeL5,
    };

    fn ring(&self) -> PolynomialRing<'static> {
        PolynomialRing::new(self.parameters)
    }

    fn sampler(&self) -> Sampler<'static> {
        Sampler::new(self.parameters)
    }

    /// The function `L` of BIKE, `function_l` of the C code: the first 32 bytes of the SHA3-384
    /// of the bytes of `e0` and of `e1`.
    fn errorHash(&self, error: &ErrorVector) -> [u8; 32] {
        let ring = self.ring();
        let mut hash = SHA3384::new();
        hash.absorb(&ring.bytes(&error[0]));
        hash.absorb(&ring.bytes(&error[1]));
        let digest = hash.finalize();
        digest[..32].try_into().expect("32 bytes")
    }

    /// The function `K` of BIKE, `function_k` of the C code: the first 32 bytes of the
    /// SHA3-384 of the message and of the ciphertext bytes as they are.
    fn sharedSecret(message: &[u8; 32], ciphertext: &[u8]) -> SecretBytes {
        let mut hash = SHA3384::new();
        hash.absorb(message);
        hash.absorb(ciphertext);
        let digest = hash.finalize();
        SecretBytes::new(digest[..Parameters::sharedSecretLength].to_vec())
    }

    /// The key pair of the 64 bytes of one random request, `keypair` of the C code: the first
    /// 32 bytes seed the secret blocks and the last 32 are `sigma`.
    ///
    /// The secret key is the positions of `h0` and `h1` as little-endian 32-bit values, the
    /// bytes of `h0` and `h1`, the public key `h = h1 / h0` and `sigma`.
    fn keyPair(&self, seeds: &[u8; 64]) -> KeyPair {
        let parameters = self.parameters;
        let ring = self.ring();
        let seed: &[u8; 32] = seeds[..32].try_into().expect("32 bytes");
        let (blocks, positions) = self.sampler().secretBlocks(seed);
        let publicKey = ring.bytes(&ring.product(&blocks[1], &ring.inverse(&blocks[0])));
        let mut secretKey = vec![0u8; parameters.description.secretKeyLength];
        for (block, blockPositions) in positions.iter().enumerate() {
            for (bytes, position) in secretKey[parameters.positionsRange(block)]
                .chunks_exact_mut(4)
                .zip(blockPositions)
            {
                bytes.copy_from_slice(&position.to_le_bytes());
            }
            secretKey[parameters.secretBlockRange(block)]
                .copy_from_slice(&ring.bytes(&blocks[block]));
        }
        secretKey[parameters.publicKeyRange()].copy_from_slice(&publicKey);
        secretKey[parameters.sigmaRange()].copy_from_slice(&seeds[32..]);
        KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        }
    }

    /// The encapsulation of a message under a public key, `encaps` of the C code after the
    /// random request: the error vector `e = H(m)`, the ciphertext `(e0 + e1 h, m + L(e))` and
    /// the shared secret `K(m, c)`.
    fn encapsulation(&self, publicKey: &[u8], message: &[u8; 32]) -> Encapsulation {
        let ring = self.ring();
        let error = self.sampler().errorVector(message);
        let mut firstBlock = ring.product(&error[1], &ring.polynomial(publicKey));
        for (word, errorWord) in firstBlock.iter_mut().zip(error[0].iter()) {
            *word ^= errorWord;
        }
        let mut ciphertext = ring.bytes(&firstBlock);
        let mask = self.errorHash(&error);
        ciphertext.extend(mask.iter().zip(message).map(|(left, right)| left ^ right));
        let sharedSecret = Self::sharedSecret(message, &ciphertext);
        Encapsulation {
            ciphertext,
            sharedSecret,
        }
    }

    /// The decapsulation of a ciphertext with a secret key, `decaps` of the C code. The block
    /// `h1` of the secret key is not used.
    fn decapsulation(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let parameters = self.parameters;
        let description = &parameters.description;
        let ciphertext = InputLength::checked(ciphertext, description.ciphertextLength)?;
        let secretKey = InputLength::checked(secretKey, description.secretKeyLength)?;
        let decoded = Decoder::new(parameters).decodedCiphertext(ciphertext, secretKey);
        let mask = &ciphertext[parameters.polynomialByteCount()..];
        let sigma = &secretKey[parameters.sigmaRange()];
        let hash = self.errorHash(&decoded);
        let mut message = [0u8; 32];
        for ((byte, hashByte), maskByte) in message.iter_mut().zip(hash).zip(mask) {
            *byte = hashByte ^ maskByte;
        }
        let rebuilt = self.sampler().errorVector(&message);
        // The choice of the message depends on a secret value, so it uses a mask, not a branch.
        let differences = decoded
            .iter()
            .flatten()
            .zip(rebuilt.iter().flatten())
            .fold(0u64, |accumulated, (left, right)| {
                accumulated | (left ^ right)
            });
        // The top bit of `x | -x` is set exactly when `x` is not zero.
        let isDifferent = ((differences | differences.wrapping_neg()) >> 63) as u8;
        let isDifferentMask = 0u8.wrapping_sub(isDifferent);
        for (byte, seedByte) in message.iter_mut().zip(sigma) {
            *byte ^= isDifferentMask & (*byte ^ seedByte);
        }
        Ok(Self::sharedSecret(&message, ciphertext))
    }
}

impl KeyEncapsulating for BIKE {
    fn description(&self) -> &'static KEMDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seeds = [0u8; 64];
        random.fillRandomBytes(&mut seeds);
        Ok(self.keyPair(&seeds))
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        let publicKey =
            InputLength::checked(publicKey, self.parameters.description.publicKeyLength)?;
        // The C code draws two seeds in one request and uses the first as the message.
        let mut seeds = [0u8; 64];
        random.fillRandomBytes(&mut seeds);
        let message: &[u8; 32] = seeds[..32].try_into().expect("32 bytes");
        Ok(self.encapsulation(publicKey, message))
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        self.decapsulation(ciphertext, secretKey)
    }
}

#[cfg(test)]
mod tests {
    use super::BIKE;
    use crate::decoder::Decoder;
    use crate::parameters::Parameters;
    use crate::polynomialRing::PolynomialRing;
    use OQSNativeDomain::KeyEncapsulating;

    const mechanisms: [&BIKE; 3] = [&BIKE::bikeL1, &BIKE::bikeL3, &BIKE::bikeL5];

    /// A ciphertext whose decoded error differs from the error of its message only in the
    /// coefficients 0 and 64 of one block, and the shared secrets of its acceptance and of its
    /// rejection.
    ///
    /// The change of the block c0 moves the error by the two coefficients, and the change of
    /// the mask keeps the message, so the rebuilt error is the error of the encapsulation.
    fn ciphertextWithTwoChangedCoefficients(
        mechanism: &BIKE,
        block: usize,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let parameters: &Parameters = mechanism.parameters;
        let ring = PolynomialRing::new(parameters);
        let keyPair = mechanism.keyPair(&[0x3C; 64]);
        let message = [0x5A; 32];
        let encapsulation = mechanism.encapsulation(&keyPair.publicKey, &message);
        let error = mechanism.sampler().errorVector(&message);
        let mut changedError = error.clone();
        changedError[block][0] ^= 1;
        changedError[block][1] ^= 1;
        let mut change = vec![0u64; parameters.wordCount()];
        change[0] = 1;
        change[1] = 1;
        if block == 1 {
            change = ring.product(&change, &ring.polynomial(&keyPair.publicKey));
        }
        let byteCount = parameters.polynomialByteCount();
        let mut ciphertext = encapsulation.ciphertext.clone();
        for (byte, changeByte) in ciphertext.iter_mut().zip(ring.bytes(&change)) {
            *byte ^= changeByte;
        }
        let oldHash = mechanism.errorHash(&error);
        let newHash = mechanism.errorHash(&changedError);
        for (index, byte) in ciphertext[byteCount..].iter_mut().enumerate() {
            *byte ^= oldHash[index] ^ newHash[index];
        }
        let secretKey = keyPair.secretKey.bytes();
        assert_eq!(
            Decoder::new(parameters).decodedCiphertext(&ciphertext, secretKey),
            changedError,
            "{}: the decoder finds the changed error",
            parameters.description.name
        );
        let sigma: [u8; 32] = secretKey[parameters.sigmaRange()]
            .try_into()
            .expect("32 bytes");
        let accepted = BIKE::sharedSecret(&message, &ciphertext).bytes().to_vec();
        let rejected = BIKE::sharedSecret(&sigma, &ciphertext).bytes().to_vec();
        let decapsulated = mechanism
            .decapsulate(&ciphertext, secretKey)
            .expect("decapsulation")
            .bytes()
            .to_vec();
        (decapsulated, accepted, rejected)
    }

    #[test]
    fn aDecodedErrorThatDiffersInTheSameBitOfTwoWordsIsRejected() {
        // Coefficients 0 and 64 are bit 0 of words 0 and 1, and of bytes 0 and 8, so the two
        // differences cancel in an exclusive or. The comparison must gather them with an or.
        for mechanism in mechanisms {
            for block in [0, 1] {
                let (decapsulated, accepted, rejected) =
                    ciphertextWithTwoChangedCoefficients(mechanism, block);
                assert_ne!(accepted, rejected);
                assert_eq!(
                    decapsulated,
                    rejected,
                    "{}, block {block}",
                    mechanism.description().name
                );
            }
        }
    }

    #[test]
    fn theSharedSecretsAreTheTruncatedSHA3384OfTheMessageAndTheCiphertext() {
        let mechanism = &BIKE::bikeL1;
        let keyPair = mechanism.keyPair(&[0x21; 64]);
        let message = [0x77; 32];
        let encapsulation = mechanism.encapsulation(&keyPair.publicKey, &message);
        let mut input = message.to_vec();
        input.extend(&encapsulation.ciphertext);
        let digest = OQSNativeSHA3::SHA3384::hash(&input);
        assert_eq!(encapsulation.sharedSecret.bytes(), &digest[..32]);
        // The mask is the message plus the first 32 bytes of the SHA3-384 of the error.
        let error = mechanism.sampler().errorVector(&message);
        let ring = PolynomialRing::new(mechanism.parameters);
        let mut errorBytes = ring.bytes(&error[0]);
        errorBytes.extend(ring.bytes(&error[1]));
        let errorDigest = OQSNativeSHA3::SHA3384::hash(&errorBytes);
        let mask = &encapsulation.ciphertext[1541..];
        for index in 0..32 {
            assert_eq!(mask[index], errorDigest[index] ^ message[index]);
        }
    }
}
