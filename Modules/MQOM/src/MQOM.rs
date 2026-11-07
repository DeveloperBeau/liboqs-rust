use crate::internalAlgorithms::InternalAlgorithms;
use crate::parameters::{
    Parameters, mqom2Cat1GF16FastR3, mqom2Cat1GF16FastR5, mqom2Cat1GF16ShortR3,
    mqom2Cat1GF16ShortR5, mqom2Cat3GF16FastR3, mqom2Cat3GF16FastR5, mqom2Cat3GF16ShortR3,
    mqom2Cat3GF16ShortR5, mqom2Cat5GF16FastR3, mqom2Cat5GF16FastR5, mqom2Cat5GF16ShortR3,
    mqom2Cat5GF16ShortR5,
};
use OQSNativeDomain::{InputLength, RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, SignatureDescription};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::RangeInclusive;

/// MQOM, the MQ on my Mind signature scheme of round 2 of the NIST call for additional
/// signatures, with one parameter set.
///
/// The twelve parameter sets combine the NIST levels 1, 3 and 5, the fast and the short trade
/// off, and the three-round and five-round proofs. The short trade off gives shorter
/// signatures that take longer to make. Each gives the bytes of the liboqs
/// algorithm of the same name, whose C code is the default implementation of the MQOM team. A
/// key pair draws its seed of 2 λ / 8 bytes in one random request. A signature draws its root
/// seed of λ / 8 bytes and then its salt of λ / 8 bytes in two requests, as liboqs does. MQOM
/// signs without a context string.
pub struct MQOM {
    parameters: &'static Parameters,
}

impl MQOM {
    /// `mqom2_cat1_gf16_fast_r3`, at the NIST level 1, with the fast trade off and the
    /// three-round proof.
    pub const mqom2Cat1GF16FastR3: MQOM = MQOM {
        parameters: &mqom2Cat1GF16FastR3,
    };

    /// `mqom2_cat1_gf16_fast_r5`, at the NIST level 1, with the fast trade off and the
    /// five-round proof.
    pub const mqom2Cat1GF16FastR5: MQOM = MQOM {
        parameters: &mqom2Cat1GF16FastR5,
    };

    /// `mqom2_cat1_gf16_short_r3`, at the NIST level 1, with the short trade off and the
    /// three-round proof.
    pub const mqom2Cat1GF16ShortR3: MQOM = MQOM {
        parameters: &mqom2Cat1GF16ShortR3,
    };

    /// `mqom2_cat1_gf16_short_r5`, at the NIST level 1, with the short trade off and the
    /// five-round proof.
    pub const mqom2Cat1GF16ShortR5: MQOM = MQOM {
        parameters: &mqom2Cat1GF16ShortR5,
    };

    /// `mqom2_cat3_gf16_fast_r3`, at the NIST level 3, with the fast trade off and the
    /// three-round proof.
    pub const mqom2Cat3GF16FastR3: MQOM = MQOM {
        parameters: &mqom2Cat3GF16FastR3,
    };

    /// `mqom2_cat3_gf16_fast_r5`, at the NIST level 3, with the fast trade off and the
    /// five-round proof.
    pub const mqom2Cat3GF16FastR5: MQOM = MQOM {
        parameters: &mqom2Cat3GF16FastR5,
    };

    /// `mqom2_cat3_gf16_short_r3`, at the NIST level 3, with the short trade off and the
    /// three-round proof.
    pub const mqom2Cat3GF16ShortR3: MQOM = MQOM {
        parameters: &mqom2Cat3GF16ShortR3,
    };

    /// `mqom2_cat3_gf16_short_r5`, at the NIST level 3, with the short trade off and the
    /// five-round proof.
    pub const mqom2Cat3GF16ShortR5: MQOM = MQOM {
        parameters: &mqom2Cat3GF16ShortR5,
    };

    /// `mqom2_cat5_gf16_fast_r3`, at the NIST level 5, with the fast trade off and the
    /// three-round proof.
    pub const mqom2Cat5GF16FastR3: MQOM = MQOM {
        parameters: &mqom2Cat5GF16FastR3,
    };

    /// `mqom2_cat5_gf16_fast_r5`, at the NIST level 5, with the fast trade off and the
    /// five-round proof.
    pub const mqom2Cat5GF16FastR5: MQOM = MQOM {
        parameters: &mqom2Cat5GF16FastR5,
    };

    /// `mqom2_cat5_gf16_short_r3`, at the NIST level 5, with the short trade off and the
    /// three-round proof.
    pub const mqom2Cat5GF16ShortR3: MQOM = MQOM {
        parameters: &mqom2Cat5GF16ShortR3,
    };

    /// `mqom2_cat5_gf16_short_r5`, at the NIST level 5, with the short trade off and the
    /// five-round proof.
    pub const mqom2Cat5GF16ShortR5: MQOM = MQOM {
        parameters: &mqom2Cat5GF16ShortR5,
    };

    fn internalAlgorithms(&self) -> InternalAlgorithms<'static> {
        InternalAlgorithms::new(self.parameters)
    }

    /// The signature of a message under a secret key, with the nonces of a range for the proof
    /// of work. The length of the secret key is checked before the random requests.
    fn signature(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
        nonces: RangeInclusive<u32>,
    ) -> Result<Vec<u8>, OQSError> {
        let secretKey =
            InputLength::checked(secretKey, self.parameters.description.secretKeyLength)?;
        // `crypto_sign_signature` draws the root seed and then the salt.
        let seedLength = self.parameters.seedLength();
        let mut rootSeed = vec![0u8; seedLength];
        random.fillRandomBytes(&mut rootSeed);
        let mut salt = vec![0u8; seedLength];
        random.fillRandomBytes(&mut salt);
        self.internalAlgorithms()
            .signature(secretKey, message, &salt, &rootSeed, nonces)
            .ok_or(OQSError::operationFailed)
    }
}

impl Signing for MQOM {
    fn description(&self) -> &'static SignatureDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seed = vec![0u8; self.parameters.digestLength()];
        random.fillRandomBytes(&mut seed);
        let (publicKey, secretKey) = self.internalAlgorithms().keyPair(&seed);
        Ok(KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        })
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        self.signature(message, secretKey, random, 0..=u32::MAX)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        let description = &self.parameters.description;
        signature.len() == description.signatureLength
            && publicKey.len() == description.publicKeyLength
            && self
                .internalAlgorithms()
                .isValidSignature(signature, message, publicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::MQOM;
    use OQSNativeDomain::{RandomGenerating, Signing};
    use OQSNativeEntities::OQSError;

    /// A random source that gives one byte to every request.
    struct FixedRandom(u8);

    impl RandomGenerating for FixedRandom {
        fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
            bytes.fill(self.0);
        }
    }

    #[test]
    fn aSignatureWithNoNonceThatMeetsTheProofOfWorkIsAnOperationFailure() {
        for scheme in [&MQOM::mqom2Cat1GF16FastR3, &MQOM::mqom2Cat3GF16FastR5] {
            let keyPair = scheme
                .generateKeyPair(&mut FixedRandom(5))
                .expect("key pair");
            let secretKey = keyPair.secretKey.bytes();
            let signature = scheme
                .sign(b"message", secretKey, &mut FixedRandom(5))
                .expect("a signature");
            // The nonce ends the signature. It is not 0, so the range of the nonce 0 alone
            // holds no nonce that meets the proof of work.
            let nonce = &signature[signature.len() - 4..];
            assert_ne!(nonce, [0, 0, 0, 0]);
            assert_eq!(
                scheme.signature(b"message", secretKey, &mut FixedRandom(5), 0..=0),
                Err(OQSError::operationFailed)
            );
            let found = u32::from_le_bytes(nonce.try_into().expect("four bytes"));
            assert_eq!(
                scheme.signature(b"message", secretKey, &mut FixedRandom(5), 0..=found),
                Ok(signature)
            );
        }
    }

    #[test]
    fn aSignatureTriesTheNoncesFromZero() {
        // With w = 3, the nonce 0 meets the proof of work for about one challenge in eight, so
        // one of the first signatures of a key takes it. A search from the nonce 1 never does.
        let scheme = &MQOM::mqom2Cat3GF16FastR5;
        let keyPair = scheme
            .generateKeyPair(&mut FixedRandom(5))
            .expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let signature = (0..64u8)
            .map(|byte| {
                scheme
                    .sign(b"message", secretKey, &mut FixedRandom(byte))
                    .expect("a signature")
            })
            .find(|signature| signature.ends_with(&[0, 0, 0, 0]))
            .expect("a signature with the nonce 0");
        assert!(scheme.isValidSignature(&signature, b"message", &keyPair.publicKey));
    }
}
