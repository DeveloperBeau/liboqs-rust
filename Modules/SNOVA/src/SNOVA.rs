use crate::keyGenerator::KeyGenerator;
use crate::messageHashing::MessageHashing;
use crate::parameters::{
    Parameters, publicSeedLength, saltLength, secretSeedLength, snova24x5x4, snova24x5x4SHAKE,
    snova24x5x4SHAKEWithExpandedSecretKey, snova24x5x4WithExpandedSecretKey, snova24x5x5,
    snova25x8x3, snova29x6x5, snova37x8x4, snova37x17x2, snova49x11x3, snova56x25x2, snova60x10x4,
};
use crate::signer::Signer;
use crate::verifier::Verifier;
use OQSNativeDomain::{InputLength, RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, SignatureDescription};
use alloc::vec::Vec;

/// SNOVA, the multivariate signature scheme over matrices of GF(16), with one parameter set,
/// as liboqs ships it from the optimized code of the SNOVA team.
///
/// The twelve parameter sets are `SNOVA::snova24x5x4` and the others, each named after the
/// numbers v, o and l of its liboqs name, such as `SNOVA_24_5_4`. Each gives the bytes of the
/// liboqs algorithm of that name. A key pair draws the 16-byte public seed and the 32-byte
/// secret seed in one request of 48 bytes. A signature hashes the message with SHAKE256 and
/// draws a 16-byte salt. The sets with SHAKE in their names expand the public seed with
/// SHAKE128, and the others with AES-128. The sets with an expanded secret key keep the whole
/// secret map in the key, and the others keep the seeds. SNOVA has no context string.
pub struct SNOVA {
    parameters: &'static Parameters,
}

impl SNOVA {
    /// SNOVA_24_5_4, at the NIST level 1.
    pub const snova24x5x4: SNOVA = SNOVA {
        parameters: &snova24x5x4,
    };

    /// SNOVA_24_5_4_SHAKE, at the NIST level 1, with the public seed expanded by SHAKE128.
    pub const snova24x5x4SHAKE: SNOVA = SNOVA {
        parameters: &snova24x5x4SHAKE,
    };

    /// SNOVA_24_5_4_esk, at the NIST level 1, with the expanded secret key.
    pub const snova24x5x4WithExpandedSecretKey: SNOVA = SNOVA {
        parameters: &snova24x5x4WithExpandedSecretKey,
    };

    /// SNOVA_24_5_4_SHAKE_esk, at the NIST level 1, with the public seed expanded by SHAKE128
    /// and the expanded secret key.
    pub const snova24x5x4SHAKEWithExpandedSecretKey: SNOVA = SNOVA {
        parameters: &snova24x5x4SHAKEWithExpandedSecretKey,
    };

    /// SNOVA_37_17_2, at the NIST level 1.
    pub const snova37x17x2: SNOVA = SNOVA {
        parameters: &snova37x17x2,
    };

    /// SNOVA_25_8_3, at the NIST level 1.
    pub const snova25x8x3: SNOVA = SNOVA {
        parameters: &snova25x8x3,
    };

    /// SNOVA_56_25_2, at the NIST level 3.
    pub const snova56x25x2: SNOVA = SNOVA {
        parameters: &snova56x25x2,
    };

    /// SNOVA_49_11_3, at the NIST level 3.
    pub const snova49x11x3: SNOVA = SNOVA {
        parameters: &snova49x11x3,
    };

    /// SNOVA_37_8_4, at the NIST level 3.
    pub const snova37x8x4: SNOVA = SNOVA {
        parameters: &snova37x8x4,
    };

    /// SNOVA_24_5_5, at the NIST level 3.
    pub const snova24x5x5: SNOVA = SNOVA {
        parameters: &snova24x5x5,
    };

    /// SNOVA_60_10_4, at the NIST level 5.
    pub const snova60x10x4: SNOVA = SNOVA {
        parameters: &snova60x10x4,
    };

    /// SNOVA_29_6_5, at the NIST level 5.
    pub const snova29x6x5: SNOVA = SNOVA {
        parameters: &snova29x6x5,
    };
}

impl Signing for SNOVA {
    fn description(&self) -> &'static SignatureDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seeds = [0u8; publicSeedLength + secretSeedLength];
        random.fillRandomBytes(&mut seeds);
        let (publicKey, secretKey) = KeyGenerator::new(self.parameters).keyPair(&seeds);
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
        let secretKey =
            InputLength::checked(secretKey, self.parameters.description.secretKeyLength)?;
        let digest = MessageHashing::digest(message);
        let mut salt = [0u8; saltLength];
        random.fillRandomBytes(&mut salt);
        let key = KeyGenerator::new(self.parameters).signingKey(secretKey);
        Signer::new(self.parameters)
            .signature(&key, &digest, &salt)
            .ok_or(OQSError::operationFailed)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        let description = &self.parameters.description;
        if signature.len() != description.signatureLength
            || publicKey.len() != description.publicKeyLength
        {
            return false;
        }
        let digest = MessageHashing::digest(message);
        Verifier::new(self.parameters).isValidSignature(signature, &digest, publicKey)
    }
}
