use crate::parameters::{
    Parameters, crossRSDP128Balanced, crossRSDP128Fast, crossRSDP128Small, crossRSDP192Balanced,
    crossRSDP192Fast, crossRSDP192Small, crossRSDP256Balanced, crossRSDP256Fast, crossRSDP256Small,
    crossRSDPG128Balanced, crossRSDPG128Fast, crossRSDPG128Small, crossRSDPG192Balanced,
    crossRSDPG192Fast, crossRSDPG192Small, crossRSDPG256Balanced, crossRSDPG256Fast,
    crossRSDPG256Small,
};
use crate::{KeyMaterial, Signer, Verifier};
use OQSNativeDomain::{InputLength, RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, SignatureDescription};
use alloc::vec;
use alloc::vec::Vec;

/// CROSS, the Codes and Restricted Objects Signature Scheme, with one parameter set, as liboqs
/// ships it from the clean code of the CROSS team.
///
/// The eighteen parameter sets are `CROSS::crossRSDP128Balanced` to `CROSS::crossRSDPG256Small`:
/// RSDP or RSDP(G), the security levels 128, 192 and 256, and the trade-offs balanced, fast and
/// small. Each gives the bytes of the liboqs algorithm of the same name. The secret key is a seed
/// of 2 lambda / 8 bytes, so every byte string of that length signs. A key pair draws the seed in
/// one request. A signature draws a root seed of lambda / 8 bytes and then a salt of 2 lambda / 8
/// bytes, in two requests. CROSS has no context string.
pub struct CROSS {
    parameters: &'static Parameters,
}

impl CROSS {
    /// cross-rsdp-128-balanced, at the NIST level 1.
    pub const crossRSDP128Balanced: CROSS = CROSS {
        parameters: &crossRSDP128Balanced,
    };

    /// cross-rsdp-128-fast, at the NIST level 1.
    pub const crossRSDP128Fast: CROSS = CROSS {
        parameters: &crossRSDP128Fast,
    };

    /// cross-rsdp-128-small, at the NIST level 1.
    pub const crossRSDP128Small: CROSS = CROSS {
        parameters: &crossRSDP128Small,
    };

    /// cross-rsdp-192-balanced, at the NIST level 3.
    pub const crossRSDP192Balanced: CROSS = CROSS {
        parameters: &crossRSDP192Balanced,
    };

    /// cross-rsdp-192-fast, at the NIST level 3.
    pub const crossRSDP192Fast: CROSS = CROSS {
        parameters: &crossRSDP192Fast,
    };

    /// cross-rsdp-192-small, at the NIST level 3.
    pub const crossRSDP192Small: CROSS = CROSS {
        parameters: &crossRSDP192Small,
    };

    /// cross-rsdp-256-balanced, at the NIST level 5.
    pub const crossRSDP256Balanced: CROSS = CROSS {
        parameters: &crossRSDP256Balanced,
    };

    /// cross-rsdp-256-fast, at the NIST level 5.
    pub const crossRSDP256Fast: CROSS = CROSS {
        parameters: &crossRSDP256Fast,
    };

    /// cross-rsdp-256-small, at the NIST level 5.
    pub const crossRSDP256Small: CROSS = CROSS {
        parameters: &crossRSDP256Small,
    };

    /// cross-rsdpg-128-balanced, at the NIST level 1.
    pub const crossRSDPG128Balanced: CROSS = CROSS {
        parameters: &crossRSDPG128Balanced,
    };

    /// cross-rsdpg-128-fast, at the NIST level 1.
    pub const crossRSDPG128Fast: CROSS = CROSS {
        parameters: &crossRSDPG128Fast,
    };

    /// cross-rsdpg-128-small, at the NIST level 1.
    pub const crossRSDPG128Small: CROSS = CROSS {
        parameters: &crossRSDPG128Small,
    };

    /// cross-rsdpg-192-balanced, at the NIST level 3.
    pub const crossRSDPG192Balanced: CROSS = CROSS {
        parameters: &crossRSDPG192Balanced,
    };

    /// cross-rsdpg-192-fast, at the NIST level 3.
    pub const crossRSDPG192Fast: CROSS = CROSS {
        parameters: &crossRSDPG192Fast,
    };

    /// cross-rsdpg-192-small, at the NIST level 3.
    pub const crossRSDPG192Small: CROSS = CROSS {
        parameters: &crossRSDPG192Small,
    };

    /// cross-rsdpg-256-balanced, at the NIST level 5.
    pub const crossRSDPG256Balanced: CROSS = CROSS {
        parameters: &crossRSDPG256Balanced,
    };

    /// cross-rsdpg-256-fast, at the NIST level 5.
    pub const crossRSDPG256Fast: CROSS = CROSS {
        parameters: &crossRSDPG256Fast,
    };

    /// cross-rsdpg-256-small, at the NIST level 5.
    pub const crossRSDPG256Small: CROSS = CROSS {
        parameters: &crossRSDPG256Small,
    };
}

impl Signing for CROSS {
    fn description(&self) -> &'static SignatureDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let parameters = self.parameters;
        let mut secretSeed = vec![0u8; parameters.digestLength()];
        random.fillRandomBytes(&mut secretSeed);
        let publicKey = KeyMaterial::expanded(parameters, &secretSeed).publicKey(parameters);
        Ok(KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretSeed),
        })
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        let parameters = self.parameters;
        let secretKey = InputLength::checked(secretKey, parameters.digestLength())?;
        let mut rootSeed = vec![0u8; parameters.seedLength()];
        random.fillRandomBytes(&mut rootSeed);
        let mut salt = vec![0u8; parameters.digestLength()];
        random.fillRandomBytes(&mut salt);
        Ok(Signer::new(parameters).signature(message, secretKey, &rootSeed, &salt))
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        Verifier::new(self.parameters).isValidSignature(signature, message, publicKey)
    }
}
