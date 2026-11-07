use crate::gf16::GF16;
use crate::gf256::GF256;
use crate::parameters::{
    Parameters, ovIII, ovIIICompressedKeys, ovIIICompressedPublicKey, ovIp, ovIpCompressedKeys,
    ovIpCompressedPublicKey, ovIs, ovIsCompressedKeys, ovIsCompressedPublicKey, ovV,
    ovVCompressedKeys, ovVCompressedPublicKey, saltLength, secretSeedLength,
};
use crate::{Field, KeyForm, KeyGenerator, PublicMap, Signer};
use OQSNativeDomain::{InputLength, RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, SignatureDescription};
use alloc::vec::Vec;

/// UOV, the Unbalanced Oil and Vinegar signature scheme, with one parameter set, as liboqs
/// ships it from the reference code of the pqov project.
///
/// The twelve sets are the liboqs algorithms of the same names: four shapes, `OV-Is`, `OV-Ip`,
/// `OV-III` and `OV-V`, each with classic keys, with a compressed public key (`-pkc`), and
/// with a compressed public key and a compressed secret key (`-pkc-skc`). A key pair draws a
/// 32-byte seed in one request, and a signature draws a 16-byte salt in one request, as liboqs
/// does. A signature is the point w and the salt. UOV has no context string.
pub struct UOV {
    parameters: &'static Parameters,
}

impl UOV {
    /// OV-Is: GF(16), 160 variables and 64 equations, at the NIST level 1.
    pub const ovIs: UOV = UOV { parameters: &ovIs };

    /// OV-Ip: GF(256), 112 variables and 44 equations, at the NIST level 1.
    pub const ovIp: UOV = UOV { parameters: &ovIp };

    /// OV-III: GF(256), 184 variables and 72 equations, at the NIST level 3.
    pub const ovIII: UOV = UOV { parameters: &ovIII };

    /// OV-V: GF(256), 244 variables and 96 equations, at the NIST level 5.
    pub const ovV: UOV = UOV { parameters: &ovV };

    /// OV-Is-pkc: OV-Is with a compressed public key.
    pub const ovIsCompressedPublicKey: UOV = UOV {
        parameters: &ovIsCompressedPublicKey,
    };

    /// OV-Ip-pkc: OV-Ip with a compressed public key.
    pub const ovIpCompressedPublicKey: UOV = UOV {
        parameters: &ovIpCompressedPublicKey,
    };

    /// OV-III-pkc: OV-III with a compressed public key.
    pub const ovIIICompressedPublicKey: UOV = UOV {
        parameters: &ovIIICompressedPublicKey,
    };

    /// OV-V-pkc: OV-V with a compressed public key.
    pub const ovVCompressedPublicKey: UOV = UOV {
        parameters: &ovVCompressedPublicKey,
    };

    /// OV-Is-pkc-skc: OV-Is with a compressed public key and a compressed secret key.
    pub const ovIsCompressedKeys: UOV = UOV {
        parameters: &ovIsCompressedKeys,
    };

    /// OV-Ip-pkc-skc: OV-Ip with a compressed public key and a compressed secret key.
    pub const ovIpCompressedKeys: UOV = UOV {
        parameters: &ovIpCompressedKeys,
    };

    /// OV-III-pkc-skc: OV-III with a compressed public key and a compressed secret key.
    pub const ovIIICompressedKeys: UOV = UOV {
        parameters: &ovIIICompressedKeys,
    };

    /// OV-V-pkc-skc: OV-V with a compressed public key and a compressed secret key.
    pub const ovVCompressedKeys: UOV = UOV {
        parameters: &ovVCompressedKeys,
    };

    /// The key pair of a 32-byte secret seed in the form of the set.
    fn keyPairOfSeed(&self, seed: &[u8; secretSeedLength]) -> (Vec<u8>, SecretBytes) {
        match self.parameters.field {
            Field::gf16 => KeyGenerator::keyPair::<GF16>(self.parameters, seed),
            Field::gf256 => KeyGenerator::keyPair::<GF256>(self.parameters, seed),
        }
    }

    /// The classic secret key of a 32-byte secret seed, as `expand_sk` makes it.
    fn expandedSecretKey(&self, seed: &[u8]) -> SecretBytes {
        match self.parameters.field {
            Field::gf16 => KeyGenerator::expandedSecretKey::<GF16>(self.parameters, seed),
            Field::gf256 => KeyGenerator::expandedSecretKey::<GF256>(self.parameters, seed),
        }
    }

    /// The signature of a message under a classic secret key with a salt.
    fn signature(
        &self,
        classicSecretKey: &[u8],
        message: &[u8],
        salt: &[u8; saltLength],
    ) -> Option<Vec<u8>> {
        match self.parameters.field {
            Field::gf16 => {
                Signer::signature::<GF16>(self.parameters, classicSecretKey, message, salt)
            }
            Field::gf256 => {
                Signer::signature::<GF256>(self.parameters, classicSecretKey, message, salt)
            }
        }
    }

    /// True when a signature of the length of the set is valid under a classic public key.
    fn isValidUnderClassicKey(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        match self.parameters.field {
            Field::gf16 => {
                PublicMap::isValidSignature::<GF16>(self.parameters, signature, message, publicKey)
            }
            Field::gf256 => {
                PublicMap::isValidSignature::<GF256>(self.parameters, signature, message, publicKey)
            }
        }
    }
}

impl Signing for UOV {
    fn description(&self) -> &'static SignatureDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seed = [0u8; secretSeedLength];
        random.fillRandomBytes(&mut seed);
        let (publicKey, secretKey) = self.keyPairOfSeed(&seed);
        Ok(KeyPair {
            publicKey,
            secretKey,
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
        // `ov_expand_and_sign` expands a compressed secret key before it draws the salt, and
        // wipes the expanded key at the end.
        let expanded = match self.parameters.form {
            KeyForm::compressedKeys => Some(self.expandedSecretKey(secretKey)),
            KeyForm::classic | KeyForm::compressedPublicKey => None,
        };
        let classicSecretKey = expanded.as_ref().map_or(secretKey, SecretBytes::bytes);
        let mut salt = [0u8; saltLength];
        random.fillRandomBytes(&mut salt);
        self.signature(classicSecretKey, message, &salt)
            .ok_or(OQSError::operationFailed)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        let description = &self.parameters.description;
        // `crypto_sign_verify` refuses a signature of another length. The C code reads a public
        // key of the length of the set.
        if signature.len() != description.signatureLength
            || publicKey.len() != description.publicKeyLength
        {
            return false;
        }
        match self.parameters.form {
            KeyForm::classic => self.isValidUnderClassicKey(signature, message, publicKey),
            KeyForm::compressedPublicKey | KeyForm::compressedKeys => {
                let expanded = KeyGenerator::expandedPublicKey(self.parameters, publicKey);
                self.isValidUnderClassicKey(signature, message, &expanded)
            }
        }
    }
}
