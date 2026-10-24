use crate::parameters::{
    ntruHPS2048509, ntruHPS2048677, ntruHPS4096821, ntruHPS40961229, ntruHRSS701, ntruHRSS1373,
};
use crate::{Packing, Parameters, PolynomialRing, PublicKeyEncryption, Sampler};
use OQSNativeDomain::{InputLength, KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};
use OQSNativeSHA3::SHA3256;

/// NTRU, the lattice key encapsulation mechanism of round 3 of the NIST process, with one
/// parameter set.
///
/// The six parameter sets are `NTRU::ntruHPS2048509` to `NTRU::ntruHRSS1373`, and each gives
/// the bytes of the liboqs algorithm of the same name, whose C code is the clean code of
/// PQClean. A key pair draws two requests of random bytes, the bytes of `f` and `g` and then
/// the key of the implicit rejection. An encapsulation draws one request, the bytes of `r` and
/// `m`. The shared secret is the SHA3-256 of the packed `r` and `m`. Decapsulation does not
/// encrypt again: it checks the ciphertext, `r` and `m`, and a failed check gives the
/// SHA3-256 of the rejection key and the ciphertext, with a mask and no branch. NTRU checks
/// neither key, and liboqs gives it no seeded forms.
pub struct NTRU {
    parameters: &'static Parameters,
}

impl NTRU {
    /// NTRU-HPS-2048-509, security category 1.
    pub const ntruHPS2048509: NTRU = NTRU {
        parameters: &ntruHPS2048509,
    };

    /// NTRU-HPS-2048-677, security category 3.
    pub const ntruHPS2048677: NTRU = NTRU {
        parameters: &ntruHPS2048677,
    };

    /// NTRU-HPS-4096-821, security category 5.
    pub const ntruHPS4096821: NTRU = NTRU {
        parameters: &ntruHPS4096821,
    };

    /// NTRU-HPS-4096-1229, security category 5.
    pub const ntruHPS40961229: NTRU = NTRU {
        parameters: &ntruHPS40961229,
    };

    /// NTRU-HRSS-701, security category 3.
    pub const ntruHRSS701: NTRU = NTRU {
        parameters: &ntruHRSS701,
    };

    /// NTRU-HRSS-1373, security category 5.
    pub const ntruHRSS1373: NTRU = NTRU {
        parameters: &ntruHRSS1373,
    };
}

impl KeyEncapsulating for NTRU {
    fn description(&self) -> &'static KEMDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let parameters = self.parameters;
        let mut seed = SecretBytes::zeroed(parameters.sampleLength());
        random.fillRandomBytes(seed.mutableBytes());
        let (publicKey, mut secretKey) = PublicKeyEncryption::new(parameters).keyPair(seed.bytes());
        let mut rejectionKey = SecretBytes::zeroed(Parameters::rejectionKeyLength);
        random.fillRandomBytes(rejectionKey.mutableBytes());
        secretKey.extend_from_slice(rejectionKey.bytes());
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
        let publicKey = InputLength::checked(publicKey, parameters.description.publicKeyLength)?;
        let mut seed = SecretBytes::zeroed(parameters.sampleLength());
        random.fillRandomBytes(seed.mutableBytes());
        let (mut blinding, message) = Sampler::new(parameters).messagePolynomials(seed.bytes());
        let packing = Packing::new(parameters);
        let mut packed = SecretBytes::zeroed(parameters.messageLength());
        let (packedBlinding, packedMessage) = packed
            .mutableBytes()
            .split_at_mut(parameters.ternaryLength());
        packedBlinding.copy_from_slice(&packing.ternaryBytes(&blinding));
        packedMessage.copy_from_slice(&packing.ternaryBytes(&message));
        let sharedSecret = SHA3256::hash(packed.bytes());
        PolynomialRing::new(parameters).liftTernaryCoefficients(&mut blinding);
        let ciphertext =
            PublicKeyEncryption::new(parameters).encrypt(&blinding, &message, publicKey);
        Ok(Encapsulation {
            ciphertext,
            sharedSecret: SecretBytes::new(sharedSecret.to_vec()),
        })
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let parameters = self.parameters;
        let description = &parameters.description;
        let ciphertext = InputLength::checked(ciphertext, description.ciphertextLength)?;
        let secretKey = InputLength::checked(secretKey, description.secretKeyLength)?;
        let (packed, failure) = PublicKeyEncryption::new(parameters).decrypt(ciphertext, secretKey);
        let packed = SecretBytes::new(packed);
        let mut sharedSecret = SHA3256::hash(packed.bytes());
        let mut hash = SHA3256::new();
        hash.absorb(&secretKey[parameters.encryptionSecretKeyLength()..]);
        hash.absorb(ciphertext);
        let rejectionSecret = hash.finalize();
        // `cmov`: the choice depends on a secret value, so it uses a mask, not a branch.
        let mask = core::hint::black_box(failure).wrapping_neg();
        for (byte, rejected) in sharedSecret.iter_mut().zip(&rejectionSecret) {
            *byte ^= mask & (*byte ^ rejected);
        }
        Ok(SecretBytes::new(sharedSecret.to_vec()))
    }
}
