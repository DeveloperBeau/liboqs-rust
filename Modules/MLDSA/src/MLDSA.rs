use crate::PreHashAlgorithm;
use crate::internalAlgorithms::InternalAlgorithms;
use crate::parameters::{Parameters, mldsa44, mldsa65, mldsa87, representativeLength, seedLength};
use OQSNativeDomain::{InputLength, RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, SignatureDescription};
use alloc::vec::Vec;

/// The longest context string of FIPS 204, 255 bytes.
const maximumContextLength: usize = 255;

/// ML-DSA, the module-lattice digital signature algorithm of FIPS 204, with one parameter set.
///
/// The three parameter sets are `MLDSA::mldsa44`, `MLDSA::mldsa65` and `MLDSA::mldsa87`. Each
/// gives the bytes of the liboqs algorithm of the same name, whose C code is mldsa-native. A
/// key pair draws 32 random bytes in one request, and a signature draws 32 more for its hedged
/// randomness, as liboqs does. A signature takes a context string of up to 255 bytes. The
/// internal forms of FIPS 204 with given randomness, with an external message representative
/// and with a pre-hashed message serve the vector tests of liboqs.
pub struct MLDSA {
    parameters: &'static Parameters,
}

impl MLDSA {
    /// ML-DSA-44, at the NIST level 2.
    pub const mldsa44: MLDSA = MLDSA {
        parameters: &mldsa44,
    };

    /// ML-DSA-65, at the NIST level 3.
    pub const mldsa65: MLDSA = MLDSA {
        parameters: &mldsa65,
    };

    /// ML-DSA-87, at the NIST level 5.
    pub const mldsa87: MLDSA = MLDSA {
        parameters: &mldsa87,
    };

    fn internalAlgorithms(&self) -> InternalAlgorithms<'static> {
        InternalAlgorithms::new(self.parameters)
    }

    /// The prefix of the formatted message M' of FIPS 204, Algorithms 2 and 4, as
    /// `mld_prepare_domain_separation_prefix` writes it: the domain byte, the length of the
    /// context and the context, then for a pre-hash signature the identifier of the hash
    /// function and the hash.
    fn formattedPrefix(
        context: &[u8],
        preHash: Option<(PreHashAlgorithm, &[u8])>,
    ) -> Result<Vec<u8>, OQSError> {
        if context.len() > maximumContextLength {
            return Err(OQSError::contextTooLong);
        }
        let mut prefix = Vec::with_capacity(2 + context.len() + 11 + 64);
        prefix.push(u8::from(preHash.is_some()));
        prefix.push(context.len() as u8);
        prefix.extend_from_slice(context);
        if let Some((algorithm, hash)) = preHash {
            prefix.extend_from_slice(&algorithm.objectIdentifier());
            prefix.extend_from_slice(hash);
        }
        Ok(prefix)
    }

    /// The signature of a formatted message under a secret key with 32 bytes of randomness,
    /// with the message representative that the secret key gives it.
    fn signatureOfFormattedMessage(
        &self,
        prefix: &[u8],
        message: &[u8],
        secretKey: &[u8],
        randomness: &[u8; seedLength],
    ) -> Result<Vec<u8>, OQSError> {
        // tr, the hash of the public key, follows rho and K in the secret key.
        let publicKeyHash = &secretKey[2 * seedLength..2 * seedLength + representativeLength];
        let representative =
            InternalAlgorithms::messageRepresentative(publicKeyHash, prefix, message);
        self.internalAlgorithms()
            .signature(secretKey, &representative, randomness)
            .ok_or(OQSError::operationFailed)
    }

    /// True when a signature of a formatted message is valid for a public key of the right
    /// length.
    fn isValidSignatureOfFormattedMessage(
        &self,
        signature: &[u8],
        prefix: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> bool {
        if publicKey.len() != self.parameters.description.publicKeyLength {
            return false;
        }
        let publicKeyHash = InternalAlgorithms::publicKeyHash(publicKey);
        let representative =
            InternalAlgorithms::messageRepresentative(&publicKeyHash, prefix, message);
        self.internalAlgorithms()
            .isValidSignature(signature, publicKey, &representative)
    }

    /// The randomness of an internal signature: exactly 32 bytes.
    fn checkedRandomness(randomness: &[u8]) -> Result<&[u8; seedLength], OQSError> {
        Ok(InputLength::checked(randomness, seedLength)?
            .try_into()
            .expect("32 bytes"))
    }

    /// Signs with ML-DSA.Sign_internal of FIPS 204, Algorithm 7, as
    /// `signature_internal` of mldsa-native with an empty prefix: the message is M' as it is,
    /// or with `isExternalMu` the 64-byte message representative mu.
    ///
    /// `tests/vectors_sig.c` calls this form for the internal vectors of ACVP and Wycheproof.
    /// The randomness has 32 bytes, all zero for the deterministic variant.
    pub fn internalSignature(
        &self,
        message: &[u8],
        secretKey: &[u8],
        randomness: &[u8],
        isExternalMu: bool,
    ) -> Result<Vec<u8>, OQSError> {
        let secretKey =
            InputLength::checked(secretKey, self.parameters.description.secretKeyLength)?;
        let randomness = Self::checkedRandomness(randomness)?;
        if isExternalMu {
            let representative: &[u8; representativeLength] =
                InputLength::checked(message, representativeLength)?
                    .try_into()
                    .expect("64 bytes");
            return self
                .internalAlgorithms()
                .signature(secretKey, representative, randomness)
                .ok_or(OQSError::operationFailed);
        }
        self.signatureOfFormattedMessage(&[], message, secretKey, randomness)
    }

    /// True when a signature is valid under ML-DSA.Verify_internal of FIPS 204, Algorithm 8,
    /// as `verify_internal` of mldsa-native with an empty prefix: the message is M' as it is,
    /// or with `isExternalMu` the 64-byte message representative mu.
    ///
    /// `tests/vectors_sig.c` calls this form for the internal vectors of ACVP and Wycheproof.
    pub fn isValidInternalSignature(
        &self,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
        isExternalMu: bool,
    ) -> bool {
        if !isExternalMu {
            return self.isValidSignatureOfFormattedMessage(signature, &[], message, publicKey);
        }
        let Ok(representative) = <&[u8; representativeLength]>::try_from(message) else {
            return false;
        };
        publicKey.len() == self.parameters.description.publicKeyLength
            && self
                .internalAlgorithms()
                .isValidSignature(signature, publicKey, representative)
    }

    /// Signs the hash of a message with HashML-DSA.Sign of FIPS 204, Algorithm 4, as
    /// `signature_pre_hash_internal` of mldsa-native: the hash comes from the caller, with the
    /// length of its hash function, and the randomness has 32 bytes.
    ///
    /// `tests/vectors_sig.c` calls this form for the pre-hash vectors of ACVP.
    pub fn preHashSignature(
        &self,
        hash: &[u8],
        hashAlgorithm: PreHashAlgorithm,
        context: &[u8],
        secretKey: &[u8],
        randomness: &[u8],
    ) -> Result<Vec<u8>, OQSError> {
        let hash = InputLength::checked(hash, hashAlgorithm.hashLength())?;
        let secretKey =
            InputLength::checked(secretKey, self.parameters.description.secretKeyLength)?;
        let randomness = Self::checkedRandomness(randomness)?;
        let prefix = Self::formattedPrefix(context, Some((hashAlgorithm, hash)))?;
        self.signatureOfFormattedMessage(&prefix, &[], secretKey, randomness)
    }

    /// True when a signature of the hash of a message is valid under HashML-DSA.Verify of
    /// FIPS 204, Algorithm 5, as `verify_pre_hash_internal` of mldsa-native.
    ///
    /// `tests/vectors_sig.c` calls this form for the pre-hash vectors of ACVP.
    pub fn isValidPreHashSignature(
        &self,
        signature: &[u8],
        hash: &[u8],
        hashAlgorithm: PreHashAlgorithm,
        context: &[u8],
        publicKey: &[u8],
    ) -> bool {
        if hash.len() != hashAlgorithm.hashLength() {
            return false;
        }
        let Ok(prefix) = Self::formattedPrefix(context, Some((hashAlgorithm, hash))) else {
            return false;
        };
        self.isValidSignatureOfFormattedMessage(signature, &prefix, &[], publicKey)
    }
}

impl Signing for MLDSA {
    fn description(&self) -> &'static SignatureDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut seed = [0u8; seedLength];
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
        // `OQS_SIG_sign` signs with the empty context.
        self.signWithContext(message, &[], secretKey, random)
    }

    fn signWithContext(
        &self,
        message: &[u8],
        context: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        let secretKey =
            InputLength::checked(secretKey, self.parameters.description.secretKeyLength)?;
        // The C code checks the context before it draws the randomness.
        let prefix = Self::formattedPrefix(context, None)?;
        let mut randomness = [0u8; seedLength];
        random.fillRandomBytes(&mut randomness);
        self.signatureOfFormattedMessage(&prefix, message, secretKey, &randomness)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        self.isValidSignatureWithContext(signature, message, &[], publicKey)
    }

    fn isValidSignatureWithContext(
        &self,
        signature: &[u8],
        message: &[u8],
        context: &[u8],
        publicKey: &[u8],
    ) -> bool {
        let Ok(prefix) = Self::formattedPrefix(context, None) else {
            return false;
        };
        self.isValidSignatureOfFormattedMessage(signature, &prefix, message, publicKey)
    }
}
