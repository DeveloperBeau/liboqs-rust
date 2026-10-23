use crate::{
    Address, ByteConversion, FORS, HashContext, Hypertree, Parameters, PreHash, SchemeName,
    parameterSets,
};
use OQSNativeDomain::{InputLength, RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, SignatureDescription};
use alloc::vec;
use alloc::vec::Vec;

/// SLH-DSA, the stateless hash-based signature scheme of FIPS 205, with one parameter set and
/// either the pure form or a pre-hash function, as liboqs ships it.
///
/// The twelve parameter sets of FIPS 205 are the constants `SLHDSA::sha2128s` to
/// `SLHDSA::shake256f`, in the pure form of liboqs `SLH_DSA_PURE_<set>`. `preHashed` gives the
/// pre-hash form HashSLH-DSA of a set, the liboqs scheme `SLH_DSA_<function>_PREHASH_<set>`.
/// `SLHDSA::schemes` lists all 156 schemes in the order of the liboqs list.
///
/// A key pair draws `3 n` random bytes in one request: `SK.seed`, `SK.prf` and `PK.seed`. A
/// signature draws the `n` bytes of the additional randomness `addrnd` in one request, also
/// when the context is too long, as the C code does. Each scheme signs with a context of up to
/// 255 bytes.
#[derive(Clone, Copy)]
pub struct SLHDSA {
    parameters: &'static Parameters,
    preHash: Option<PreHash>,
}

/// The number of schemes: the pure form and the twelve pre-hash forms of each parameter set.
const schemeCount: usize = 13 * 12;

/// The longest context string of FIPS 205, Algorithms 22 to 25.
const maximumContextLength: usize = 255;

/// The liboqs names of the schemes, in the order of the liboqs list.
static schemeNames: [SchemeName; schemeCount] = SLHDSA::names();

/// The facts of the schemes, in the order of the liboqs list.
static schemeDescriptions: [SignatureDescription; schemeCount] = SLHDSA::descriptions(&schemeNames);

/// The schemes, in the order of the liboqs list.
static everyScheme: [SLHDSA; schemeCount] = SLHDSA::everyScheme();

impl SLHDSA {
    /// SLH-DSA-SHA2-128s of FIPS 205, security category 1, the liboqs scheme
    /// `SLH_DSA_PURE_SHA2_128S`.
    pub const sha2128s: SLHDSA = SLHDSA::pure(0);
    /// SLH-DSA-SHA2-128f of FIPS 205, security category 1, `SLH_DSA_PURE_SHA2_128F`.
    pub const sha2128f: SLHDSA = SLHDSA::pure(1);
    /// SLH-DSA-SHA2-192s of FIPS 205, security category 3, `SLH_DSA_PURE_SHA2_192S`.
    pub const sha2192s: SLHDSA = SLHDSA::pure(2);
    /// SLH-DSA-SHA2-192f of FIPS 205, security category 3, `SLH_DSA_PURE_SHA2_192F`.
    pub const sha2192f: SLHDSA = SLHDSA::pure(3);
    /// SLH-DSA-SHA2-256s of FIPS 205, security category 5, `SLH_DSA_PURE_SHA2_256S`.
    pub const sha2256s: SLHDSA = SLHDSA::pure(4);
    /// SLH-DSA-SHA2-256f of FIPS 205, security category 5, `SLH_DSA_PURE_SHA2_256F`.
    pub const sha2256f: SLHDSA = SLHDSA::pure(5);
    /// SLH-DSA-SHAKE-128s of FIPS 205, security category 1, `SLH_DSA_PURE_SHAKE_128S`.
    pub const shake128s: SLHDSA = SLHDSA::pure(6);
    /// SLH-DSA-SHAKE-128f of FIPS 205, security category 1, `SLH_DSA_PURE_SHAKE_128F`.
    pub const shake128f: SLHDSA = SLHDSA::pure(7);
    /// SLH-DSA-SHAKE-192s of FIPS 205, security category 3, `SLH_DSA_PURE_SHAKE_192S`.
    pub const shake192s: SLHDSA = SLHDSA::pure(8);
    /// SLH-DSA-SHAKE-192f of FIPS 205, security category 3, `SLH_DSA_PURE_SHAKE_192F`.
    pub const shake192f: SLHDSA = SLHDSA::pure(9);
    /// SLH-DSA-SHAKE-256s of FIPS 205, security category 5, `SLH_DSA_PURE_SHAKE_256S`.
    pub const shake256s: SLHDSA = SLHDSA::pure(10);
    /// SLH-DSA-SHAKE-256f of FIPS 205, security category 5, `SLH_DSA_PURE_SHAKE_256F`.
    pub const shake256f: SLHDSA = SLHDSA::pure(11);

    /// The twelve pure schemes, in the order of the liboqs list.
    pub const pureSchemes: [SLHDSA; 12] = [
        SLHDSA::sha2128s,
        SLHDSA::sha2128f,
        SLHDSA::sha2192s,
        SLHDSA::sha2192f,
        SLHDSA::sha2256s,
        SLHDSA::sha2256f,
        SLHDSA::shake128s,
        SLHDSA::shake128f,
        SLHDSA::shake192s,
        SLHDSA::shake192f,
        SLHDSA::shake256s,
        SLHDSA::shake256f,
    ];

    /// Every scheme of the family as a signature capability, in the order of the liboqs list:
    /// the twelve pure schemes, and then the twelve parameter sets with each pre-hash function
    /// of `PreHash::all` in turn.
    pub const schemes: &'static [&'static dyn Signing] = &SLHDSA::capabilities(&everyScheme);

    /// The pure form of the parameter set at a position of the liboqs list.
    const fn pure(index: usize) -> SLHDSA {
        SLHDSA {
            parameters: &parameterSets[index],
            preHash: None,
        }
    }

    /// The pre-hash form HashSLH-DSA of the parameter set with a hash function, FIPS 205,
    /// Section 10.2.2: the liboqs scheme `SLH_DSA_<function>_PREHASH_<set>`.
    pub const fn preHashed(self, preHash: PreHash) -> SLHDSA {
        SLHDSA {
            parameters: self.parameters,
            preHash: Some(preHash),
        }
    }

    /// The position of the scheme in the liboqs list.
    const fn position(&self) -> usize {
        let form = match self.preHash {
            None => 0,
            Some(preHash) => 1 + preHash.index(),
        };
        form * 12 + self.parameters.index
    }

    /// The schemes in the order of the liboqs list.
    const fn everyScheme() -> [SLHDSA; schemeCount] {
        let mut schemes = [SLHDSA::pure(0); schemeCount];
        let mut position = 0;
        while position < schemeCount {
            let scheme = SLHDSA::pure(position % 12);
            schemes[position] = match position / 12 {
                0 => scheme,
                form => scheme.preHashed(PreHash::all[form - 1]),
            };
            position += 1;
        }
        schemes
    }

    /// The names of the schemes in the order of the liboqs list.
    const fn names() -> [SchemeName; schemeCount] {
        let schemes = SLHDSA::everyScheme();
        let mut names = [const { SchemeName::new(&parameterSets[0], None) }; schemeCount];
        let mut position = 0;
        while position < schemeCount {
            names[position] =
                SchemeName::new(schemes[position].parameters, schemes[position].preHash);
            position += 1;
        }
        names
    }

    /// The facts of the schemes, which liboqs gives the same for each form of a set: version
    /// `FIPS205`, EUF-CMA, no SUF-CMA, and context support.
    const fn descriptions(
        names: &'static [SchemeName; schemeCount],
    ) -> [SignatureDescription; schemeCount] {
        let schemes = SLHDSA::everyScheme();
        let mut descriptions = [SignatureDescription {
            name: "",
            algorithmVersion: "FIPS205",
            claimedNISTLevel: 0,
            isEUFCMASecure: true,
            isSUFCMASecure: false,
            supportsContext: true,
            publicKeyLength: 0,
            secretKeyLength: 0,
            signatureLength: 0,
        }; schemeCount];
        let mut position = 0;
        while position < schemeCount {
            let parameters = schemes[position].parameters;
            let description = &mut descriptions[position];
            description.name = names[position].text();
            description.claimedNISTLevel = parameters.claimedNISTLevel;
            description.publicKeyLength = parameters.publicKeyLength();
            description.secretKeyLength = parameters.secretKeyLength();
            description.signatureLength = parameters.signatureLength();
            position += 1;
        }
        descriptions
    }

    /// The schemes as signature capabilities.
    const fn capabilities(
        schemes: &'static [SLHDSA; schemeCount],
    ) -> [&'static dyn Signing; schemeCount] {
        let mut capabilities: [&'static dyn Signing; schemeCount] = [&schemes[0]; schemeCount];
        let mut position = 1;
        while position < schemeCount {
            capabilities[position] = &schemes[position];
            position += 1;
        }
        capabilities
    }

    /// `slh_keygen_internal` of FIPS 205, Algorithm 18, from `SK.seed || SK.prf || PK.seed`.
    fn keyPair(&self, seeds: &[u8]) -> KeyPair {
        let parameters = self.parameters;
        let n = parameters.hashLength;
        let zeros = [0u8; Parameters::maximumHashLength];
        let mut context = HashContext::new(
            parameters,
            &seeds[..n],
            &seeds[n..2 * n],
            &seeds[2 * n..3 * n],
            &zeros[..n],
        );
        let root = Hypertree::root(&mut context);
        let mut secretKey = Vec::with_capacity(parameters.secretKeyLength());
        secretKey.extend_from_slice(&seeds[..3 * n]);
        secretKey.extend_from_slice(&root[..n]);
        let mut publicKey = Vec::with_capacity(parameters.publicKeyLength());
        publicKey.extend_from_slice(&seeds[2 * n..3 * n]);
        publicKey.extend_from_slice(&root[..n]);
        KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        }
    }

    /// The tree and the leaf of the bottom layer that a digest selects, `split_digest` of the C
    /// code and FIPS 205, Algorithm 19, lines 7 to 10.
    fn treeAndLeafIndex(parameters: &Parameters, digest: &[u8]) -> (u64, u32) {
        let treeBits = parameters.hypertreeHeight - parameters.treeHeight;
        let treeStart = parameters.forsDigestLength();
        let treeLength = treeBits.div_ceil(8) as usize;
        let leafLength = parameters.treeHeight.div_ceil(8) as usize;
        let mut treeIndex = ByteConversion::toInteger(&digest[treeStart..treeStart + treeLength]);
        if treeBits != 64 {
            treeIndex &= (1u64 << treeBits) - 1;
        }
        let leafStart = treeStart + treeLength;
        let leafIndex = ByteConversion::toInteger(&digest[leafStart..leafStart + leafLength])
            as u32
            & ((1u32 << parameters.treeHeight) - 1);
        (treeIndex, leafIndex)
    }

    /// `slh_sign_internal` of FIPS 205, Algorithm 19, with the message of the pure form when a
    /// context is given. The secret key and the randomness have their lengths.
    fn signature(
        &self,
        message: &[u8],
        context: Option<&[u8]>,
        secretKey: &[u8],
        additionalRandomness: &[u8],
    ) -> Vec<u8> {
        let parameters = self.parameters;
        let n = parameters.hashLength;
        let mut hashes = HashContext::fromSecretKey(parameters, secretKey);
        let mut signature = vec![0u8; parameters.signatureLength()];
        let randomizer = hashes.prfMessage(additionalRandomness, context, message);
        signature[..n].copy_from_slice(&randomizer[..n]);
        let mut digest = [0u8; Parameters::maximumDigestLength];
        let digest = &mut digest[..parameters.digestLength];
        hashes.messageDigest(&randomizer[..n], context, message, digest);
        let (treeIndex, leafIndex) = Self::treeAndLeafIndex(parameters, digest);
        hashes.address = Address::zero;
        hashes.address.setTreeAddress(treeIndex);
        hashes
            .address
            .setTypeAndClearKeepingKeyPair(Address::forsTree);
        hashes.address.setKeyPairAddress(leafIndex);
        let forsEnd = n + parameters.forsSignatureLength();
        let forsDigest = &digest[..parameters.forsDigestLength()];
        FORS::sign(&mut hashes, &mut signature[n..forsEnd], forsDigest);
        // The C code takes the FORS public key from the FORS signature.
        let forsPublicKey =
            FORS::publicKeyFromSignature(&mut hashes, &signature[n..forsEnd], forsDigest);
        Hypertree::sign(
            &mut hashes,
            &mut signature[forsEnd..],
            &forsPublicKey[..n],
            treeIndex,
            leafIndex,
        );
        signature
    }

    /// `slh_verify_internal` of FIPS 205, Algorithm 20, with the message of the pure form when
    /// a context is given. A signature or a public key of another length is not valid.
    fn isValid(
        &self,
        signature: &[u8],
        message: &[u8],
        context: Option<&[u8]>,
        publicKey: &[u8],
    ) -> bool {
        let parameters = self.parameters;
        let n = parameters.hashLength;
        if signature.len() != parameters.signatureLength()
            || publicKey.len() != parameters.publicKeyLength()
        {
            return false;
        }
        let mut hashes = HashContext::fromPublicKey(parameters, publicKey);
        let mut digest = [0u8; Parameters::maximumDigestLength];
        let digest = &mut digest[..parameters.digestLength];
        hashes.messageDigest(&signature[..n], context, message, digest);
        let (treeIndex, leafIndex) = Self::treeAndLeafIndex(parameters, digest);
        hashes.address = Address::zero;
        hashes.address.setTreeAddress(treeIndex);
        hashes
            .address
            .setTypeAndClearKeepingKeyPair(Address::forsTree);
        hashes.address.setKeyPairAddress(leafIndex);
        let forsEnd = n + parameters.forsSignatureLength();
        let forsPublicKey = FORS::publicKeyFromSignature(
            &mut hashes,
            &signature[n..forsEnd],
            &digest[..parameters.forsDigestLength()],
        );
        Hypertree::isValid(
            &mut hashes,
            &forsPublicKey[..n],
            &signature[forsEnd..],
            treeIndex,
            leafIndex,
        )
    }

    /// The message `M'` of the pre-hash form, FIPS 205, Algorithms 23 and 25:
    /// `toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M)`, as `hash_slh_dsa_pad` of the C
    /// code makes it. The context has at most 255 bytes.
    fn preHashedMessage(preHash: PreHash, context: &[u8], message: &[u8]) -> Vec<u8> {
        let mut prefixed = Vec::with_capacity(2 + context.len() + 11 + 64);
        prefixed.push(1);
        prefixed.push(context.len() as u8);
        prefixed.extend_from_slice(context);
        prefixed.extend_from_slice(&preHash.objectIdentifier());
        preHash.appendDigest(message, &mut prefixed);
        prefixed
    }

    /// `slh_sign_internal` of FIPS 205, Algorithm 19: the signature of a message with the
    /// additional randomness `addrnd` of `n` bytes, with no context and no pre-hash. A
    /// deterministic signature passes `PK.seed` as the randomness.
    ///
    /// `VectorsSig.rs` needs it for the ACVP vectors of the internal interface, which
    /// `tests/vectors_sig.c` signs with the C function `slh_sign_internal`.
    pub fn signInternal(
        &self,
        message: &[u8],
        secretKey: &[u8],
        additionalRandomness: &[u8],
    ) -> Result<Vec<u8>, OQSError> {
        let parameters = self.parameters;
        let secretKey = InputLength::checked(secretKey, parameters.secretKeyLength())?;
        let randomness = InputLength::checked(additionalRandomness, parameters.hashLength)?;
        Ok(self.signature(message, None, secretKey, randomness))
    }

    /// `slh_verify_internal` of FIPS 205, Algorithm 20: true when a signature of a message
    /// with no context and no pre-hash is valid for a public key.
    ///
    /// `VectorsSig.rs` needs it for the ACVP vectors of the internal interface, which
    /// `tests/vectors_sig.c` checks with the C function `slh_verify_internal`.
    pub fn isValidSignatureInternal(
        &self,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> bool {
        self.isValid(signature, message, None, publicKey)
    }
}

impl Signing for SLHDSA {
    fn description(&self) -> &'static SignatureDescription {
        &schemeDescriptions[self.position()]
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let n = self.parameters.hashLength;
        let mut seeds = [0u8; 3 * Parameters::maximumHashLength];
        random.fillRandomBytes(&mut seeds[..3 * n]);
        Ok(self.keyPair(&seeds[..3 * n]))
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        self.signWithContext(message, &[], secretKey, random)
    }

    fn signWithContext(
        &self,
        message: &[u8],
        context: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        let parameters = self.parameters;
        let secretKey = InputLength::checked(secretKey, parameters.secretKeyLength())?;
        // The C code draws `addrnd` before it checks the context.
        let mut randomness = [0u8; Parameters::maximumHashLength];
        let randomness = &mut randomness[..parameters.hashLength];
        random.fillRandomBytes(randomness);
        if context.len() > maximumContextLength {
            return Err(OQSError::contextTooLong);
        }
        Ok(match self.preHash {
            None => self.signature(message, Some(context), secretKey, randomness),
            Some(preHash) => self.signature(
                &Self::preHashedMessage(preHash, context, message),
                None,
                secretKey,
                randomness,
            ),
        })
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
        if context.len() > maximumContextLength {
            return false;
        }
        match self.preHash {
            None => self.isValid(signature, message, Some(context), publicKey),
            Some(preHash) => self.isValid(
                signature,
                &Self::preHashedMessage(preHash, context, message),
                None,
                publicKey,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SLHDSA, everyScheme, schemeCount, schemeDescriptions};
    use crate::{PreHash, parameterSets};
    use OQSNativeDomain::Signing;

    #[test]
    fn schemesFollowTheLiboqsListWithTheirNames() {
        assert_eq!(SLHDSA::schemes.len(), schemeCount);
        assert_eq!(
            SLHDSA::schemes[0].description().name,
            "SLH_DSA_PURE_SHA2_128S"
        );
        assert_eq!(
            SLHDSA::schemes[11].description().name,
            "SLH_DSA_PURE_SHAKE_256F"
        );
        assert_eq!(
            SLHDSA::schemes[12].description().name,
            "SLH_DSA_SHA2_224_PREHASH_SHA2_128S"
        );
        assert_eq!(
            SLHDSA::schemes[155].description().name,
            "SLH_DSA_SHAKE_256_PREHASH_SHAKE_256F"
        );
        for (position, scheme) in everyScheme.iter().enumerate() {
            assert_eq!(scheme.position(), position);
            assert!(core::ptr::eq(
                scheme.description(),
                &schemeDescriptions[position]
            ));
            assert_eq!(
                SLHDSA::schemes[position].description().name,
                scheme.description().name
            );
        }
    }

    #[test]
    fn preHashedFormsKeepTheSetAndTakeTheirOwnName() {
        let scheme = SLHDSA::shake192f.preHashed(PreHash::sha3384);
        assert_eq!(
            scheme.description().name,
            "SLH_DSA_SHA3_384_PREHASH_SHAKE_192F"
        );
        assert!(core::ptr::eq(scheme.parameters, &parameterSets[9]));
        let again = scheme.preHashed(PreHash::sha256);
        assert_eq!(
            again.description().name,
            "SLH_DSA_SHA2_256_PREHASH_SHAKE_192F"
        );
        for (index, scheme) in SLHDSA::pureSchemes.iter().enumerate() {
            assert_eq!(scheme.parameters.index, index);
            assert!(scheme.preHash.is_none());
        }
    }

    #[test]
    fn everyFormOfASetHasTheFactsOfTheSet() {
        for scheme in &everyScheme {
            let description = scheme.description();
            let parameters = scheme.parameters;
            assert_eq!(description.algorithmVersion, "FIPS205");
            assert_eq!(description.claimedNISTLevel, parameters.claimedNISTLevel);
            assert!(description.isEUFCMASecure && !description.isSUFCMASecure);
            assert!(description.supportsContext);
            assert_eq!(description.publicKeyLength, 2 * parameters.hashLength);
            assert_eq!(description.secretKeyLength, 4 * parameters.hashLength);
            assert_eq!(description.signatureLength, parameters.signatureLength());
            assert!(description.name.ends_with(parameters.liboqsName));
        }
    }

    #[test]
    fn treeAndLeafIndexTakeTheirBitsAfterTheFORSDigest() {
        // SHA2-128s: 21 bytes of FORS digest, 7 bytes of tree index masked to 54 bits, and 2
        // bytes of leaf index masked to 9 bits.
        let mut digest = [0u8; 30];
        digest[21..28].copy_from_slice(&[0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99]);
        digest[28..30].copy_from_slice(&[0xFF, 0x34]);
        let (treeIndex, leafIndex) = SLHDSA::treeAndLeafIndex(&parameterSets[0], &digest);
        assert_eq!(treeIndex, 0x00FF_EEDD_CCBB_AA99 & ((1 << 54) - 1));
        assert_eq!(leafIndex, 0x1FF34 & 0x1FF);
        // SHA2-256f: h - h' = 64, so the 8 bytes of the tree index are kept whole.
        let mut digest = [0u8; 49];
        digest[40..48].copy_from_slice(&[0xF1, 2, 3, 4, 5, 6, 7, 8]);
        digest[48] = 0xFF;
        let (treeIndex, leafIndex) = SLHDSA::treeAndLeafIndex(&parameterSets[5], &digest);
        assert_eq!(treeIndex, 0xF102_0304_0506_0708);
        assert_eq!(leafIndex, 0x0F);
    }
}
