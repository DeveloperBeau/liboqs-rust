use crate::parameters::{self, Parameters, identifierLength, seedLength};
use crate::{
    AuxiliaryData, LMSWorkingKey, MerkleTree, PrivateKey, SignatureVerification, TreeBuilder,
};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, StatefulSignatureDescription};
use alloc::vec::Vec;

/// LMS and HSS, the hash-based stateful signatures of RFC 8554 and NIST SP 800-208, with one
/// parameter set of liboqs.
///
/// The 33 parameter sets are the constants `LMS::lmsSHA256H5W1` to `LMS::lmsSHA256H20W8H20W8`.
/// Each gives the bytes of the liboqs algorithm of the same name, whose C code is the hash-sigs
/// code of Cisco. A set of one level is an LMS tree of height 5 to 25 with the Winternitz
/// parameter 1, 2, 4 or 8, and a set of two levels is an HSS key whose top tree signs the
/// trees below it.
///
/// A key pair draws 48 random bytes in one request, the seed and the identifier I of the top
/// tree, and signatures draw none. The secret key is the serialized key of liboqs: the private
/// key of hash-sigs, 64 bytes, then the aux data of the key pair. Each signature loads the key,
/// as liboqs does, which costs about one key generation for each level. `workingKey` loads a
/// key once for many signatures.
#[derive(Clone, Copy)]
pub struct LMS {
    parameters: &'static Parameters,
}

impl LMS {
    /// `LMS_SHA256_H5_W1`: one tree of height 5 with the Winternitz parameter 1.
    pub const lmsSHA256H5W1: LMS = LMS::of(&parameters::lmsSHA256H5W1);
    /// `LMS_SHA256_H5_W2`: one tree of height 5 with the Winternitz parameter 2.
    pub const lmsSHA256H5W2: LMS = LMS::of(&parameters::lmsSHA256H5W2);
    /// `LMS_SHA256_H5_W4`: one tree of height 5 with the Winternitz parameter 4.
    pub const lmsSHA256H5W4: LMS = LMS::of(&parameters::lmsSHA256H5W4);
    /// `LMS_SHA256_H5_W8`: one tree of height 5 with the Winternitz parameter 8.
    pub const lmsSHA256H5W8: LMS = LMS::of(&parameters::lmsSHA256H5W8);
    /// `LMS_SHA256_H10_W1`: one tree of height 10 with the Winternitz parameter 1.
    pub const lmsSHA256H10W1: LMS = LMS::of(&parameters::lmsSHA256H10W1);
    /// `LMS_SHA256_H10_W2`: one tree of height 10 with the Winternitz parameter 2.
    pub const lmsSHA256H10W2: LMS = LMS::of(&parameters::lmsSHA256H10W2);
    /// `LMS_SHA256_H10_W4`: one tree of height 10 with the Winternitz parameter 4.
    pub const lmsSHA256H10W4: LMS = LMS::of(&parameters::lmsSHA256H10W4);
    /// `LMS_SHA256_H10_W8`: one tree of height 10 with the Winternitz parameter 8.
    pub const lmsSHA256H10W8: LMS = LMS::of(&parameters::lmsSHA256H10W8);
    /// `LMS_SHA256_H15_W1`: one tree of height 15 with the Winternitz parameter 1.
    pub const lmsSHA256H15W1: LMS = LMS::of(&parameters::lmsSHA256H15W1);
    /// `LMS_SHA256_H15_W2`: one tree of height 15 with the Winternitz parameter 2.
    pub const lmsSHA256H15W2: LMS = LMS::of(&parameters::lmsSHA256H15W2);
    /// `LMS_SHA256_H15_W4`: one tree of height 15 with the Winternitz parameter 4.
    pub const lmsSHA256H15W4: LMS = LMS::of(&parameters::lmsSHA256H15W4);
    /// `LMS_SHA256_H15_W8`: one tree of height 15 with the Winternitz parameter 8.
    pub const lmsSHA256H15W8: LMS = LMS::of(&parameters::lmsSHA256H15W8);
    /// `LMS_SHA256_H20_W1`: one tree of height 20 with the Winternitz parameter 1.
    pub const lmsSHA256H20W1: LMS = LMS::of(&parameters::lmsSHA256H20W1);
    /// `LMS_SHA256_H20_W2`: one tree of height 20 with the Winternitz parameter 2.
    pub const lmsSHA256H20W2: LMS = LMS::of(&parameters::lmsSHA256H20W2);
    /// `LMS_SHA256_H20_W4`: one tree of height 20 with the Winternitz parameter 4.
    pub const lmsSHA256H20W4: LMS = LMS::of(&parameters::lmsSHA256H20W4);
    /// `LMS_SHA256_H20_W8`: one tree of height 20 with the Winternitz parameter 8.
    pub const lmsSHA256H20W8: LMS = LMS::of(&parameters::lmsSHA256H20W8);
    /// `LMS_SHA256_H25_W1`: one tree of height 25 with the Winternitz parameter 1.
    pub const lmsSHA256H25W1: LMS = LMS::of(&parameters::lmsSHA256H25W1);
    /// `LMS_SHA256_H25_W2`: one tree of height 25 with the Winternitz parameter 2.
    pub const lmsSHA256H25W2: LMS = LMS::of(&parameters::lmsSHA256H25W2);
    /// `LMS_SHA256_H25_W4`: one tree of height 25 with the Winternitz parameter 4.
    pub const lmsSHA256H25W4: LMS = LMS::of(&parameters::lmsSHA256H25W4);
    /// `LMS_SHA256_H25_W8`: one tree of height 25 with the Winternitz parameter 8.
    pub const lmsSHA256H25W8: LMS = LMS::of(&parameters::lmsSHA256H25W8);
    /// `LMS_SHA256_H5_W8_H5_W8`: two levels of height 5 with the Winternitz parameter 8.
    pub const lmsSHA256H5W8H5W8: LMS = LMS::of(&parameters::lmsSHA256H5W8H5W8);
    /// `LMS_SHA256_H10_W4_H5_W8`: a top level of height 10 with the Winternitz parameter 4,
    /// and a bottom level of height 5 with the Winternitz parameter 8.
    pub const lmsSHA256H10W4H5W8: LMS = LMS::of(&parameters::lmsSHA256H10W4H5W8);
    /// `LMS_SHA256_H10_W8_H5_W8`: a top level of height 10 and a bottom level of height 5,
    /// both with the Winternitz parameter 8.
    pub const lmsSHA256H10W8H5W8: LMS = LMS::of(&parameters::lmsSHA256H10W8H5W8);
    /// `LMS_SHA256_H10_W2_H10_W2`: two levels of height 10 with the Winternitz parameter 2.
    pub const lmsSHA256H10W2H10W2: LMS = LMS::of(&parameters::lmsSHA256H10W2H10W2);
    /// `LMS_SHA256_H10_W4_H10_W4`: two levels of height 10 with the Winternitz parameter 4.
    pub const lmsSHA256H10W4H10W4: LMS = LMS::of(&parameters::lmsSHA256H10W4H10W4);
    /// `LMS_SHA256_H10_W8_H10_W8`: two levels of height 10 with the Winternitz parameter 8.
    pub const lmsSHA256H10W8H10W8: LMS = LMS::of(&parameters::lmsSHA256H10W8H10W8);
    /// `LMS_SHA256_H15_W8_H5_W8`: a top level of height 15 and a bottom level of height 5,
    /// both with the Winternitz parameter 8.
    pub const lmsSHA256H15W8H5W8: LMS = LMS::of(&parameters::lmsSHA256H15W8H5W8);
    /// `LMS_SHA256_H15_W8_H10_W8`: a top level of height 15 and a bottom level of height 10,
    /// both with the Winternitz parameter 8.
    pub const lmsSHA256H15W8H10W8: LMS = LMS::of(&parameters::lmsSHA256H15W8H10W8);
    /// `LMS_SHA256_H15_W8_H15_W8`: two levels of height 15 with the Winternitz parameter 8.
    pub const lmsSHA256H15W8H15W8: LMS = LMS::of(&parameters::lmsSHA256H15W8H15W8);
    /// `LMS_SHA256_H20_W8_H5_W8`: a top level of height 20 and a bottom level of height 5,
    /// both with the Winternitz parameter 8.
    pub const lmsSHA256H20W8H5W8: LMS = LMS::of(&parameters::lmsSHA256H20W8H5W8);
    /// `LMS_SHA256_H20_W8_H10_W8`: a top level of height 20 and a bottom level of height 10,
    /// both with the Winternitz parameter 8.
    pub const lmsSHA256H20W8H10W8: LMS = LMS::of(&parameters::lmsSHA256H20W8H10W8);
    /// `LMS_SHA256_H20_W8_H15_W8`: a top level of height 20 and a bottom level of height 15,
    /// both with the Winternitz parameter 8.
    pub const lmsSHA256H20W8H15W8: LMS = LMS::of(&parameters::lmsSHA256H20W8H15W8);
    /// `LMS_SHA256_H20_W8_H20_W8`: two levels of height 20 with the Winternitz parameter 8.
    pub const lmsSHA256H20W8H20W8: LMS = LMS::of(&parameters::lmsSHA256H20W8H20W8);

    /// Every LMS set, in the order of the liboqs list.
    pub const schemes: &'static [&'static dyn StatefulSigning] = &[
        &LMS::lmsSHA256H5W1,
        &LMS::lmsSHA256H5W2,
        &LMS::lmsSHA256H5W4,
        &LMS::lmsSHA256H5W8,
        &LMS::lmsSHA256H10W1,
        &LMS::lmsSHA256H10W2,
        &LMS::lmsSHA256H10W4,
        &LMS::lmsSHA256H10W8,
        &LMS::lmsSHA256H15W1,
        &LMS::lmsSHA256H15W2,
        &LMS::lmsSHA256H15W4,
        &LMS::lmsSHA256H15W8,
        &LMS::lmsSHA256H20W1,
        &LMS::lmsSHA256H20W2,
        &LMS::lmsSHA256H20W4,
        &LMS::lmsSHA256H20W8,
        &LMS::lmsSHA256H25W1,
        &LMS::lmsSHA256H25W2,
        &LMS::lmsSHA256H25W4,
        &LMS::lmsSHA256H25W8,
        &LMS::lmsSHA256H5W8H5W8,
        &LMS::lmsSHA256H10W4H5W8,
        &LMS::lmsSHA256H10W8H5W8,
        &LMS::lmsSHA256H10W2H10W2,
        &LMS::lmsSHA256H10W4H10W4,
        &LMS::lmsSHA256H10W8H10W8,
        &LMS::lmsSHA256H15W8H5W8,
        &LMS::lmsSHA256H15W8H10W8,
        &LMS::lmsSHA256H15W8H15W8,
        &LMS::lmsSHA256H20W8H5W8,
        &LMS::lmsSHA256H20W8H10W8,
        &LMS::lmsSHA256H20W8H15W8,
        &LMS::lmsSHA256H20W8H20W8,
    ];

    /// The scheme of a parameter set.
    pub(crate) const fn of(parameters: &'static Parameters) -> LMS {
        LMS { parameters }
    }

    /// Loads a serialized secret key once for many signatures, as `hss_load_private_key` does.
    ///
    /// The load costs about one key generation for each level. The parameter set comes from
    /// the key. A secret key shorter than 64 bytes is `OQSError::invalidLength`, a key after its
    /// last signature is `OQSError::keyExhausted`, and a key with a malformed parameter set, or
    /// whose signature is longer than the signature of this scheme, is
    /// `OQSError::operationFailed`.
    pub fn workingKey(&self, secretKey: &[u8]) -> Result<LMSWorkingKey, OQSError> {
        LMSWorkingKey::load(self.parameters, secretKey)
    }

    /// The key pair of the 48 random bytes of a key pair, as `hss_generate_private_key` makes
    /// it: the HSS public key with the root of the top tree, and the private key with the
    /// aux data.
    fn keyPairOf(&self, randomBytes: &[u8; seedLength + identifierLength]) -> KeyPair {
        let seed: [u8; seedLength] = randomBytes[..seedLength].try_into().expect("32 bytes");
        let identifier: [u8; identifierLength] =
            randomBytes[seedLength..].try_into().expect("16 bytes");
        let levels = self.parameters.levels;
        let privateKey = PrivateKey::new(levels, &seed, &identifier);
        let tree = MerkleTree::new(levels[0], identifier, seed);
        let height = tree.height();
        // The aux data needs every node down to its deepest depth, and the root is node 1.
        let deepestDepth = AuxiliaryData::deepestDepth(height).unwrap_or(0);
        let mut builder = TreeBuilder::wholeTree(tree.clone(), 2 << deepestDepth, height, &[]);
        builder.complete();
        let top = builder.takeTop();
        let mut publicKey = Vec::with_capacity(parameters::publicKeyLength);
        publicKey.extend_from_slice(&(levels.len() as u32).to_be_bytes());
        publicKey.extend_from_slice(&tree.publicKey(&top[1]));
        let mut secretKey = privateKey.bytes.to_vec();
        secretKey.extend_from_slice(&AuxiliaryData::bytes(height, &top, &seed));
        KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        }
    }
}

impl StatefulSigning for LMS {
    fn description(&self) -> &'static StatefulSignatureDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        // `hss_generate_private_key` draws the seed and the identifier I of the top tree in
        // one request of `PRIVATE_KEY_SEED_LEN` bytes.
        let mut randomBytes = [0u8; seedLength + identifierLength];
        random.fillRandomBytes(&mut randomBytes);
        Ok(self.keyPairOf(&randomBytes))
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &mut SecretBytes,
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        // `oqs_sig_stfl_lms_sign` loads a working key for each signature.
        let workingKey = LMSWorkingKey::load(self.parameters, secretKey.bytes())?;
        let (signature, advanced) = workingKey.signatureOnce(message)?;
        // The C library advances the key in memory before it stores it, so the key never signs
        // twice with one state, even when the store fails.
        *secretKey = advanced;
        self.releaseSignature(signature, secretKey.bytes(), persisting)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        SignatureVerification::isValid(signature, message, publicKey)
    }

    fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        // `OQS_SIG_STFL_lms_sigs_left`: the highest count less the count of the key.
        let privateKey = PrivateKey::ofSecretKey(secretKey)?;
        Ok(privateKey.parameterSet().maximumCount() - privateKey.count())
    }

    fn totalSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        // `OQS_SIG_STFL_lms_sigs_total`: the highest count of the parameter set of the key.
        Ok(PrivateKey::ofSecretKey(secretKey)?
            .parameterSet()
            .maximumCount())
    }
}
