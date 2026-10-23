use crate::{
    BigEndian, CoreAlgorithms, CoreHash, KeyedHash, MerkleTree, Parameters, SigningFailure, Variant,
};
use OQSNativeDomain::{InputLength, RandomGenerating};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, StatefulSignatureDescription};
use alloc::vec;
use alloc::vec::Vec;

/// The version text of every set, `alg_version` of `sig_stfl_xmss_xmssmt.c`.
const algorithmVersion: &str = "https://datatracker.ietf.org/doc/html/rfc8391";

/// The length of the object identifier in front of each key.
const identifierLength: usize = Parameters::objectIdentifierLength;

/// One liboqs set of XMSS or XMSS^MT: its facts and the wrappers of `sig_stfl_xmss_xmssmt.c`,
/// `sig_stfl_xmss_functions.c`, `sig_stfl_xmssmt_functions.c` and `xmss.c` around the core
/// functions.
///
/// Each key starts with the object identifier of its set. A signature and the counts take the
/// parameters from the identifier of the secret key, as the C code does, and the hash function
/// from the set. A verification needs the identifier of the set in the public key.
pub(crate) struct Scheme {
    variant: Variant,
    function: CoreHash,
    parameters: Parameters,
    description: StatefulSignatureDescription,
}

impl Scheme {
    /// Makes the set of a liboqs name, an object identifier of a variant and a core hash.
    pub(crate) const fn new(
        name: &'static str,
        objectIdentifier: u32,
        variant: Variant,
        function: CoreHash,
    ) -> Scheme {
        let parameters = match Parameters::of(variant, objectIdentifier) {
            Some(parameters) => parameters,
            None => panic!("the object identifier of a set is in the table of params.c"),
        };
        assert!(
            parameters.hashLength == function.outputLength(),
            "the core hash of a set gives n bytes"
        );
        Scheme {
            variant,
            function,
            parameters,
            description: StatefulSignatureDescription {
                objectIdentifier,
                name,
                algorithmVersion,
                isEUFCMASecure: true,
                isSUFCMASecure: false,
                publicKeyLength: identifierLength + parameters.publicKeyLength,
                secretKeyLength: identifierLength + parameters.secretKeyLength,
                signatureLength: parameters.signatureLength,
            },
        }
    }

    /// The facts of the set.
    pub(crate) fn description(&self) -> &StatefulSignatureDescription {
        &self.description
    }

    /// Generates a key pair, as `xmss_keypair` and `xmssmt_keypair`: the identifier of the set,
    /// then the key of the core function.
    pub(crate) fn generateKeyPair(
        &self,
        random: &mut dyn RandomGenerating,
    ) -> Result<KeyPair, OQSError> {
        let mut publicKey = vec![0u8; self.description.publicKeyLength];
        // The key object of liboqs starts zeroed, and the BDS states start from those zeros.
        let mut secretKey = SecretBytes::zeroed(self.description.secretKeyLength);
        let identifier = self.description.objectIdentifier.to_be_bytes();
        publicKey[..identifierLength].copy_from_slice(&identifier);
        secretKey.mutableBytes()[..identifierLength].copy_from_slice(&identifier);
        CoreAlgorithms::new(&self.parameters, self.function)
            .keyPair(
                &mut publicKey[identifierLength..],
                &mut secretKey.mutableBytes()[identifierLength..],
                random,
            )
            .map_err(|_| OQSError::operationFailed)?;
        Ok(KeyPair {
            publicKey,
            secretKey,
        })
    }

    /// The parameters of the identifier of a secret key of the length of the set.
    fn keyParameters(&self, secretKey: &[u8]) -> Result<Parameters, OQSError> {
        let secretKey = InputLength::checked(secretKey, self.description.secretKeyLength)?;
        let identifier = BigEndian::read(&secretKey[..identifierLength]) as u32;
        Parameters::of(self.variant, identifier).ok_or(OQSError::operationFailed)
    }

    /// Signs a message and advances the secret key in place, as `xmss_sign` and `xmssmt_sign`
    /// under `OQS_SIG_STFL_alg_xmss_sign`. The caller saves the advanced key before it releases
    /// the signature.
    ///
    /// A key of another length is `OQSError::invalidLength`, and a key whose identifier is not a
    /// set of the variant is `OQSError::operationFailed`. The identifier of another set of the
    /// variant signs with the parameters of that set and the hash function of this set, as in
    /// the C code. When those parameters have another hash length, or need a longer key or a
    /// longer signature than this set, the C code overruns its buffers, and the port refuses the
    /// key with `OQSError::operationFailed`. A key past its last index is wiped after its
    /// identifier, as the C code wipes it, and gives `OQSError::keyExhausted`.
    pub(crate) fn sign(
        &self,
        message: &[u8],
        secretKey: &mut SecretBytes,
    ) -> Result<Vec<u8>, OQSError> {
        let parameters = self.keyParameters(secretKey.bytes())?;
        // A longer key needs no check here: its first access past the buffer fails as undefined.
        if parameters.hashLength != self.function.outputLength()
            || parameters.signatureLength > self.parameters.signatureLength
        {
            return Err(OQSError::operationFailed);
        }
        // The signature works on a copy, so a failure of a forged state leaves the key as it was.
        let mut advanced = secretKey.clone();
        let algorithms = CoreAlgorithms::new(&parameters, self.function);
        let key = &mut advanced.mutableBytes()[identifierLength..];
        let outcome = match self.variant {
            Variant::xmss => algorithms.singleTreeSignature(key, message),
            Variant::xmssmt => algorithms.multiTreeSignature(key, message),
        };
        match outcome {
            Ok(signature) => {
                *secretKey = advanced;
                Ok(signature)
            }
            Err(SigningFailure::exhausted) => {
                *secretKey = advanced;
                Err(OQSError::keyExhausted)
            }
            Err(SigningFailure::undefined) => Err(OQSError::operationFailed),
        }
    }

    /// True when a signature of a message is valid for a public key, as
    /// `OQS_SIG_STFL_alg_xmss_verify` with the checks of the wrapper of the set: the signature
    /// has the length of the set, and the public key has the length and the identifier of the
    /// set.
    pub(crate) fn isValidSignature(
        &self,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> bool {
        if signature.len() != self.description.signatureLength
            || publicKey.len() != self.description.publicKeyLength
            || publicKey[..identifierLength] != self.description.objectIdentifier.to_be_bytes()
        {
            return false;
        }
        let hashLength = self.parameters.hashLength;
        let key = &publicKey[identifierLength..];
        let hash = KeyedHash::new(&self.parameters, self.function, &key[hashLength..]);
        MerkleTree::isValidSignature(&hash, message, signature, &key[..hashLength])
    }

    /// The index and the last index of a secret key, from the parameters of its identifier.
    fn indices(&self, secretKey: &[u8]) -> Result<(u64, u64), OQSError> {
        let parameters = self.keyParameters(secretKey)?;
        let index = BigEndian::read(
            &secretKey[identifierLength..identifierLength + parameters.indexLength],
        );
        Ok((index, parameters.lastIndex()))
    }

    /// The signatures that a secret key can still make, as `xmss_remaining_signatures`: the last
    /// index minus the index, with the wrap of the unsigned C arithmetic.
    pub(crate) fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        let (index, lastIndex) = self.indices(secretKey)?;
        Ok(lastIndex.wrapping_sub(index))
    }

    /// The signatures that a secret key can make over its life, as `xmss_total_signatures`:
    /// 2^h - 1, one less than the leaves of the hypertree.
    pub(crate) fn totalSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        Ok(self.indices(secretKey)?.1)
    }
}
