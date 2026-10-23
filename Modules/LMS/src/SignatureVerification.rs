use crate::parameters::{hashLength, identifierLength, maximumLevelCount, publicKeyLength};
use crate::{LevelType, MerkleTree, OneTimeSignature, OneTimeSignatureType, TreeType};

/// The verification of an HSS signature, RFC 8554, Algorithm 6b and Section 6.3, as
/// `hss_validate_signature_init`, `hss_validate_signature_finalize` and `lm_validate_signature`
/// of hash-sigs decide it, with the patch of liboqs that also reads a raw LMS public key.
///
/// The public key and the signature give their own parameter sets, so a verification under
/// any LMS set of liboqs accepts a valid signature of another set.
pub(crate) struct SignatureVerification;

/// A big-endian 32-bit word at a place of a slice that is long enough.
fn word(bytes: &[u8], place: usize) -> u64 {
    u64::from(u32::from_be_bytes(
        bytes[place..place + 4].try_into().expect("4 bytes"),
    ))
}

impl SignatureVerification {
    /// True when a signature of a message is valid for a public key.
    ///
    /// The C code reads the public key from a buffer of 60 bytes. A shorter key is read with
    /// zeros after it, as the C oracle gives it to the C code, so the raw LMS public key of 56
    /// bytes verifies. A longer key is not valid.
    pub(crate) fn isValid(signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        if publicKey.len() > publicKeyLength {
            return false;
        }
        let mut paddedKey = [0u8; publicKeyLength];
        paddedKey[..publicKey.len()].copy_from_slice(publicKey);
        Self::isValidForPaddedKey(signature, message, &paddedKey)
    }

    /// True when the words of a public key and of a signature show the HSS public key form,
    /// `is_hss_public_key` of liboqs: the level count of the signature, from 1 to 8, equals the
    /// first word of the key, the one-time typecode of the first signature equals the third
    /// word of the key, and the second and third words of the key are known typecodes.
    fn isHSSPublicKey(publicKey: &[u8; publicKeyLength], signature: &[u8]) -> bool {
        let signatureLevels = word(signature, 0) + 1;
        if signatureLevels > maximumLevelCount as u64 || word(publicKey, 0) != signatureLevels {
            return false;
        }
        word(publicKey, 8) == word(signature, 8)
            && TreeType::ofCode(word(publicKey, 4)).is_some()
            && OneTimeSignatureType::ofCode(word(publicKey, 8)).is_some()
    }

    /// The level count of a public key, `public_key_levels` of liboqs: the first word of a key
    /// of the HSS form, 1 for a raw LMS public key of two known typecodes, and 0 for any other
    /// key.
    fn publicKeyLevels(publicKey: &[u8; publicKeyLength], signature: &[u8]) -> u64 {
        if Self::isHSSPublicKey(publicKey, signature) {
            return word(publicKey, 0);
        }
        let isRawKey = TreeType::ofCode(word(publicKey, 0)).is_some()
            && OneTimeSignatureType::ofCode(word(publicKey, 4)).is_some();
        u64::from(isRawKey)
    }

    /// The verification of a public key of 60 bytes.
    fn isValidForPaddedKey(
        signature: &[u8],
        message: &[u8],
        paddedKey: &[u8; publicKeyLength],
    ) -> bool {
        // The C code reads the first three words of the signature before it knows its length.
        // Every signature shorter than them fails a later length check, so it is not valid.
        if signature.len() < 12 {
            return false;
        }
        let levels = word(signature, 0) + 1;
        let publicKeyLevels = Self::publicKeyLevels(paddedKey, signature);
        let mut publicKey: &[u8] = if Self::isHSSPublicKey(paddedKey, signature) {
            &paddedKey[4..]
        } else {
            &paddedKey[..]
        };
        if levels > maximumLevelCount as u64 || levels != publicKeyLevels {
            return false;
        }
        let mut rest = &signature[4..];
        for _ in 1..levels {
            // The signature of the public key of the next level, then that public key.
            let Some(kind) = Self::levelType(publicKey) else {
                return false;
            };
            let signatureLength = kind.signatureLength();
            if signatureLength > rest.len() {
                return false;
            }
            let (levelSignature, afterSignature) = rest.split_at(signatureLength);
            if afterSignature.len() < 4 || TreeType::ofCode(word(afterSignature, 0)).is_none() {
                return false;
            }
            if LevelType::publicKeyLength > afterSignature.len() {
                return false;
            }
            let (nextPublicKey, afterPublicKey) =
                afterSignature.split_at(LevelType::publicKeyLength);
            let messageHashOf = |identifier: &[u8; identifierLength]| {
                OneTimeSignature::messageHash(
                    identifier,
                    word(levelSignature, 0) as u32,
                    &levelSignature[8..8 + hashLength],
                    nextPublicKey,
                )
            };
            if !Self::isValidLMSSignature(publicKey, levelSignature, messageHashOf) {
                return false;
            }
            publicKey = nextPublicKey;
            rest = afterPublicKey;
        }
        // The bottom level signs the message.
        if OneTimeSignatureType::ofCode(word(publicKey, 4)).is_none() {
            return false;
        }
        // The prefix of the message hash takes q and C from the signature. A signature too
        // short for them fails the length checks of the LMS verification.
        if rest.len() < 8 + hashLength {
            return false;
        }
        let messageHashOf = |identifier: &[u8; identifierLength]| {
            OneTimeSignature::messageHash(
                identifier,
                word(rest, 0) as u32,
                &rest[8..8 + hashLength],
                message,
            )
        };
        Self::isValidLMSSignature(publicKey, rest, messageHashOf)
    }

    /// The level type of the first two words of an LMS public key, or `None` when either is
    /// not a known typecode.
    fn levelType(publicKey: &[u8]) -> Option<LevelType> {
        Some(LevelType::new(
            TreeType::ofCode(word(publicKey, 0))?,
            OneTimeSignatureType::ofCode(word(publicKey, 4))?,
        ))
    }

    /// True when an LMS signature is valid for an LMS public key, RFC 8554, Algorithm 6a, as
    /// `lm_validate_signature` decides it. The message hash comes from the identifier I of
    /// the key, as the C code computes it before the signature is parsed.
    fn isValidLMSSignature(
        publicKey: &[u8],
        signature: &[u8],
        messageHashOf: impl Fn(&[u8; identifierLength]) -> [u8; hashLength],
    ) -> bool {
        let Some(tree) = TreeType::ofCode(word(publicKey, 0)) else {
            return false;
        };
        if signature.len() < 8 {
            return false;
        }
        let Some(oneTimeSignatureType) = OneTimeSignatureType::ofCode(word(publicKey, 4)) else {
            return false;
        };
        let identifier: &[u8; identifierLength] = publicKey[8..8 + identifierLength]
            .try_into()
            .expect("16 bytes");
        let q = word(signature, 0);
        let rest = &signature[4..];
        let oneTimeLength = oneTimeSignatureType.signatureLength();
        if rest.len() < oneTimeLength {
            return false;
        }
        let (oneTimeSignature, afterOneTime) = rest.split_at(oneTimeLength);
        let messageHash = messageHashOf(identifier);
        let Some(candidate) = OneTimeSignature::new(oneTimeSignatureType).candidatePublicKey(
            identifier,
            q as u32,
            &messageHash,
            oneTimeSignature,
        ) else {
            return false;
        };
        let height = tree.height();
        if afterOneTime.len() < 4 || word(afterOneTime, 0) != u64::from(tree.code()) {
            return false;
        }
        let path = &afterOneTime[4..];
        if path.len() != hashLength * height as usize || q >= 1 << height {
            return false;
        }
        let mut nodeNumber = (1 << height) + q as u32;
        let mut node = MerkleTree::leafNodeOfKey(identifier, nodeNumber, &candidate);
        for sibling in path.chunks_exact(hashLength) {
            let sibling: &[u8; hashLength] = sibling.try_into().expect("32 bytes");
            let (left, right) = if nodeNumber % 2 == 1 {
                (sibling, &node)
            } else {
                (&node, sibling)
            };
            nodeNumber /= 2;
            node = MerkleTree::internalNodeOf(identifier, nodeNumber, left, right);
        }
        node[..] == publicKey[8 + identifierLength..8 + identifierLength + hashLength]
    }
}
