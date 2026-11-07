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

/// The big-endian 32-bit word at the start of a slice, and the bytes after it, or `None` when
/// the slice is shorter than 4 bytes.
fn leadingWord(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (first, rest) = bytes.split_first_chunk::<4>()?;
    Some((u64::from(u32::from_be_bytes(*first)), rest))
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
        // Every signature shorter than them fails a later length check, so it is not valid. The
        // checked splits below refuse each part that is too short, as the length checks of the
        // C code do.
        if signature.first_chunk::<12>().is_none() {
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
            let Some((levelSignature, afterSignature)) =
                rest.split_at_checked(kind.signatureLength())
            else {
                return false;
            };
            // The C code reads the tree typecode of the next public key before its length.
            let Some((nextTreeCode, _)) = leadingWord(afterSignature) else {
                return false;
            };
            if TreeType::ofCode(nextTreeCode).is_none() {
                return false;
            }
            let Some((nextPublicKey, afterPublicKey)) =
                afterSignature.split_at_checked(LevelType::publicKeyLength)
            else {
                return false;
            };
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
        // The prefix of the message hash takes q and C from the signature. The LMS verification
        // computes the hash only after the length check of the one-time signature, which a
        // signature too short for them fails.
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
        // The C code refuses a signature shorter than 8 bytes here. One of 4 to 7 bytes fails
        // the length check of the one-time signature instead, with the same verdict.
        let Some((q, rest)) = leadingWord(signature) else {
            return false;
        };
        let Some(oneTimeSignatureType) = OneTimeSignatureType::ofCode(word(publicKey, 4)) else {
            return false;
        };
        let identifier: &[u8; identifierLength] = publicKey[8..8 + identifierLength]
            .try_into()
            .expect("16 bytes");
        let Some((oneTimeSignature, afterOneTime)) =
            rest.split_at_checked(oneTimeSignatureType.signatureLength())
        else {
            return false;
        };
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
        let Some((treeCode, path)) = leadingWord(afterOneTime) else {
            return false;
        };
        if treeCode != u64::from(tree.code()) {
            return false;
        }
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

#[cfg(test)]
mod tests {
    use super::SignatureVerification;
    use crate::parameters::{Parameters, lmsSHA256H5W4, lmsSHA256H25W1};
    use crate::testInputs::sequenceBytes;
    use crate::{LMSWorkingKey, LevelType, MerkleTree, OneTimeSignatureType, PrivateKey};
    use crate::{TreeState, TreeType};
    use OQSNativeAlgorithmTests::OutputDigest;
    use OQSNativeEntities::StatefulSignatureDescription;

    // The known answers come from a C program that made each key with
    // `OQS_LMS_NAMESPACE_hss_generate_private_key` from the seed and the identifier below, signed
    // with `OQS_LMS_NAMESPACE_hss_generate_signature`, and gave each signature, each prefix of
    // it and each public key to `OQS_SIG_STFL_verify` of `LMS_SHA256_H5_W4`.

    const message: &[u8] = b"the quick brown fox";

    /// The level of every key of the tests: a tree of height 5 with the Winternitz parameter 4.
    const level: LevelType = LevelType::new(TreeType::height5, OneTimeSignatureType::winternitz4);

    /// A scheme whose signature has room for eight levels, the most that hash-sigs reads. No set
    /// of liboqs has that room, so liboqs cannot sign such a key, but it verifies its
    /// signatures.
    static eightLevels: Parameters = Parameters {
        levels: &[level; 8],
        description: StatefulSignatureDescription {
            signatureLength: 19180,
            ..lmsSHA256H25W1.description
        },
    };

    /// The HSS public key and the first signature of the message by the key of a number of
    /// levels whose seed and identifier are the sequences of the seeds 21 and 22, signed under
    /// a scheme with room for its signature.
    fn publicKeyAndSignature(levelCount: usize, scheme: &'static Parameters) -> (Vec<u8>, Vec<u8>) {
        let seed: [u8; 32] = sequenceBytes(32, 21).try_into().expect("32 bytes");
        let identifier: [u8; 16] = sequenceBytes(16, 22).try_into().expect("16 bytes");
        let levels = vec![level; levelCount];
        let privateKey = PrivateKey::new(&levels, &seed, &identifier);
        let tree = MerkleTree::new(level, identifier, seed);
        let state = TreeState::computed(tree.clone(), 0, 5);
        let mut publicKey = (levelCount as u32).to_be_bytes().to_vec();
        publicKey.extend_from_slice(&tree.publicKey(state.root()));
        let workingKey = LMSWorkingKey::load(scheme, &privateKey.bytes).expect("a working key");
        let (signature, _) = workingKey.signatureOnce(message).expect("a signature");
        (publicKey, signature)
    }

    /// The lengths of the prefixes of a signature that end just before, at and just after each
    /// edge of its fields, and every length up to 13, below the length of the signature.
    fn prefixLengths(edges: &[usize], signatureLength: usize) -> Vec<usize> {
        let mut lengths: Vec<usize> = (0..=13).collect();
        for edge in edges {
            lengths.extend(edge - 3..=edge + 1);
        }
        lengths.retain(|length| *length < signatureLength);
        lengths
    }

    #[test]
    fn eachPrefixOfASignatureIsRefusedAsTheCLibraryRefusesIt() {
        // One level: the level count, then q, the one-time signature of 2180 bytes, the tree
        // typecode and the path of 160 bytes. The C library refused each of the 2352 prefixes.
        let (publicKey, signature) = publicKeyAndSignature(1, &lmsSHA256H5W4);
        assert_eq!(
            OutputDigest::of(&publicKey),
            "1cbf4e38c12b0f68a49e0e02c72811c625c78dc8a651b17d21a30682d0643030"
        );
        assert_eq!(
            OutputDigest::of(&signature),
            "07c67fd5939f0817037481f6ae8f64645bdb53c7134649cf1c310576cac62da0"
        );
        assert!(SignatureVerification::isValid(
            &signature, message, &publicKey
        ));
        for length in prefixLengths(&[4, 12, 44, 2188, 2192, 2352], signature.len()) {
            assert!(
                !SignatureVerification::isValid(&signature[..length], message, &publicKey),
                "one level, {length} bytes"
            );
        }
        // Two levels: the level count, the LMS signature of 2348 bytes of the public key of the
        // bottom tree, that public key of 56 bytes, and the LMS signature of the message. The
        // C library refused each of the 4756 prefixes.
        let (publicKey, signature) = publicKeyAndSignature(2, &lmsSHA256H25W1);
        assert_eq!(
            OutputDigest::of(&publicKey),
            "8f6ba2c997cbd61ab8d2dcbd82256610469578ceaa57c5686522cc35a38ed388"
        );
        assert_eq!(
            OutputDigest::of(&signature),
            "97c71082bcfffa90b782c08e9f9183f1d45b6378993f54003034edbbe754df40"
        );
        assert!(SignatureVerification::isValid(
            &signature, message, &publicKey
        ));
        for length in prefixLengths(
            &[4, 12, 2352, 2356, 2408, 2448, 2592, 2596, 4756],
            signature.len(),
        ) {
            assert!(
                !SignatureVerification::isValid(&signature[..length], message, &publicKey),
                "two levels, {length} bytes"
            );
        }
    }

    #[test]
    fn aRawLMSPublicKeyVerifiesASignatureOfOneLevelOnlyAsTheCLibraryDecides() {
        // The raw LMS public key is the HSS public key without its level count. The C library
        // accepted the signature of one level and refused the signature of two levels under it.
        let (publicKey, signature) = publicKeyAndSignature(1, &lmsSHA256H5W4);
        assert!(SignatureVerification::isValid(
            &signature,
            message,
            &publicKey[4..]
        ));
        let (publicKey, signature) = publicKeyAndSignature(2, &lmsSHA256H25W1);
        assert!(SignatureVerification::isValid(
            &signature, message, &publicKey
        ));
        assert!(!SignatureVerification::isValid(
            &signature,
            message,
            &publicKey[4..]
        ));
    }

    #[test]
    fn aSignatureOfEightLevelsIsValidAsTheCLibraryAcceptsIt() {
        let (publicKey, signature) = publicKeyAndSignature(8, &eightLevels);
        assert_eq!(
            OutputDigest::of(&publicKey),
            "fe6a7733d75573bf67e8fc688c27e3c1641fd2e16a3a810d98cf685727ec9d05"
        );
        assert_eq!(signature.len(), 19180);
        assert_eq!(
            OutputDigest::of(&signature),
            "6ff7a97c210d07f41ae95243c153a22259d97fbcc0870e35033834590aff7eb3"
        );
        assert!(SignatureVerification::isValid(
            &signature, message, &publicKey
        ));
        // The C library accepted the signature, and refused it under the public key that
        // claims seven levels.
        let mut sevenLevels = publicKey.clone();
        sevenLevels[3] = 7;
        assert!(!SignatureVerification::isValid(
            &signature,
            message,
            &sevenLevels
        ));
    }
}
