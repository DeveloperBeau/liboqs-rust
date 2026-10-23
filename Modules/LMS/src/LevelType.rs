use crate::OneTimeSignatureType;
use crate::TreeType;
use crate::parameters::hashLength;

/// The parameter sets of one level of an HSS key: the type of its trees and the type of their
/// one-time signatures, the `lm_type` and `lm_ots_type` of hash-sigs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LevelType {
    /// The type of the trees of the level.
    pub(crate) tree: TreeType,
    /// The type of the one-time signatures of the trees of the level.
    pub(crate) oneTimeSignature: OneTimeSignatureType,
}

impl LevelType {
    /// The length of an LMS public key, `lm_get_public_key_len`: the two typecodes, the
    /// identifier I and the root.
    pub(crate) const publicKeyLength: usize = 8 + 16 + hashLength;

    /// Makes the type of a level.
    pub(crate) const fn new(tree: TreeType, oneTimeSignature: OneTimeSignatureType) -> Self {
        LevelType {
            tree,
            oneTimeSignature,
        }
    }

    /// The length of an LMS signature of a tree of the level, `lm_get_signature_len`: the leaf
    /// index, the one-time signature, the tree typecode and the authentication path.
    pub(crate) const fn signatureLength(self) -> usize {
        4 + self.oneTimeSignature.signatureLength() + 4 + hashLength * self.tree.height() as usize
    }

    /// The byte of the level in the parameter set of a private key, as
    /// `hss_compress_param_set` writes it: the tree typecode in the high half and the one-time
    /// signature typecode in the low half.
    pub(crate) const fn compressedCode(self) -> u8 {
        // Both typecodes are below 16, so the halves are disjoint.
        ((self.tree.code() << 4) + self.oneTimeSignature.code()) as u8
    }

    /// The type of a level from its byte in a private key, as `hss_get_parameter_set` reads
    /// it, or `None` when either half is not a known typecode.
    pub(crate) const fn ofCompressedCode(code: u8) -> Option<LevelType> {
        let (Some(tree), Some(oneTimeSignature)) = (
            TreeType::ofCode((code >> 4) as u64),
            OneTimeSignatureType::ofCode((code & 0x0F) as u64),
        ) else {
            return None;
        };
        Some(LevelType::new(tree, oneTimeSignature))
    }
}

#[cfg(test)]
mod tests {
    use super::LevelType;
    use crate::{OneTimeSignatureType, TreeType};

    #[test]
    fn signatureLengthsAreTheLengthsOfHashSigs() {
        // The LMS signature lengths of RFC 8554, Section 5.4, and `lm_get_signature_len`.
        let expected = [
            (TreeType::height5, OneTimeSignatureType::winternitz1, 8684),
            (TreeType::height10, OneTimeSignatureType::winternitz2, 4620),
            (TreeType::height15, OneTimeSignatureType::winternitz4, 2668),
            (TreeType::height20, OneTimeSignatureType::winternitz8, 1772),
            (TreeType::height25, OneTimeSignatureType::winternitz8, 1932),
        ];
        for (tree, oneTimeSignature, length) in expected {
            assert_eq!(
                LevelType::new(tree, oneTimeSignature).signatureLength(),
                length,
                "{tree:?}, {oneTimeSignature:?}"
            );
        }
        assert_eq!(LevelType::publicKeyLength, 56);
    }

    #[test]
    fn compressedCodesHoldBothTypecodes() {
        let level = LevelType::new(TreeType::height10, OneTimeSignatureType::winternitz4);
        assert_eq!(level.compressedCode(), 0x63);
        assert_eq!(LevelType::ofCompressedCode(0x63), Some(level));
        assert_eq!(
            LevelType::ofCompressedCode(0x94),
            Some(LevelType::new(
                TreeType::height25,
                OneTimeSignatureType::winternitz8
            ))
        );
        // A known tree typecode with an unknown one-time typecode, and the other way around.
        for code in [0x50, 0x55, 0x4F, 0xA1, 0x01, 0xFF, 0x00] {
            assert_eq!(LevelType::ofCompressedCode(code), None, "{code:#x}");
        }
    }
}
