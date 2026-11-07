use crate::LevelType;
use crate::parameters::{maximumLevelCount, parameterSetLength};

/// The parameter set of an HSS key: the types of its levels, the top level first.
///
/// liboqs names sets of one and two levels, and hash-sigs reads keys of up to eight levels.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ParameterSet<'levels> {
    /// The types of the levels, the top level first.
    pub(crate) levels: &'levels [LevelType],
}

impl<'levels> ParameterSet<'levels> {
    /// The parameter set of one to eight levels.
    pub(crate) const fn new(levels: &'levels [LevelType]) -> Self {
        assert!(!levels.is_empty() && levels.len() <= maximumLevelCount);
        ParameterSet { levels }
    }

    /// The length of an HSS signature, `hss_get_signature_len`: the count of signed public
    /// keys, an LMS signature and a public key for each level below the top, and the LMS
    /// signature of the message.
    pub(crate) const fn signatureLength(self) -> usize {
        let mut length = 4;
        let mut index = 0;
        while index < self.levels.len() {
            length += self.levels[index].signatureLength();
            if index > 0 {
                length += LevelType::publicKeyLength;
            }
            index += 1;
        }
        length
    }

    /// The sum of the heights of the trees of the levels.
    pub(crate) const fn totalHeight(self) -> u32 {
        let mut height = 0;
        let mut index = 0;
        while index < self.levels.len() {
            height += self.levels[index].tree.height();
            index += 1;
        }
        height
    }

    /// The highest count of a private key, `max_count` of `allocate_working_key`: the number of
    /// signatures less one, with the count `2^64 - 1` kept free as the mark of a used-up key.
    ///
    /// liboqs reports this value as the total number of signatures of a key.
    pub(crate) const fn maximumCount(self) -> u64 {
        let height = self.totalHeight();
        if height >= 64 {
            u64::MAX - 1
        } else {
            (1 << height) - 1
        }
    }

    /// The parameter set as the 8 bytes of a private key, `hss_compress_param_set`: one byte
    /// for each level, then the end mark `0xFF`.
    pub(crate) const fn compressed(self) -> [u8; parameterSetLength] {
        let mut bytes = [0xFF; parameterSetLength];
        let mut index = 0;
        while index < self.levels.len() {
            bytes[index] = self.levels[index].compressedCode();
            index += 1;
        }
        bytes
    }

    /// The object identifier that `sig_stfl_lms.h` gives the set: the level count, then the
    /// compressed byte of each level, the top level first.
    pub(crate) const fn objectIdentifier(self) -> u32 {
        let mut identifier = self.levels.len() as u32;
        let mut index = 0;
        while index < self.levels.len() {
            identifier = (identifier << 8) + self.levels[index].compressedCode() as u32;
            index += 1;
        }
        identifier
    }
}

#[cfg(test)]
mod tests {
    use super::ParameterSet;
    use crate::{LevelType, OneTimeSignatureType, TreeType};

    fn level(tree: TreeType, oneTimeSignature: OneTimeSignatureType) -> LevelType {
        LevelType::new(tree, oneTimeSignature)
    }

    #[test]
    fn signatureLengthsOfTwoLevelsAreTheLengthsOfLiboqs() {
        // `sig_stfl_lms.h` of liboqs.
        let h5w8 = level(TreeType::height5, OneTimeSignatureType::winternitz8);
        let h10w4 = level(TreeType::height10, OneTimeSignatureType::winternitz4);
        let h10w8 = level(TreeType::height10, OneTimeSignatureType::winternitz8);
        assert_eq!(ParameterSet::new(&[h5w8, h5w8]).signatureLength(), 2644);
        assert_eq!(ParameterSet::new(&[h10w4, h5w8]).signatureLength(), 3860);
        assert_eq!(ParameterSet::new(&[h10w8, h5w8]).signatureLength(), 2804);
        assert_eq!(ParameterSet::new(&[h5w8]).signatureLength(), 1296);
    }

    #[test]
    fn maximumCountsCountFromTheHighestSequenceNumber() {
        let h5 = level(TreeType::height5, OneTimeSignatureType::winternitz8);
        let h25 = level(TreeType::height25, OneTimeSignatureType::winternitz1);
        assert_eq!(ParameterSet::new(&[h5]).maximumCount(), 31);
        assert_eq!(ParameterSet::new(&[h5, h5]).maximumCount(), 1023);
        assert_eq!(ParameterSet::new(&[h25, h25]).maximumCount(), (1 << 50) - 1);
        // A height of 64 or more keeps the count 2^64 - 1 as the mark of a used-up key.
        let h20 = level(TreeType::height20, OneTimeSignatureType::winternitz1);
        let sixtyFour = [
            h20,
            h20,
            h20,
            level(TreeType::height5, OneTimeSignatureType::winternitz1),
        ];
        assert_eq!(ParameterSet::new(&sixtyFour).totalHeight(), 65);
        assert_eq!(ParameterSet::new(&sixtyFour).maximumCount(), u64::MAX - 1);
        assert_eq!(
            ParameterSet::new(&[h20, h20, h20]).maximumCount(),
            (1 << 60) - 1
        );
    }

    #[test]
    fn compressedSetsAndIdentifiersFollowTheLayoutOfHashSigsAndLiboqs() {
        let h10w4 = level(TreeType::height10, OneTimeSignatureType::winternitz4);
        let h5w8 = level(TreeType::height5, OneTimeSignatureType::winternitz8);
        let levels = [h10w4, h5w8];
        let set = ParameterSet::new(&levels);
        assert_eq!(
            set.compressed(),
            [0x63, 0x54, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        // `OQS_LMS_ID_sha256_h10_w4_h5_w8` and `OQS_LMS_ID_sha256_h5_w1` of `sig_stfl_lms.h`.
        assert_eq!(set.objectIdentifier(), 0x02_6354);
        let h5w1 = level(TreeType::height5, OneTimeSignatureType::winternitz1);
        assert_eq!(ParameterSet::new(&[h5w1]).objectIdentifier(), 0x0151);
        assert_eq!(ParameterSet::new(&[h5w1; 8]).compressed(), [0x51; 8]);
    }
}
