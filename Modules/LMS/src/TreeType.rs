/// The LMS parameter set of one tree, RFC 8554, Section 5.1, with SHA-256 and n = 32: the
/// height of the tree and its typecode.
///
/// The cases are the five tree types of `lm_look_up_parameter_set` of hash-sigs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TreeType {
    /// `LMS_SHA256_M32_H5`, typecode 5.
    height5,
    /// `LMS_SHA256_M32_H10`, typecode 6.
    height10,
    /// `LMS_SHA256_M32_H15`, typecode 7.
    height15,
    /// `LMS_SHA256_M32_H20`, typecode 8.
    height20,
    /// `LMS_SHA256_M32_H25`, typecode 9.
    height25,
}

impl TreeType {
    /// The tree type of a typecode, or `None` for a typecode that hash-sigs does not know.
    pub(crate) const fn ofCode(code: u64) -> Option<TreeType> {
        match code {
            5 => Some(TreeType::height5),
            6 => Some(TreeType::height10),
            7 => Some(TreeType::height15),
            8 => Some(TreeType::height20),
            9 => Some(TreeType::height25),
            _ => None,
        }
    }

    /// The typecode of RFC 8554, Section 5.1.
    pub(crate) const fn code(self) -> u32 {
        match self {
            TreeType::height5 => 5,
            TreeType::height10 => 6,
            TreeType::height15 => 7,
            TreeType::height20 => 8,
            TreeType::height25 => 9,
        }
    }

    /// The height h of the tree, which has `2^h` leaves.
    pub(crate) const fn height(self) -> u32 {
        match self {
            TreeType::height5 => 5,
            TreeType::height10 => 10,
            TreeType::height15 => 15,
            TreeType::height20 => 20,
            TreeType::height25 => 25,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TreeType;

    #[test]
    fn eachTypecodeIsTheTypecodeOfRFC8554AndHashSigs() {
        // RFC 8554, Section 8.1, and `common_defs.h` of hash-sigs.
        let expected = [
            (TreeType::height5, 5, 5),
            (TreeType::height10, 6, 10),
            (TreeType::height15, 7, 15),
            (TreeType::height20, 8, 20),
            (TreeType::height25, 9, 25),
        ];
        for (tree, code, height) in expected {
            assert_eq!(tree.code(), code, "{tree:?}");
            assert_eq!(tree.height(), height, "{tree:?}");
            assert_eq!(TreeType::ofCode(u64::from(code)), Some(tree), "{tree:?}");
        }
    }

    #[test]
    fn everyOtherTypecodeIsUnknown() {
        for code in [0, 1, 4, 10, 0x0E, 0xFF, 0x1_0000_0005] {
            assert_eq!(TreeType::ofCode(code), None, "{code}");
        }
    }
}
