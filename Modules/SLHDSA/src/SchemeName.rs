use crate::{Parameters, PreHash};

/// The liboqs name of one scheme of the family, which the compiler builds from the name of the
/// parameter set and the name of the pre-hash function.
pub(crate) struct SchemeName {
    bytes: [u8; SchemeName::maximumLength],
    length: usize,
}

impl SchemeName {
    /// The length of the longest name, `SLH_DSA_SHA2_512_224_PREHASH_SHAKE_256F`.
    pub(crate) const maximumLength: usize = 39;

    /// The name `SLH_DSA_PURE_<set>` of a pure form, or `SLH_DSA_<function>_PREHASH_<set>` of
    /// a pre-hash form, as the liboqs templates make the names.
    pub(crate) const fn new(parameters: &Parameters, preHash: Option<PreHash>) -> Self {
        let name = SchemeName {
            bytes: [0; Self::maximumLength],
            length: 0,
        }
        .appending("SLH_DSA_");
        let name = match preHash {
            None => name.appending("PURE_"),
            Some(preHash) => name.appending(preHash.liboqsName()).appending("_PREHASH_"),
        };
        name.appending(parameters.liboqsName)
    }

    /// The name with a text after it.
    const fn appending(mut self, text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            self.bytes[self.length] = bytes[index];
            self.length += 1;
            index += 1;
        }
        self
    }

    /// The name as text.
    pub(crate) const fn text(&'static self) -> &'static str {
        match core::str::from_utf8(self.bytes.split_at(self.length).0) {
            Ok(text) => text,
            Err(_) => panic!("a scheme name is ASCII text"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SchemeName;
    use crate::{PreHash, parameterSets};

    static pure: SchemeName = SchemeName::new(&parameterSets[0], None);
    static longest: SchemeName = SchemeName::new(&parameterSets[11], Some(PreHash::sha512224));
    static shakePreHash: SchemeName = SchemeName::new(&parameterSets[5], Some(PreHash::shake128));

    #[test]
    fn namesAreTheNamesOfTheLiboqsTemplates() {
        assert_eq!(pure.text(), "SLH_DSA_PURE_SHA2_128S");
        assert_eq!(longest.text(), "SLH_DSA_SHA2_512_224_PREHASH_SHAKE_256F");
        assert_eq!(longest.text().len(), SchemeName::maximumLength);
        assert_eq!(shakePreHash.text(), "SLH_DSA_SHAKE_128_PREHASH_SHA2_256F");
    }
}
