use alloc::vec::Vec;

/// The digests of the known-answer programs of the C library, from a copy of a liboqs
/// `kats.json` file.
///
/// Each entry holds the SHA-256 of the `single` run, which prints count 0, and of the `all`
/// run, which prints every count. The files keep the layout of liboqs, so a new release copies
/// over them unchanged.
pub struct KnownAnswerDigests {
    json: &'static str,
}

impl KnownAnswerDigests {
    /// The digests of `kat_kem`, from `tests/KATs/kem/kats.json`.
    pub fn kem() -> Self {
        KnownAnswerDigests {
            json: include_str!("../Data/KEMKnownAnswers.json"),
        }
    }

    /// The digests of `kat_sig`, from `tests/KATs/sig/kats.json`.
    pub fn signature() -> Self {
        KnownAnswerDigests {
            json: include_str!("../Data/SignatureKnownAnswers.json"),
        }
    }

    /// The algorithm names of the file, in file order.
    pub fn names(&self) -> Vec<&'static str> {
        self.json
            .lines()
            .filter_map(|line| entryName(line.trim()))
            .collect()
    }

    /// The digest of the run of count 0 of an algorithm.
    pub fn singleDigest(&self, algorithm: &str) -> Option<&'static str> {
        self.field(algorithm, "single")
    }

    /// The digest of the run of every count of an algorithm.
    pub fn allDigest(&self, algorithm: &str) -> Option<&'static str> {
        self.field(algorithm, "all")
    }

    fn field(&self, algorithm: &str, key: &str) -> Option<&'static str> {
        let mut entry: Option<&str> = None;
        for line in self.json.lines() {
            let trimmed = line.trim().trim_end_matches(',');
            if let Some(name) = entryName(trimmed) {
                entry = Some(name);
            } else if trimmed.starts_with('}') {
                entry = None;
            } else if entry == Some(algorithm) {
                let Some((fieldKey, value)) = trimmed.split_once(": ") else {
                    continue;
                };
                if quoted(fieldKey) == Some(key) {
                    return quoted(value);
                }
            }
        }
        None
    }
}

/// The name of an entry from its opening line, `"Name": {`.
fn entryName(trimmedLine: &'static str) -> Option<&'static str> {
    quoted(trimmedLine.strip_suffix(": {")?)
}

/// The text between the double quotes of a JSON string without escapes.
fn quoted(text: &'static str) -> Option<&'static str> {
    text.strip_prefix('"')?.strip_suffix('"')
}

#[cfg(test)]
mod tests {
    use super::KnownAnswerDigests;

    #[test]
    fn digestsComeFromTheEntryOfTheName() {
        let digests = KnownAnswerDigests::kem();
        assert_eq!(
            digests.singleDigest("BIKE-L1"),
            Some("404a5504e7a13f18fa55a28fe6707329892f6e50201e6e965d9b724158026a34")
        );
        assert_eq!(
            digests.allDigest("BIKE-L1"),
            Some("c1021bcf36875170f5102b3d3e31282ef2176c9306d4992ffd43bb1b09de48d1")
        );
        assert_eq!(
            KnownAnswerDigests::signature().singleDigest("Falcon-512"),
            Some("da27fe8a462de7307ddf1f9b00072a457d9c5b14e838c148fbe2662094b9a2ca")
        );
    }

    #[test]
    fn unknownNamesAndKeysHaveNoDigest() {
        let digests = KnownAnswerDigests::kem();
        assert_eq!(digests.singleDigest("BIKE"), None);
        assert_eq!(digests.singleDigest("all"), None);
        assert_eq!(digests.field("BIKE-L1", "other"), None);
    }

    #[test]
    fn namesListEveryEntryOnce() {
        let kemNames = KnownAnswerDigests::kem().names();
        assert_eq!(kemNames.len(), 41);
        assert_eq!(kemNames.first(), Some(&"BIKE-L1"));
        assert!(kemNames.contains(&"sntrup761"));
        let signatureNames = KnownAnswerDigests::signature().names();
        assert_eq!(signatureNames.len(), 65);
        for name in signatureNames {
            assert!(
                KnownAnswerDigests::signature().singleDigest(name).is_some(),
                "{name}"
            );
        }
    }
}
