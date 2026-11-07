use OQSNativeSHA2::SHA256;
use std::collections::BTreeMap;

/// The snapshot of a liboqs version: one SHA-256 for each algorithm, over the values of its
/// base case.
///
/// The format is the format of the snapshots of the Swift and Zig ports: one line
/// `NAME digest` for each algorithm, in sorted order of the names. The digest is the SHA-256 of
/// the bytes of the fields of the base case, in sorted order of the field names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    digests: BTreeMap<String, String>,
}

impl Snapshot {
    /// Makes an empty snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads a snapshot from its text. Each line that is not `NAME digest` is an error.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut snapshot = Snapshot::new();
        for (index, line) in text.lines().enumerate() {
            let parts: Vec<&str> = line.split(' ').collect();
            let [name, digest] = parts[..] else {
                return Err(format!("line {} is not `NAME digest`", index + 1));
            };
            let isDigest = digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            if name.is_empty() || !isDigest {
                return Err(format!("line {} is not `NAME digest`", index + 1));
            }
            snapshot
                .digests
                .insert(name.to_string(), digest.to_string());
        }
        Ok(snapshot)
    }

    /// The digest of the fields of a base case. The fields must be in sorted order of their
    /// names.
    pub fn digest(fields: &[(&str, Vec<u8>)]) -> String {
        assert!(
            fields.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "the fields of a base case are in sorted order of their names"
        );
        let mut hash = SHA256::new();
        for (_, bytes) in fields {
            hash.absorb(bytes);
        }
        hash.finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Adds the digest of the base case of an algorithm.
    pub fn insert(&mut self, algorithm: &str, fields: &[(&str, Vec<u8>)]) {
        self.digests
            .insert(algorithm.to_string(), Self::digest(fields));
    }

    /// The digest of an algorithm.
    pub fn digestOf(&self, algorithm: &str) -> Option<&str> {
        self.digests.get(algorithm).map(String::as_str)
    }

    /// The algorithm names, in sorted order.
    pub fn names(&self) -> Vec<&str> {
        self.digests.keys().map(String::as_str).collect()
    }

    /// The text of the snapshot, with a line break after each line.
    pub fn text(&self) -> String {
        self.digests
            .iter()
            .map(|(name, digest)| format!("{name} {digest}\n"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Snapshot;

    #[test]
    fn digestIsTheSHA256OfTheFieldBytesInOrder() {
        // SHA-256 of "abc", from FIPS 180-4.
        assert_eq!(
            Snapshot::digest(&[("a", b"ab".to_vec()), ("b", b"c".to_vec())]),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    #[should_panic(expected = "sorted order")]
    fn fieldsOutOfOrderAreADefectOfTheCaller() {
        Snapshot::digest(&[("b", vec![]), ("a", vec![])]);
    }

    #[test]
    fn textListsTheAlgorithmsInSortedOrderAndParsesBack() {
        let mut snapshot = Snapshot::new();
        snapshot.insert("ML-KEM-768", &[("pk", vec![1])]);
        snapshot.insert("BIKE-L1", &[("pk", vec![2])]);
        let text = snapshot.text();
        assert!(text.starts_with("BIKE-L1 "));
        assert_eq!(text.lines().count(), 2);
        assert_eq!(Snapshot::parse(&text), Ok(snapshot.clone()));
        assert_eq!(snapshot.names(), vec!["BIKE-L1", "ML-KEM-768"]);
        assert_eq!(
            snapshot.digestOf("BIKE-L1"),
            Some(Snapshot::digest(&[("pk", vec![2])]).as_str())
        );
        assert_eq!(snapshot.digestOf("HQC-1"), None);
    }

    #[test]
    fn malformedLinesAreErrorsWithTheirLineNumber() {
        let digest = "a".repeat(64);
        assert!(Snapshot::parse(&format!("X {digest}\n")).is_ok());
        for line in [
            format!("X {digest} extra"),
            format!(" {digest}"),
            "X short".to_string(),
            format!("X {}", "A".repeat(64)),
            format!("X {}", "g".repeat(64)),
        ] {
            assert_eq!(
                Snapshot::parse(&format!("X {digest}\n{line}\n")),
                Err("line 2 is not `NAME digest`".to_string()),
                "{line}"
            );
        }
    }
}
