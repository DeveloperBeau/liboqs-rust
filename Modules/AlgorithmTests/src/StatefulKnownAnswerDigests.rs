use alloc::vec::Vec;

/// The digests of the known-answer program of liboqs for stateful schemes,
/// `tests/kat_sig_stfl.c`, from a copy of the liboqs file `tests/KATs/sig_stfl/kats.json`.
///
/// Each entry holds the SHA-256 of what the program prints for the response file of the
/// scheme. The file keeps the layout of liboqs, so a new release copies over it unchanged.
pub struct StatefulKnownAnswerDigests;

impl StatefulKnownAnswerDigests {
    const json: &'static str = include_str!("../Data/StatefulSignatureKnownAnswers.json");

    /// The algorithm names of the file, in file order.
    pub fn names() -> Vec<&'static str> {
        Self::entries().map(|(name, _)| name).collect()
    }

    /// The digest of an algorithm, or `None` when the file has no entry for it.
    pub fn digest(algorithm: &str) -> Option<&'static str> {
        Self::entries()
            .find(|(name, _)| *name == algorithm)
            .map(|(_, digest)| digest)
    }

    /// The entries `"Name": "digest"` of the file.
    fn entries() -> impl Iterator<Item = (&'static str, &'static str)> {
        Self::json.lines().filter_map(|line| {
            let (name, digest) = line.trim().trim_end_matches(',').split_once(": ")?;
            Some((quoted(name)?, quoted(digest)?))
        })
    }
}

/// The text between the double quotes of a JSON string without escapes.
fn quoted(text: &'static str) -> Option<&'static str> {
    text.strip_prefix('"')?.strip_suffix('"')
}

#[cfg(test)]
mod tests {
    use super::StatefulKnownAnswerDigests;

    #[test]
    fn theCopyHoldsAnEntryForEachSchemeWithAResponseFile() {
        let names = StatefulKnownAnswerDigests::names();
        assert_eq!(names.len(), 55);
        assert_eq!(names[0], "XMSS-SHA2_10_256");
        assert_eq!(names[54], "LMS_SHA256_H10_W4_H5_W8");
        assert_eq!(
            StatefulKnownAnswerDigests::digest("XMSS-SHA2_10_256"),
            Some("7acc06cc456a087456f937d07c7acae2ffeee517cf71b1693adc916f638df388")
        );
        assert_eq!(
            StatefulKnownAnswerDigests::digest("LMS_SHA256_H10_W4_H5_W8"),
            Some("f51cd27e5a35f63586796a39f00d6729f5148fb6d454e61737fbdeebbde3aed8")
        );
        assert_eq!(
            StatefulKnownAnswerDigests::digest("LMS_SHA256_H25_W8"),
            None
        );
    }
}
