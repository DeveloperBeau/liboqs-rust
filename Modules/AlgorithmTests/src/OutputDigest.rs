use OQSNativeSHA3::SHAKE128;
use alloc::string::String;

/// The digest that the C programs of the known answers of the unit tests print: 32 bytes of
/// SHAKE128 of an output, in lower-case hexadecimal.
pub struct OutputDigest;

impl OutputDigest {
    /// The digest of the bytes of an output.
    pub fn of(bytes: &[u8]) -> String {
        let mut output = [0u8; 32];
        SHAKE128::hash(bytes, &mut output);
        output
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::OutputDigest;

    #[test]
    fn digestIsTheFirst32BytesOfSHAKE128InLowerCaseHexadecimal() {
        // The values of Python hashlib.shake_128(...).hexdigest(32).
        assert_eq!(
            OutputDigest::of(b""),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        assert_eq!(
            OutputDigest::of(b"abc"),
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        );
    }
}
