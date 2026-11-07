use std::fmt;

/// The first difference between a Rust algorithm and the C algorithm of the same name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityMismatch {
    /// The liboqs name of the algorithm.
    pub algorithm: String,
    /// The variation, or `None` for the base case.
    pub case: Option<u64>,
    /// The seed of the run.
    pub seed: u64,
    /// The step that differs, such as `public key`.
    pub step: &'static str,
    /// What differs.
    pub detail: String,
}

impl ParityMismatch {
    /// Describes the first difference of two byte strings, or returns `None` when they are equal.
    pub fn difference(cBytes: &[u8], rustBytes: &[u8]) -> Option<String> {
        if cBytes.len() != rustBytes.len() {
            return Some(format!(
                "C gives {} bytes and Rust gives {}",
                cBytes.len(),
                rustBytes.len()
            ));
        }
        let index = cBytes
            .iter()
            .zip(rustBytes)
            .position(|(cByte, rustByte)| cByte != rustByte)?;
        Some(format!(
            "the bytes differ first at offset {index} of {}: C {:02x}, Rust {:02x}",
            cBytes.len(),
            cBytes[index],
            rustBytes[index]
        ))
    }
}

impl fmt::Display for ParityMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.case {
            Some(case) => write!(
                formatter,
                "{}, case {case} of seed {:#x}: {}: {}",
                self.algorithm, self.seed, self.step, self.detail
            ),
            None => write!(
                formatter,
                "{}, base case: {}: {}",
                self.algorithm, self.step, self.detail
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ParityMismatch;

    #[test]
    fn differenceNamesTheFirstDifferentByteOrTheLengths() {
        assert_eq!(ParityMismatch::difference(&[1, 2, 3], &[1, 2, 3]), None);
        assert_eq!(
            ParityMismatch::difference(&[1, 2, 3], &[1, 9, 4]),
            Some("the bytes differ first at offset 1 of 3: C 02, Rust 09".to_string())
        );
        assert_eq!(
            ParityMismatch::difference(&[1, 2], &[1, 2, 3]),
            Some("C gives 2 bytes and Rust gives 3".to_string())
        );
    }

    #[test]
    fn displayNamesTheAlgorithmTheCaseTheSeedAndTheStep() {
        let mismatch = ParityMismatch {
            algorithm: "ML-KEM-768".to_string(),
            case: Some(17),
            seed: 255,
            step: "ciphertext",
            detail: "x".to_string(),
        };
        assert_eq!(
            mismatch.to_string(),
            "ML-KEM-768, case 17 of seed 0xff: ciphertext: x"
        );
        let baseCase = ParityMismatch {
            case: None,
            ..mismatch
        };
        assert_eq!(baseCase.to_string(), "ML-KEM-768, base case: ciphertext: x");
    }
}
