use core::fmt;

/// A failure of an operation of the library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OQSError {
    /// An input has the wrong length for the algorithm.
    invalidLength {
        /// The length that the algorithm needs.
        expected: usize,
        /// The length of the input.
        actual: usize,
    },
    /// A context string was given to an algorithm that signs without one.
    contextNotSupported,
    /// The context string is longer than the algorithm allows.
    contextTooLong,
    /// The algorithm has no form of the operation that takes a seed.
    seedNotSupported,
    /// The operation failed inside the algorithm, where liboqs returns `OQS_ERROR`.
    operationFailed,
    /// A stateful secret key has no signature left.
    keyExhausted,
    /// The advanced state of a stateful secret key was not saved, so no signature was released.
    persistenceFailed,
}

impl fmt::Display for OQSError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OQSError::invalidLength { expected, actual } => {
                write!(
                    formatter,
                    "the input has {actual} bytes, but the algorithm needs {expected}"
                )
            }
            OQSError::contextNotSupported => {
                formatter.write_str("the algorithm does not take a context string")
            }
            OQSError::contextTooLong => formatter.write_str("the context string is too long"),
            OQSError::seedNotSupported => {
                formatter.write_str("the algorithm has no form of the operation that takes a seed")
            }
            OQSError::operationFailed => formatter.write_str("the operation failed"),
            OQSError::keyExhausted => formatter.write_str("the secret key has no signature left"),
            OQSError::persistenceFailed => {
                formatter.write_str("the advanced secret key was not saved")
            }
        }
    }
}

impl core::error::Error for OQSError {}

#[cfg(test)]
mod tests {
    use super::OQSError;

    #[test]
    fn displayNamesTheProblemOfEachCase() {
        let cases = [
            (
                OQSError::invalidLength {
                    expected: 32,
                    actual: 31,
                },
                "the input has 31 bytes, but the algorithm needs 32",
            ),
            (
                OQSError::contextNotSupported,
                "the algorithm does not take a context string",
            ),
            (OQSError::contextTooLong, "the context string is too long"),
            (
                OQSError::seedNotSupported,
                "the algorithm has no form of the operation that takes a seed",
            ),
            (OQSError::operationFailed, "the operation failed"),
            (
                OQSError::keyExhausted,
                "the secret key has no signature left",
            ),
            (
                OQSError::persistenceFailed,
                "the advanced secret key was not saved",
            ),
        ];
        for (error, text) in cases {
            assert_eq!(error.to_string(), text);
        }
    }
}
