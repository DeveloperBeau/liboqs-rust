use OQSNativeEntities::OQSError;

/// The rule that an input of an algorithm has the exact length that the algorithm needs.
pub struct InputLength;

impl InputLength {
    /// Returns the input when its length is the expected length, and else the length error.
    pub fn checked(input: &[u8], expected: usize) -> Result<&[u8], OQSError> {
        if input.len() == expected {
            Ok(input)
        } else {
            Err(OQSError::invalidLength {
                expected,
                actual: input.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InputLength;
    use OQSNativeEntities::OQSError;

    #[test]
    fn checkedReturnsAnInputOfTheExpectedLength() {
        assert_eq!(InputLength::checked(&[1, 2, 3], 3), Ok(&[1u8, 2, 3][..]));
        assert_eq!(InputLength::checked(&[], 0), Ok(&[][..]));
    }

    #[test]
    fn checkedRejectsAShorterAndALongerInputWithBothLengths() {
        assert_eq!(
            InputLength::checked(&[1, 2], 3),
            Err(OQSError::invalidLength {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            InputLength::checked(&[1, 2, 3, 4], 3),
            Err(OQSError::invalidLength {
                expected: 3,
                actual: 4
            })
        );
    }
}
