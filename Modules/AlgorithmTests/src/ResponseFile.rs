use alloc::vec;
use alloc::vec::Vec;

/// A liboqs response file of a stateful scheme, read as `FindMarker` and `ReadHex` of
/// `tests/kat_sig_stfl.c` read it.
///
/// A value starts after the first match of its marker, such as `pk = `. The reader skips the
/// characters before the first hexadecimal digit of the line, such as a quote, and reads the
/// digits up to the first other character. A value of a given length takes the last digits,
/// with zeros in front when the file has fewer digits, as the C reader shifts each digit in.
pub struct ResponseFile<'text> {
    text: &'text [u8],
}

impl<'text> ResponseFile<'text> {
    /// Reads the text of a response file.
    pub fn new(text: &'text str) -> Self {
        ResponseFile {
            text: text.as_bytes(),
        }
    }

    /// The value of a length after the first match of a marker at or after a position, and
    /// the position after the character that ends it, or `None` when the marker is missing.
    ///
    /// When the line has no digit, the value is all zeros, as the C reader leaves it. A length
    /// of zero reads nothing and keeps the position, as `ReadHex` does.
    pub fn value(&self, marker: &str, from: usize, length: usize) -> Option<(Vec<u8>, usize)> {
        if length == 0 {
            return Some((Vec::new(), from));
        }
        let mut position = self.positionAfter(marker, from)?;
        let mut value = vec![0u8; length];
        let mut hasStarted = false;
        while let Some(&character) = self.text.get(position) {
            position += 1;
            match (character as char).to_digit(16) {
                Some(digit) => {
                    hasStarted = true;
                    // Each shift clears the low 4 bits, and the added value is below 16, so
                    // the sum is the join of the two fields with no carry.
                    for index in 0..length - 1 {
                        value[index] = (value[index] << 4) + (value[index + 1] >> 4);
                    }
                    value[length - 1] = (value[length - 1] << 4) + digit as u8;
                }
                None if hasStarted || character == b'\n' => break,
                None => {}
            }
        }
        Some((value, position))
    }

    /// The number of bytes of the value after the first match of a marker: half the number of
    /// characters up to the end of its line, as `ReadHex` counts them for a length of zero.
    /// The count is zero when the marker is missing.
    pub fn valueLength(&self, marker: &str) -> usize {
        let Some(start) = self.positionAfter(marker, 0) else {
            return 0;
        };
        let characterCount = self.text[start..]
            .iter()
            .take_while(|character| **character != b'\n')
            .count();
        characterCount / 2
    }

    /// The decimal number after the first match of a marker at or after a position, as
    /// `fscanf` reads `%llu`, or `None`.
    pub fn number(&self, marker: &str, from: usize) -> Option<u64> {
        let start = self.positionAfter(marker, from)?;
        let text = core::str::from_utf8(&self.text[start..]).ok()?;
        let digits: &str = text
            .trim_start()
            .split(|character: char| !character.is_ascii_digit())
            .next()?;
        digits.parse().ok()
    }

    /// The position after the first match of a marker at or after a position.
    fn positionAfter(&self, marker: &str, from: usize) -> Option<usize> {
        let marker = marker.as_bytes();
        let rest = self.text.get(from..)?;
        let offset = rest
            .windows(marker.len())
            .position(|window| window == marker)?;
        Some(from + offset + marker.len())
    }
}

#[cfg(test)]
mod tests {
    use super::ResponseFile;
    use alloc::vec;

    #[test]
    fn valuesFollowTheirMarkersInFileOrder() {
        let file = ResponseFile::new("pk = 0A0b\nsk = FF\n\nmsg = 0102\nsm = 03\n");
        let (publicKey, afterPublicKey) = file.value("pk = ", 0, 2).expect("pk");
        assert_eq!(publicKey, vec![0x0A, 0x0B]);
        let (secretKey, afterSecretKey) = file.value("sk = ", afterPublicKey, 1).expect("sk");
        assert_eq!(secretKey, vec![0xFF]);
        assert_eq!(
            file.value("msg = ", afterSecretKey, 2)
                .map(|(value, _)| value),
            Some(vec![1, 2])
        );
        assert_eq!(
            file.value("pk = ", afterPublicKey, 2),
            None,
            "a marker before the position"
        );
        assert_eq!(file.value("missing = ", 0, 2), None);
    }

    #[test]
    fn readingSkipsTheCharactersBeforeTheFirstDigitAndStopsAtTheFirstOther() {
        let file = ResponseFile::new("sm = \"00AB\"\npk = \nmsg = 12 34\n");
        assert_eq!(
            file.value("sm = ", 0, 2).map(|(value, _)| value),
            Some(vec![0x00, 0xAB])
        );
        // A line without a digit gives zeros, as the C reader leaves the buffer.
        assert_eq!(
            file.value("pk = ", 0, 2).map(|(value, _)| value),
            Some(vec![0, 0])
        );
        assert_eq!(
            file.value("msg = ", 0, 1).map(|(value, _)| value),
            Some(vec![0x12])
        );
    }

    #[test]
    fn aValueKeepsTheLastDigitsWithZerosInFrontOfAShortOne() {
        let file = ResponseFile::new("a = 123456\nb = 0F\n");
        assert_eq!(
            file.value("a = ", 0, 2).map(|(value, _)| value),
            Some(vec![0x34, 0x56])
        );
        assert_eq!(
            file.value("b = ", 0, 3).map(|(value, _)| value),
            Some(vec![0, 0, 0x0F])
        );
        assert_eq!(
            file.value("b = ", 5, 0),
            Some((vec![], 5)),
            "a length of zero reads nothing"
        );
    }

    #[test]
    fn lengthsCountTheCharactersOfTheLineAndNumbersReadDecimals() {
        let file = ResponseFile::new("msg = 0102030\npk = \nremain = 1022\nmax = 1023\n");
        assert_eq!(file.valueLength("msg = "), 3);
        assert_eq!(file.valueLength("pk = "), 0);
        assert_eq!(file.valueLength("missing = "), 0);
        assert_eq!(file.number("remain = ", 0), Some(1022));
        assert_eq!(file.number("max = ", 0), Some(1023));
        assert_eq!(file.number("missing = ", 0), None);
    }
}
