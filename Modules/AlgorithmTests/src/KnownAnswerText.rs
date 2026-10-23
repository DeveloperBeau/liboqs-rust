use alloc::format;
use alloc::string::String;

/// The text of a liboqs known-answer program, built line by line as the C program prints it.
#[derive(Default)]
pub struct KnownAnswerText {
    text: String,
}

impl KnownAnswerText {
    /// Makes an empty text.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a line `label = number`, as `fprintf(fh, "count = %zu\n", count)` prints it.
    pub fn appendNumber(&mut self, label: &str, number: usize) {
        self.text.push_str(&format!("{label} = {number}\n"));
    }

    /// Appends a line `label = HEX` in upper-case hexadecimal, as `OQS_fprintBstr` prints it.
    /// An empty value prints as `00`, as in the C helper.
    pub fn appendBytes(&mut self, label: &str, bytes: &[u8]) {
        self.text.push_str(label);
        self.text.push_str(" = ");
        if bytes.is_empty() {
            self.text.push_str("00");
        }
        for byte in bytes {
            self.text.push_str(&format!("{byte:02X}"));
        }
        self.text.push('\n');
    }

    /// Appends the empty line between two counts.
    pub fn appendBlankLine(&mut self) {
        self.text.push('\n');
    }

    /// The text so far.
    pub fn text(&self) -> &str {
        &self.text
    }
}

#[cfg(test)]
mod tests {
    use super::KnownAnswerText;

    #[test]
    fn linesFollowTheFormatOfTheCPrograms() {
        let mut text = KnownAnswerText::new();
        text.appendNumber("count", 12);
        text.appendBytes("seed", &[0x0A, 0xFF, 0x00]);
        text.appendBlankLine();
        text.appendBytes("msg", &[]);
        assert_eq!(text.text(), "count = 12\nseed = 0AFF00\n\nmsg = 00\n");
    }
}
