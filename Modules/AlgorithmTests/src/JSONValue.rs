use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A value of a JSON document, for the test vector files.
///
/// A number keeps its text, because the vector files use numbers only as counts and
/// identifiers.
#[derive(Clone, Debug, PartialEq)]
pub enum JSONValue {
    /// `null`.
    null,
    /// `true` or `false`.
    boolean(bool),
    /// A number, as its text.
    number(String),
    /// A string, with its escapes decoded.
    string(String),
    /// An array.
    array(Vec<JSONValue>),
    /// An object, with its members in document order.
    object(Vec<(String, JSONValue)>),
}

impl JSONValue {
    /// Reads a whole JSON document. Text after the value is an error.
    pub fn parse(text: &str) -> Result<JSONValue, String> {
        let mut reader = Reader {
            bytes: text.as_bytes(),
            position: 0,
        };
        let value = reader.value()?;
        reader.skipSpace();
        if reader.position != reader.bytes.len() {
            return Err(reader.error("text after the value"));
        }
        Ok(value)
    }

    /// The member of an object with a name, or `None`.
    pub fn member(&self, name: &str) -> Option<&JSONValue> {
        match self {
            JSONValue::object(members) => members
                .iter()
                .find(|(memberName, _)| memberName == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The text of a string value, or `None`.
    pub fn text(&self) -> Option<&str> {
        match self {
            JSONValue::string(text) => Some(text),
            _ => None,
        }
    }

    /// The elements of an array, or an empty slice for any other value.
    pub fn elements(&self) -> &[JSONValue] {
        match self {
            JSONValue::array(elements) => elements,
            _ => &[],
        }
    }

    /// The bytes of a string value of hexadecimal digits, or `None`.
    pub fn hexBytes(&self) -> Option<Vec<u8>> {
        let text = self.text()?;
        if text.len() % 2 != 0 {
            return None;
        }
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
            .collect()
    }
}

/// The reader of one document.
struct Reader<'text> {
    bytes: &'text [u8],
    position: usize,
}

impl Reader<'_> {
    fn error(&self, what: &str) -> String {
        alloc::format!("JSON: {what} at byte {}", self.position)
    }

    fn skipSpace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.bytes.get(self.position) == Some(&byte) {
            self.position += 1;
            Ok(())
        } else {
            Err(self.error(&alloc::format!("`{}` expected", byte as char)))
        }
    }

    fn literal(&mut self, word: &str, value: JSONValue) -> Result<JSONValue, String> {
        if self.bytes[self.position..].starts_with(word.as_bytes()) {
            self.position += word.len();
            Ok(value)
        } else {
            Err(self.error("an unknown word"))
        }
    }

    fn value(&mut self) -> Result<JSONValue, String> {
        self.skipSpace();
        match self.bytes.get(self.position) {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(JSONValue::string(self.string()?)),
            Some(b't') => self.literal("true", JSONValue::boolean(true)),
            Some(b'f') => self.literal("false", JSONValue::boolean(false)),
            Some(b'n') => self.literal("null", JSONValue::null),
            Some(byte) if *byte == b'-' || byte.is_ascii_digit() => self.number(),
            _ => Err(self.error("a value expected")),
        }
    }

    fn object(&mut self) -> Result<JSONValue, String> {
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.skipSpace();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(JSONValue::object(members));
        }
        loop {
            self.skipSpace();
            let name = self.string()?;
            self.skipSpace();
            self.expect(b':')?;
            let value = self.value()?;
            members.push((name, value));
            self.skipSpace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(JSONValue::object(members));
                }
                _ => return Err(self.error("`,` or `}` expected")),
            }
        }
    }

    fn array(&mut self) -> Result<JSONValue, String> {
        self.expect(b'[')?;
        let mut elements = Vec::new();
        self.skipSpace();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(JSONValue::array(elements));
        }
        loop {
            elements.push(self.value()?);
            self.skipSpace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(JSONValue::array(elements));
                }
                _ => return Err(self.error("`,` or `]` expected")),
            }
        }
    }

    fn number(&mut self) -> Result<JSONValue, String> {
        let start = self.position;
        while self.bytes.get(self.position).is_some_and(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E')
        }) {
            self.position += 1;
        }
        let text = core::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| self.error("a number expected"))?;
        Ok(JSONValue::number(text.to_string()))
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut text = String::new();
        loop {
            let Some(&byte) = self.bytes.get(self.position) else {
                return Err(self.error("an unterminated string"));
            };
            self.position += 1;
            match byte {
                b'"' => return Ok(text),
                b'\\' => {
                    let Some(&escape) = self.bytes.get(self.position) else {
                        return Err(self.error("an unterminated escape"));
                    };
                    self.position += 1;
                    let character = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let digits = self
                                .bytes
                                .get(self.position..self.position + 4)
                                .and_then(|digits| core::str::from_utf8(digits).ok())
                                .and_then(|digits| u32::from_str_radix(digits, 16).ok())
                                .ok_or_else(|| self.error("four hexadecimal digits expected"))?;
                            self.position += 4;
                            char::from_u32(digits).unwrap_or('\u{fffd}')
                        }
                        _ => return Err(self.error("an unknown escape")),
                    };
                    text.push(character);
                }
                _ => {
                    // The plain text runs to the next quote or backslash. The run starts and
                    // ends at an ASCII byte, so it is whole characters of the `str` it came
                    // from.
                    let start = self.position - 1;
                    let end = self.bytes[start..]
                        .iter()
                        .position(|byte| matches!(byte, b'"' | b'\\'))
                        .map_or(self.bytes.len(), |offset| start + offset);
                    text.push_str(
                        core::str::from_utf8(&self.bytes[start..end]).expect("whole characters"),
                    );
                    self.position = end;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::JSONValue;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn eachKindOfValueIsRead() {
        let value = JSONValue::parse(
            " { \"a\" : [1, -2.5e3, true, false, null], \"b\": {\"c\": \"x\\\"\\\\\\/\\n\\u0041é\\b\\f\\r\\t€𝄞 y\"}, \"d\": [], \"e\": {} } ",
        )
        .expect("a valid document");
        assert_eq!(
            value.member("a"),
            Some(&JSONValue::array(vec![
                JSONValue::number("1".to_string()),
                JSONValue::number("-2.5e3".to_string()),
                JSONValue::boolean(true),
                JSONValue::boolean(false),
                JSONValue::null,
            ]))
        );
        assert_eq!(
            value
                .member("b")
                .and_then(|b| b.member("c"))
                .and_then(JSONValue::text),
            Some("x\"\\/\nAé\u{8}\u{c}\r\t€𝄞 y")
        );
        assert_eq!(
            value.member("a").map(|a| a.elements().len()),
            Some(5),
            "the elements of an array"
        );
        assert!(value.member("d").is_some_and(|d| d.elements().is_empty()));
        assert_eq!(value.member("e"), Some(&JSONValue::object(vec![])));
        assert_eq!(value.member("missing"), None);
        assert_eq!(JSONValue::null.member("a"), None);
        assert!(JSONValue::null.elements().is_empty());
        assert_eq!(JSONValue::boolean(true).text(), None);
    }

    #[test]
    fn hexStringsDecodeToBytes() {
        assert_eq!(
            JSONValue::string("00ff7A".to_string()).hexBytes(),
            Some(vec![0, 255, 0x7A])
        );
        assert_eq!(JSONValue::string(String::new()).hexBytes(), Some(vec![]));
        assert_eq!(JSONValue::string("abc".to_string()).hexBytes(), None);
        assert_eq!(JSONValue::string("zz".to_string()).hexBytes(), None);
        assert_eq!(JSONValue::null.hexBytes(), None);
    }

    #[test]
    fn malformedDocumentsAreErrorsWithTheirPosition() {
        for (text, message) in [
            ("{\"a\" 1}", "JSON: `:` expected at byte 5"),
            ("[1 2]", "JSON: `,` or `]` expected at byte 3"),
            ("{\"a\": 1 \"b\": 2}", "JSON: `,` or `}` expected at byte 8"),
            ("\"open", "JSON: an unterminated string at byte 5"),
            ("tru", "JSON: an unknown word at byte 0"),
            ("[1] x", "JSON: text after the value at byte 4"),
            ("\"\\q\"", "JSON: an unknown escape at byte 3"),
            (
                "\"\\u12\"",
                "JSON: four hexadecimal digits expected at byte 3",
            ),
            ("", "JSON: a value expected at byte 0"),
            ("{\"a\":}", "JSON: a value expected at byte 5"),
        ] {
            assert_eq!(JSONValue::parse(text), Err(message.to_string()), "{text}");
        }
    }
}
