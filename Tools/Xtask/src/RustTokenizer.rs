use crate::RustToken;
use crate::RustTokenKind;

/// Splits Rust source text into tokens. Comments and whitespace give no token.
///
/// The tokenizer knows line comments, nested block comments, strings with escapes, raw strings,
/// byte and C strings, character and byte literals, lifetimes, numbers and raw identifiers. It
/// is not a full lexer: it accepts text that Rust rejects, and it never fails, so a scan of
/// broken source still ends.
pub struct RustTokenizer {
    characters: Vec<char>,
    index: usize,
    line: usize,
    tokens: Vec<RustToken>,
}

impl RustTokenizer {
    /// Returns the tokens of a source text, in source order.
    pub fn tokens(source: &str) -> Vec<RustToken> {
        let mut tokenizer = RustTokenizer {
            characters: source.chars().collect(),
            index: 0,
            line: 1,
            tokens: Vec::new(),
        };
        while !tokenizer.isAtEnd() {
            let start = tokenizer.index;
            tokenizer.readNext();
            // Each step reads at least one character, so the loop always ends.
            debug_assert!(tokenizer.index > start, "no progress at character {start}");
        }
        tokenizer.tokens
    }

    fn readNext(&mut self) {
        let start = self.index;
        let line = self.line;
        let current = self.character(0);
        let next = self.character(1);
        let kind = match current {
            '/' if next == '/' => return self.skipLineComment(),
            '/' if next == '*' => return self.skipBlockComment(),
            '"' => {
                self.moveBy(1);
                self.skipStringBody();
                RustTokenKind::literal
            }
            '\'' => self.readQuote(),
            _ if current.is_whitespace() => return self.moveBy(1),
            _ if current.is_ascii_digit() => {
                self.skipNumber();
                RustTokenKind::literal
            }
            _ if Self::isWordCharacter(current) => self.readWord(),
            _ => {
                self.readPunctuation();
                RustTokenKind::punctuation
            }
        };
        let textStart = if kind == RustTokenKind::rawIdentifier {
            start + 2
        } else {
            start
        };
        let text = self.characters[textStart..self.index].iter().collect();
        self.tokens.push(RustToken { kind, text, line });
    }

    fn skipLineComment(&mut self) {
        self.moveTo(self.indexOfFirst(|character| character == '\n'));
    }

    fn skipBlockComment(&mut self) {
        let mut depth = 0;
        while !self.isAtEnd() {
            if self.isAt("/*") {
                depth += 1;
                self.moveBy(2);
            } else if self.isAt("*/") {
                depth -= 1;
                self.moveBy(2);
                if depth == 0 {
                    return;
                }
            } else {
                self.moveBy(1);
            }
        }
    }

    /// Reads the rest of a string after its opening quote, with its closing quote.
    fn skipStringBody(&mut self) {
        while !self.isAtEnd() {
            match self.character(0) {
                '\\' => self.moveBy(2),
                '"' => return self.moveBy(1),
                _ => self.moveBy(1),
            }
        }
    }

    /// Reads a raw string body that starts at its first `#` or at its opening quote.
    fn skipRawStringBody(&mut self) {
        let hashCount = self.characters[self.index..]
            .iter()
            .take_while(|character| **character == '#')
            .count();
        self.moveBy(hashCount + 1);
        let closing: Vec<char> = std::iter::once('"')
            .chain(std::iter::repeat_n('#', hashCount))
            .collect();
        // Without a closing quote, the raw string runs to the end of the input.
        let end = self.characters[self.index..]
            .windows(closing.len())
            .position(|window| window == closing.as_slice())
            .map_or(self.characters.len(), |offset| {
                self.index + offset + closing.len()
            });
        self.moveTo(end);
    }

    /// Reads a character literal, or else a lifetime or a loop label.
    fn readQuote(&mut self) -> RustTokenKind {
        if self.character(1) == '\\' {
            // An escape such as `'\n'`, `'\''` or `'\u{2014}'` ends at the first quote after
            // the escaped character.
            self.moveBy(3);
            self.moveTo(self.indexOfFirst(|character| character == '\''));
            self.moveBy(1);
            RustTokenKind::literal
        } else if self.character(2) == '\'' {
            self.moveBy(3);
            RustTokenKind::literal
        } else {
            self.moveBy(1);
            self.moveTo(self.indexOfFirst(|character| !Self::isWordCharacter(character)));
            RustTokenKind::lifetime
        }
    }

    /// Reads a number. A dot belongs to the number only when a digit follows it, so `0..10`
    /// stays three tokens.
    fn skipNumber(&mut self) {
        loop {
            let character = self.character(0);
            let isPartOfNumber = Self::isWordCharacter(character)
                || (character == '.' && self.character(1).is_ascii_digit());
            if !isPartOfNumber {
                return;
            }
            self.moveBy(1);
        }
    }

    /// Reads a word: an identifier, a keyword, a raw identifier, or the prefix of a literal
    /// such as `b"..."`, `r#"..."#` or `b'x'`.
    fn readWord(&mut self) -> RustTokenKind {
        let start = self.index;
        self.moveTo(self.indexOfFirst(|character| !Self::isWordCharacter(character)));
        let word: String = self.characters[start..self.index].iter().collect();
        match (word.as_str(), self.character(0)) {
            ("b" | "c", '"') => {
                self.moveBy(1);
                self.skipStringBody();
                RustTokenKind::literal
            }
            ("r" | "br" | "cr", '"' | '#') if self.isRawStringStart() => {
                self.skipRawStringBody();
                RustTokenKind::literal
            }
            ("b", '\'') => {
                self.readQuote();
                RustTokenKind::literal
            }
            ("r", '#') if Self::isWordCharacter(self.character(1)) => {
                self.moveBy(1);
                self.moveTo(self.indexOfFirst(|character| !Self::isWordCharacter(character)));
                RustTokenKind::rawIdentifier
            }
            _ => RustTokenKind::identifier,
        }
    }

    /// True when the next characters are zero or more `#` and then a quote.
    fn isRawStringStart(&self) -> bool {
        let hashCount = self.characters[self.index..]
            .iter()
            .take_while(|character| **character == '#')
            .count();
        self.character(hashCount) == '"'
    }

    fn readPunctuation(&mut self) {
        let isPair = ["->", "=>", "::"].iter().any(|pair| self.isAt(pair));
        self.moveBy(if isPair { 2 } else { 1 });
    }

    fn isWordCharacter(character: char) -> bool {
        character.is_alphanumeric() || character == '_'
    }

    fn isAtEnd(&self) -> bool {
        self.index == self.characters.len()
    }

    /// Returns the character at an offset from the current index, or NUL after the end.
    fn character(&self, offset: usize) -> char {
        self.characters
            .get(self.index + offset)
            .copied()
            .unwrap_or('\0')
    }

    fn isAt(&self, text: &str) -> bool {
        text.chars()
            .enumerate()
            .all(|(offset, expected)| self.character(offset) == expected)
    }

    /// Returns the index of the first character from the current index that passes a test, or
    /// the end index when no character passes.
    fn indexOfFirst(&self, test: impl Fn(char) -> bool) -> usize {
        self.characters[self.index..]
            .iter()
            .position(|character| test(*character))
            .map_or(self.characters.len(), |offset| self.index + offset)
    }

    /// Moves forward by a count of characters, but not past the end.
    fn moveBy(&mut self, count: usize) {
        self.moveTo((self.index + count).min(self.characters.len()));
    }

    /// Moves forward to an index and counts the line breaks on the way.
    fn moveTo(&mut self, target: usize) {
        self.line += self.characters[self.index..target]
            .iter()
            .filter(|character| **character == '\n')
            .count();
        self.index = target;
    }
}

#[cfg(test)]
mod tests {
    use super::RustTokenizer;
    use crate::RustTokenKind::{self, *};
    use crate::SeededGenerator;

    fn tokens(source: &str) -> Vec<(RustTokenKind, String)> {
        RustTokenizer::tokens(source)
            .into_iter()
            .map(|token| (token.kind, token.text))
            .collect()
    }

    fn expected(entries: &[(RustTokenKind, &str)]) -> Vec<(RustTokenKind, String)> {
        entries
            .iter()
            .map(|(kind, text)| (*kind, text.to_string()))
            .collect()
    }

    #[test]
    fn wordsNumbersAndPunctuationAreSeparateTokens() {
        assert_eq!(
            tokens("let a=b/c; x->y => z::w 0..10 1.5 0x1F_u8"),
            expected(&[
                (identifier, "let"),
                (identifier, "a"),
                (punctuation, "="),
                (identifier, "b"),
                (punctuation, "/"),
                (identifier, "c"),
                (punctuation, ";"),
                (identifier, "x"),
                (punctuation, "->"),
                (identifier, "y"),
                (punctuation, "=>"),
                (identifier, "z"),
                (punctuation, "::"),
                (identifier, "w"),
                (literal, "0"),
                (punctuation, "."),
                (punctuation, "."),
                (literal, "10"),
                (literal, "1.5"),
                (literal, "0x1F_u8"),
            ])
        );
    }

    #[test]
    fn lineCommentEndsAtTheLineBreak() {
        assert_eq!(
            tokens("a // b c\nd // e"),
            expected(&[(identifier, "a"), (identifier, "d")])
        );
    }

    #[test]
    fn blockCommentsNestAndEndAtTheirOwnClose() {
        assert_eq!(
            tokens("a /* b /* c */ d * e */ f/**/g"),
            expected(&[(identifier, "a"), (identifier, "f"), (identifier, "g")])
        );
    }

    #[test]
    fn multiplicationIsNotACommentStart() {
        assert_eq!(
            tokens("a*b"),
            expected(&[(identifier, "a"), (punctuation, "*"), (identifier, "b")])
        );
    }

    #[test]
    fn stringsKeepEscapedQuotesAndBackslashes() {
        assert_eq!(
            tokens(r#""a\"b" "c\\" d"#),
            expected(&[
                (literal, r#""a\"b""#),
                (literal, r#""c\\""#),
                (identifier, "d")
            ])
        );
    }

    #[test]
    fn rawByteAndCStringsAreOneLiteral() {
        assert_eq!(
            tokens(r###"r"a\" r#"#b"c"# br##"d"#e"## b"f\"" c"g" cr#"h"# x"###),
            expected(&[
                (literal, r#"r"a\""#),
                (literal, r##"r#"#b"c"#"##),
                (literal, r###"br##"d"#e"##"###),
                (literal, r#"b"f\"""#),
                (literal, r#"c"g""#),
                (literal, r##"cr#"h"#"##),
                (identifier, "x"),
            ])
        );
    }

    #[test]
    fn characterLiteralsAndLifetimesAreToldApart() {
        assert_eq!(
            tokens(r"'a' '\'' '\\' '\u{41}' '\x7f' 'static 'é' b'x' b'\n' after"),
            expected(&[
                (literal, "'a'"),
                (literal, r"'\''"),
                (literal, r"'\\'"),
                (literal, r"'\u{41}'"),
                (literal, r"'\x7f'"),
                (lifetime, "'static"),
                (literal, "'é'"),
                (literal, "b'x'"),
                (literal, r"b'\n'"),
                (identifier, "after"),
            ])
        );
    }

    #[test]
    fn quoteInsideACharacterLiteralDoesNotStartAString() {
        assert_eq!(
            tokens(r#"let q = '\"'; fn visible() {}"#),
            expected(&[
                (identifier, "let"),
                (identifier, "q"),
                (punctuation, "="),
                (literal, r#"'\"'"#),
                (punctuation, ";"),
                (identifier, "fn"),
                (identifier, "visible"),
                (punctuation, "("),
                (punctuation, ")"),
                (punctuation, "{"),
                (punctuation, "}"),
            ])
        );
    }

    #[test]
    fn rawIdentifierLosesItsPrefixAtAnyPosition() {
        assert_eq!(
            tokens("r#type x r#match"),
            expected(&[
                (rawIdentifier, "type"),
                (identifier, "x"),
                (rawIdentifier, "match")
            ])
        );
    }

    #[test]
    fn plainWordsThatLookLikePrefixesStayIdentifiers() {
        assert_eq!(
            tokens("r b c br r#"),
            expected(&[
                (identifier, "r"),
                (identifier, "b"),
                (identifier, "c"),
                (identifier, "br"),
                (identifier, "r"),
                (punctuation, "#"),
            ])
        );
    }

    #[test]
    fn linesAreCountedThroughCommentsStringsAndRawStrings() {
        let source = "a\n/* x\ny */ b \"c\nd\" e\nr#\"f\ng\"# h // i\nj";
        let lines: Vec<(String, usize)> = RustTokenizer::tokens(source)
            .into_iter()
            .map(|token| (token.text, token.line))
            .collect();
        let expectedLines: Vec<(String, usize)> = [
            ("a", 1),
            ("b", 3),
            ("\"c\nd\"", 3),
            ("e", 4),
            ("r#\"f\ng\"#", 5),
            ("h", 6),
            ("j", 7),
        ]
        .iter()
        .map(|(text, line)| (text.to_string(), *line))
        .collect();
        assert_eq!(lines, expectedLines);
    }

    #[test]
    fn unterminatedInputEndsWithTheRestAsOneToken() {
        assert_eq!(tokens("\"open"), expected(&[(literal, "\"open")]));
        assert_eq!(tokens("\"open\\"), expected(&[(literal, "\"open\\")]));
        assert_eq!(tokens("r#\"open"), expected(&[(literal, "r#\"open")]));
        assert_eq!(tokens("a /* open"), expected(&[(identifier, "a")]));
        assert_eq!(tokens("'\\u{41"), expected(&[(literal, "'\\u{41")]));
        assert_eq!(tokens("'"), expected(&[(lifetime, "'")]));
        assert_eq!(tokens("// only"), expected(&[]));
        assert_eq!(tokens(""), expected(&[]));
    }

    /// Random text from Rust fragments must never panic or hang, and every token must hold
    /// text. The seed is printed.
    #[test]
    fn randomFragmentsGiveNonEmptyTokensWithoutPanic() {
        let fragments = [
            "fn ", "a", "_b", "1", "1.5", ".", "'", "'x'", "'\\", "\\", "\"", "r", "b", "#", "/",
            "*", "/*", "*/", "//", "\n", " ", "->", "=>", "::", ":", "<", ">", "{", "}", "é",
        ];
        let mut generator = SeededGenerator::new(0x54_4F_4B_45_4E);
        for _ in 0..3000 {
            let count = generator.nextIndex(30);
            let source: String = (0..count).map(|_| *generator.element(&fragments)).collect();
            for token in RustTokenizer::tokens(&source) {
                assert!(!token.text.is_empty(), "empty token in {source:?}");
            }
        }
    }
}
