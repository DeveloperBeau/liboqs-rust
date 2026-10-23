use crate::RustTokenKind;

/// One token of Rust source text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustToken {
    /// What the token is.
    pub kind: RustTokenKind,
    /// The text of the token. A raw identifier has no `r#` prefix.
    pub text: String,
    /// The line of the first character of the token, counted from 1.
    pub line: usize,
}

impl RustToken {
    /// The words that are never a declared name: the strict and reserved keywords, and `_`.
    const keywords: &'static [&'static str] = &[
        "_", "abstract", "as", "async", "await", "become", "box", "break", "const", "continue",
        "crate", "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if",
        "impl", "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv",
        "pub", "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true",
        "try", "type", "typeof", "unsafe", "unsized", "use", "virtual", "where", "while", "yield",
    ];

    /// True when the token can be a declared name: a raw identifier, or an identifier that is
    /// not a keyword.
    pub fn isName(&self) -> bool {
        match self.kind {
            RustTokenKind::rawIdentifier => true,
            RustTokenKind::identifier => !Self::keywords.contains(&self.text.as_str()),
            _ => false,
        }
    }

    /// True when the token is the identifier or keyword `word`, not written as a raw identifier.
    pub fn isWord(&self, word: &str) -> bool {
        self.kind == RustTokenKind::identifier && self.text == word
    }

    /// True when the token is the punctuation `text`.
    pub fn isPunctuation(&self, text: &str) -> bool {
        self.kind == RustTokenKind::punctuation && self.text == text
    }
}

#[cfg(test)]
mod tests {
    use super::RustToken;
    use crate::RustTokenKind;

    fn token(kind: RustTokenKind, text: &str) -> RustToken {
        RustToken {
            kind,
            text: text.to_string(),
            line: 1,
        }
    }

    #[test]
    fn isNameAcceptsPlainAndRawNamesButNotKeywordsOrOtherKinds() {
        assert!(token(RustTokenKind::identifier, "publicKey").isName());
        assert!(token(RustTokenKind::rawIdentifier, "type").isName());
        for keyword in ["fn", "_", "self", "Self", "mut", "yield"] {
            assert!(
                !token(RustTokenKind::identifier, keyword).isName(),
                "{keyword}"
            );
        }
        assert!(!token(RustTokenKind::lifetime, "'a").isName());
        assert!(!token(RustTokenKind::literal, "1").isName());
        assert!(!token(RustTokenKind::punctuation, "<").isName());
    }

    #[test]
    fn isWordMatchesOnlyAPlainIdentifierWithTheSameText() {
        assert!(token(RustTokenKind::identifier, "fn").isWord("fn"));
        assert!(!token(RustTokenKind::rawIdentifier, "fn").isWord("fn"));
        assert!(!token(RustTokenKind::identifier, "fn").isWord("let"));
    }

    #[test]
    fn isPunctuationMatchesOnlyPunctuationWithTheSameText() {
        assert!(token(RustTokenKind::punctuation, "::").isPunctuation("::"));
        assert!(!token(RustTokenKind::punctuation, ":").isPunctuation("::"));
        assert!(!token(RustTokenKind::literal, ":").isPunctuation(":"));
    }
}
