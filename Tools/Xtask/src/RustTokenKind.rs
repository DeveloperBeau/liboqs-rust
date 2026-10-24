/// The kind of a token of Rust source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustTokenKind {
    /// A name or a keyword.
    identifier,
    /// A name written with the `r#` prefix. The token text has no prefix.
    rawIdentifier,
    /// A lifetime or a loop label, such as `'a`.
    lifetime,
    /// A string, raw string, byte string, character, byte or number literal.
    literal,
    /// One punctuation character, or one of the pairs `->`, `=>` and `::`.
    punctuation,
}
