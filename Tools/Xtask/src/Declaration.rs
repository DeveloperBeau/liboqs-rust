use crate::DeclarationKind;

/// One name that a Rust source file declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    /// The declared name, without a raw identifier prefix.
    pub name: String,
    /// What the name names.
    pub kind: DeclarationKind,
    /// The line of the name in the source file.
    pub line: usize,
}
