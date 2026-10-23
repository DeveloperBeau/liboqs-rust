/// What a declared Rust name names, which decides the casing rule for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclarationKind {
    /// A function or a method.
    function,
    /// A function parameter.
    parameter,
    /// A `let` binding or a `for` loop binding.
    variable,
    /// A `const` or a `static` item.
    constant,
    /// A named field of a structure or of an enumeration case.
    field,
    /// A case of an enumeration.
    enumerationCase,
    /// A structure, an enumeration, a union or a type alias.
    r#type,
    /// A trait.
    protocol,
    /// A generic type parameter or a generic constant parameter.
    genericParameter,
    /// A module.
    module,
    /// A `macro_rules!` macro.
    r#macro,
}
