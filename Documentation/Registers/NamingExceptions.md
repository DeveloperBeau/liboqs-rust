# Naming exceptions

A name in this table keeps a form that the casing rules forbid, because the language, a wire format or a framework forces the form. `cargo xtask check-names` accepts each name only for its kind. The kind `path` covers a folder or file name in a Rust source path. Add a row only for a forced form, and give the reason.

| Kind | Name | Reason |
|---|---|---|
| `function` | `from_str` | The standard library trait `FromStr` calls this name. |
| `function` | `try_from` | The standard library trait `TryFrom` calls this name. |
| `function` | `as_ref` | The standard library trait `AsRef` calls this name. |
| `function` | `partial_cmp` | The standard library trait `PartialOrd` calls this name. |
