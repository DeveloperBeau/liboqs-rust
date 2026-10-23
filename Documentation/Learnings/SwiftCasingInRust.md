# Swift casing in Rust

## A file named after its type gives a module with the name of the type

- **Trap.** The rule "one public type per file, with the name of the type" gives `Finding.rs` and so `mod Finding`. Rust puts modules and types in the same namespace. `pub use Finding::Finding` next to `mod Finding` is a name conflict, and the public path becomes `Finding::Finding`.
- **Finding.** The first build of `Tools/Xtask` had `pub mod Finding` and needed a doc comment on each module and a doubled path at each use.
- **Rule.** Keep the file name, and give the module a `lowerCamelCase` name with the `#[path]` attribute: `#[path = "Finding.rs"] mod finding;` then `pub use finding::Finding;`. The public path is `RepositoryTools::Finding`.

## The compiler warns about every Swift name

- **Trap.** Rust lints `non_snake_case`, `non_upper_case_globals` and `non_camel_case_types` are on by default, and `clippy::upper_case_acronyms` rejects `MLKEM768`.
- **Finding.** A probe crate with `generateKeyPair`, `const PublicKeyLength`, a module `MLKEM768` and a library name `OQSNativeProbe` built and tested with these four lints set to `allow`, and with no other change.
- **Rule.** Set the four lints in `[workspace.lints]` once. Every crate uses `[lints] workspace = true`. Do not rename to quiet a warning.

## The default library name is snake case

- **Trap.** Cargo makes the library name from the package name, so `oqs-native-entities` becomes `oqs_native_entities` in code.
- **Finding.** Cargo accepts an `UpperCamelCase` `[lib] name`, and the probe crate imported `OQSNativeProbe` in its tests.
- **Rule.** Every library crate sets `[lib] name`. `cargo xtask check-names` reports a crate with `src/lib.rs` and no `[lib] name`.

## Clippy hides some lints for public types

- **Trap.** `clippy::enum_variant_names` rejects an enumeration whose cases all start with the same word. Clippy skips the lint for a public type by default (`avoid-breaking-exported-api`).
- **Finding.** `Command` had the cases `checkAll`, `checkRings` and others. Clippy accepted them while `Command` was public, and rejected them when `Command` became private to the crate.
- **Rule.** Run `cargo clippy --workspace --all-targets` after each change of visibility. Name each case by its role without the shared word, such as `Command::rings`.

## A constant captures a binding of the same name

- **Trap.** Rust reads a lower-case name in a pattern as a constant when a constant of that name is in scope. With Swift casing, constants and variables share one form, so `const seed` turns a parameter `seed` into a constant pattern.
- **Finding.** A test module of `Modules/Falcon` had `const seed: u64` and a helper `fn seeded(seed: u64)`. The build failed with E0005, "refutable pattern in function argument", because `seed` was a constant pattern and not a new variable. In a `match` arm, the same collision builds and compares with the constant without a word.
- **Rule.** Name a constant by its role, with a word that no binding in its scope uses, such as `operandSeed` or `nonceLength`.
