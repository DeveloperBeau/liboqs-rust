# Repository checks

## Purpose

`cargo xtask` runs the checks that `standards.md` names. A check reads its rule list from a register, so the register is the one owner of the rule. The `.cargo/config.toml` alias runs the `xtask` binary of `Tools/Xtask`.

## Crate

`Tools/Xtask` has the package name `xtask` and the library name `RepositoryTools`. It has no third-party dependency. It reads TOML and Markdown with small readers for the subset that the repository uses.

The public surface is `run`, `Report`, `FileReading` and `DiskFileSystem`. The binary needs these four. Every other type is private to the crate.

| Type | Job |
|---|---|
| `FileReading` | The interface to the repository files. |
| `DiskFileSystem` | The real repository. It takes the file list from `git ls-files`, so ignored and excluded files are not checked. It also reads a local file from the git folder. |
| `MemoryFileSystem` | The test double. Every unit test runs against it. |
| `CargoManifest`, `WorkspaceLayout`, `MemberCrate`, `Dependency` | The parts of the manifests that the checks read. |
| `MarkdownTable` | The first table of a register. |
| `RingCheck` | Rings and approved dependencies. See [Rings.md](Rings.md). |
| `NamingCheck` | Swift casing of Rust names and paths. |
| `RustTokenizer`, `RustToken`, `RustTokenKind` | The tokens of a Rust source file. |
| `TokenTree` | The tokens grouped by brackets. |
| `DeclarationScanner` | The declared names of a Rust source file. |
| `VersionCheck` | Every copy of the version against `LIBOQS_VERSION`. See [Versioning.md](Versioning.md). |
| `HygieneCheck` | Em-dash, absolute paths, forbidden words and semicolons in prose. |
| `UnsafeCodeCheck` | `unsafe` code only in the files of the unsafe code register. |
| `Command` | The command words. |
| `Report` | The output text and the exit status of one run. |

## Data flow

1. `main.rs`, the composition root, builds `DiskFileSystem` for the repository root. It reads the `HYGIENE_WORDS` variable and the local word file `info/hygiene-words` in the git folder.
2. `run` reads the command, runs the checks through `FileReading`, and returns a `Report`.
3. `main.rs` prints the two texts of the report and exits with its status.

## Commands

- `cargo xtask check` runs every check.
- `cargo xtask check-rings`, `check-names`, `check-versions`, `check-hygiene` and `check-unsafe` run one check.

The command exits with status 0 when there is no finding, 1 when there is a finding, and 2 for a wrong command.

## Names

The names check has three steps:

1. `RustTokenizer` splits a source file into tokens. Comments and whitespace give no token. It knows strings with escapes, raw strings, byte and C strings, character literals, lifetimes, numbers and raw identifiers, so text in a literal or a comment never counts as a name.
2. `TokenTree` groups the tokens by `(`, `[` and `{`. A missing or extra bracket never stops the scan.
3. `DeclarationScanner` walks the trees. A handler for each keyword reads the names after it. The scan goes into every other group, so a declaration inside a block is found too. It does not go into the body of a `macro_rules!` macro or into an `extern` block. It also leaves out the name of an `extern` function, because the foreign ABI fixes it.

The scanner finds the names of functions, parameters, `let` and `for` bindings, constants, statics, types, traits, generic parameters, fields, enumeration cases, modules and macros. `NamingCheck` applies the rules of `standards.md` section 3.2 to each name. It also checks each folder and file name in a Rust source path, and the `[lib] name` of each crate. A crate with `src/lib.rs` and no `[lib] name` is a finding, because the default library name is snake case.

The scanner has limits. It does not read the names inside a pattern of a type, such as `let Some(value) = ...`, or a tuple pattern in a parameter list. These limits can let a bad name pass. They can not make a good name fail.

## Hygiene

`HygieneCheck` reads every file that git lists:

- An em-dash is a finding in any file.
- An absolute path of a computer is a finding in any file.
- A forbidden word is a finding in a file name or in a line, in any letter case.
- A semicolon is a finding in the prose of a Markdown file at the root or under `Documentation/`. Text in a fenced code block or in a code span is not prose.

The forbidden words come from the `HYGIENE_WORDS` variable, a comma-separated list, or else from the local file `info/hygiene-words` in the git folder. The repository never holds the list, because the list is the words that the repository must not hold. Without a list, the word scan does not run and the command prints a note.

## Unsafe code

`UnsafeCodeCheck` reads every Rust file through `RustTokenizer`, so `unsafe` in a comment, a string or a raw identifier is not code. A file with an `unsafe` token must have a row in `Documentation/Registers/UnsafeCode.md`. A row whose file has no `unsafe` token is a finding too, so the register cannot keep a stale exception.

## Tests

- Each type has unit tests in its file. The tokenizer tests compare the token list, kind and text, with a hand-written list. The scanner tests compare the declarations with a hand-written list.
- `RepositoryFixtureTests.rs` runs `run` and the checks on a whole repository in memory, with the real registers, and compares the result with text written by hand.
- `tests/DiskFileSystemContract.rs` is the contract test of the adapter. It makes a real git repository in a temporary folder, with tracked, new, ignored, excluded and deleted files, and deletes the folder at the end.
- `tests/CommandLine.rs` runs the built binary with a wrong command and with no command, and checks the exit status and the usage text. The wait for the binary has a limit of 30 seconds.
- Seeded random tests cover the tokenizer (3000 random fragment lists), the scanner (3000 lists), the naming rules (500 random names in each form), the ring rule (200 random workspaces) and the hygiene rules (500 random lines).
- The mutation results are in `Documentation/Registers/MutationResults.md`.
