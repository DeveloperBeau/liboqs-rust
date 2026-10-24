# Standards

This file is the contract of the project. Every contributor and every automated agent reads it in full before they write code, write tests or write a brief. When a rule here and the code disagree, that is a defect in one of them. Say which one, and fix it.

The companion folders are `Documentation/Architecture/`, which describes the code as it is, `Documentation/Learnings/`, which records traps and the rules that follow from them, and `Documentation/Registers/`, which holds each rule that needs a list.

## 1. What the project is

The project is a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs). It is not a set of bindings. No C code enters a shipped crate. The C library at the version in `LIBOQS_VERSION` is the source of truth for behavior, and the tests use it only as an oracle.

- Every algorithm gives output that is byte-identical to the C library for the same random bytes.
- The crate version equals the liboqs version. `LIBOQS_VERSION` is the one owner of that value.
- The API may differ from the C API. For example, each operation takes its random source as an argument.

## 2. Architecture

### 2.1 Rings

Code lives in rings. A crate depends only on a ring further in. `cargo xtask check-rings` checks the rule. The register `Documentation/Registers/RingDependencies.md` is the owner of the allowed edges.

| Ring | Holds | May know |
|---|---|---|
| `entities` | Plain data types: algorithm identifiers, sizes, key and ciphertext containers, the error type | Nothing |
| `domain` | The interface for each capability, and the logic that uses the interfaces | Entities |
| `sharedComponents` | Primitives that more than one family uses, such as SHA-3, SHA-2 and AES | Entities, other shared components |
| `infrastructure` | Adapters for outside services, such as OS randomness, the test-only C oracle and the test support of the families | Entities, the interfaces that it implements, shared components, other infrastructure |
| `features` | One crate for each algorithm family | Entities, domain interfaces, shared components |
| `composition` | The facade crate. It is the only place that builds concrete objects and wires them. | Everything except tooling |
| `tooling` | Repository tools and test-only crates | Everything. No ring may depend on tooling. |

The project is a library. It has no UI ring. The facade crate is the composition root.

Exceptions to the general rule, each with its reason:

- `infrastructure` may use `sharedComponents`. The NIST KAT random generator is built on AES.
- `infrastructure` may use another infrastructure crate. The known-answer programs of the test support build on the known-answer random generators.
- `sharedComponents` may use another shared component. A primitive can build on another primitive.
- A `features` crate may use `infrastructure` in its tests only. The KAT random generator is the test double for randomness, and the test support runs the known-answer programs.

### 2.2 Placement

Ask these questions in order:

1. Does more than one crate need it? Put it in the innermost ring that both can reach.
2. Is it an algorithm rule? It goes in the family crate or in a shared component, and it is testable with no outside service.
3. Does it touch the OS, a file, the network or a foreign library? Then it is infrastructure, behind an interface that the domain owns.

### 2.3 Rules that hold everywhere

- One public type per file. The file has the name of the type.
- Each crate declares every crate that it uses, and builds and tests alone.
- No hidden global state. The composition root builds objects and passes them in. Write each exception where it is declared, with its reason.
- Required dependencies are arguments. Do not give them default values.
- Each crate below the composition ring builds without the standard library. It has a `std` feature, on by default, and its root says `#![cfg_attr(not(feature = "std"), no_std)]`. CI builds the workspace with `--no-default-features`. See `Documentation/Learnings/MutationTesting.md` for why `std` is on by default.
- Randomness, time, the file system and every other outside service are reached only through an interface. Tests use doubles. The one exception is the contract test of an adapter crate, which must call the real service to prove the adapter.
- When the same decision is written in two places, move it to one owner. Copies that agree today are still a finding.
- No new third-party dependency without the owner's approval. `Documentation/Registers/ApprovedDependencies.md` lists each approval, and `cargo xtask check-rings` rejects every other crate.
- `unsafe` code is forbidden, except in the files that `Documentation/Registers/UnsafeCode.md` lists, each with its reason. The workspace lint `unsafe_code` is `deny`, so each use also needs `#[allow(unsafe_code)]` at its site. `cargo xtask check-unsafe` rejects `unsafe` code in any other file.

## 3. API design and code style

The API of every crate follows the Swift API Design Guidelines. The project uses the Swift casing, not the Rust casing, so that one style reads the same in every port of liboqs.

### 3.1 API design

- Clarity at the point of use is the most important goal. Judge a name by the call site.
- Clarity is more important than brevity. Do not remove a word that the reader needs. Do not add a word that the reader does not need.
- Name each thing by its role, not by its type.
- A method with side effects reads as an imperative verb phrase. A method without side effects reads as a noun phrase.
- A mutating method and its non-mutating pair use matching names, such as `sort` and `sorted`.
- A boolean reads as an assertion about the thing, such as `isEmpty` or `hasPath`.
- A trait that names a capability ends in a word that says so, such as `KeyEncapsulating` or `RandomGenerating`. A trait that describes what something is reads as a noun.
- Give an argument a default value only when one value is correct in nearly every call. Never default a required collaborator.
- Document every public declaration with a one-sentence summary. Use a noun phrase for a thing and a verb phrase for an action.
- Use the same name for the same concept everywhere.
- Avoid abbreviations. Use an established term of art as it is.
- Make a declaration public only when another crate needs it.

### 3.2 Names and casing

- Types, traits and generic parameters: `UpperCamelCase`.
- Functions, methods, fields, variables, arguments, constants, statics and enumeration cases: `lowerCamelCase`. Swift writes a constant as `static let maximumSize`, so the project writes `const maximumSize`.
- Modules: `lowerCamelCase`. A module that holds one type has the name of the type with a lower-case first letter.
- Files: one public type per file, with the name of the type, such as `PublicKey.rs`. The module that holds it uses the `#[path]` attribute: `#[path = "PublicKey.rs"] mod publicKey;` and `pub use publicKey::PublicKey;`. See `Documentation/Learnings/SwiftCasingInRust.md` for the reason.
- Library names, as code sees them in `[lib] name`: `UpperCamelCase`, such as `OQSNative` and `OQSNativeEntities`, after the Swift module `OQS`.
- Acronyms: one unit, all upper case or all lower case, such as `MLKEM768`, `userID` and `kemName`. `Documentation/Registers/Acronyms.md` lists the acronyms.
- No `snake_case`, no `SCREAMING_CASE`, no `I` prefix, no `_` prefix and no `Impl` suffix.
- `cargo xtask check-names` checks these rules. `rustfmt.toml` sets the layout, so the formatter decides layout, not the reviewer.

The compiler warns about Swift casing by default. The workspace `[workspace.lints]` table turns off `non_snake_case`, `non_upper_case_globals`, `non_camel_case_types` and `clippy::upper_case_acronyms`. The names stay as they are.

### 3.3 Forced forms

Where the language, a registry or a framework forces another form, use the forced form and nothing more.

- Package names in `Cargo.toml` are registry identifiers: lower case words with hyphens, such as `oqs-native-entities`. Code never sees them, because `[lib] name` sets the code name.
- Cargo fixes the names `Cargo.toml`, `build.rs`, `src/lib.rs`, `src/main.rs`, `src/`, `tests/` and `benches/`.
- Command-line words of the repository tool, such as `check-rings`, are words that a person types, not code names.
- A name inside an `extern` block is the name of the foreign symbol.
- A method that a standard library trait calls by name, such as `from_str`, keeps that name. `Documentation/Registers/NamingExceptions.md` lists each one.

## 4. Testing

- Every crate has its own tests, and the whole suite is the gate.
- Every feature, every seam and every complete data flow has three kinds of test:
  - success: the correct result, from a known answer where one exists,
  - failure: each rejection path, with the specific error,
  - fuzz: seeded random and hostile input, which must give a defined error or a correct result and never a panic.
- Each test that decides between accept and reject proves both sides:
  - false positive validation: a known-bad input is rejected,
  - false negative validation: a known-good input is accepted.
- Interleaving proves that an assertion is honest. Run each new assertion once against deliberately wrong code and see it fail, then against the real code and see it pass.
- Mutation proves that the test is connected. Run `cargo mutants` on each changed crate. Each surviving mutant is a finding: add a test, or record in `Documentation/Registers/MutationResults.md` why the mutant is equivalent. Record the named test that kills each mutant of a rule.
- Coverage is a floor. A test that cannot fail proves nothing.
- Follow each value that crosses a crate boundary with an end-to-end test. Compare the value on the other side with an expected result written by hand or taken from an independent source, such as the C oracle or the liboqs KAT files. Do not compare it with a value read from the same code.
- Every random input comes from a seeded generator. The test prints the seed.
- Waits in tests are bounded. A hang fails with the name of what hung.
- A test name says what the test proves.
- A flaky test is a defect. Find the cause and fix it. Do not run it again, skip it or let it pass.

### 4.1 Parity with the C library

- Each algorithm runs against the C oracle at the same version. The base case seeds the NIST KAT random generator with the bytes `0` to `47` and signs the message `the quick brown fox`, the same scheme as the Swift and Zig ports. The snapshot file of each version is comparable line by line with theirs.
- Each algorithm also runs 1000 seeded variations: random seeds, message lengths and context strings. For each variation the C and Rust outputs are byte-identical, each side accepts the output of the other, and both sides reject the same tampered input.
- Each test in the liboqs `tests/` folder has a Rust test that replicates it. The Rust test name names the upstream file.

## 5. Documentation and prose

- Plans, specs, drafts and brainstorming never live in this repository. The repository holds code, its tests, its documentation and its README.
- Never write an absolute path, a user name or a computer name into a file. Use paths relative to the repository root.
- Write short, plain sentences in simplified technical English. One topic for each paragraph. Use the same word for the same thing every time.
- Do not use a semicolon in prose. Do not use an em-dash anywhere.
- Use a numbered list for steps whose order matters and a bullet list for steps whose order does not.
- Code comments say why or what, not what changed.
- Documentation describes the code as it is. Do not write a page for a feature that does not exist.
- `cargo xtask check-hygiene` checks the em-dash, absolute path and semicolon rules. It also rejects a list of forbidden words that it reads from outside the repository.

## 6. Repository hygiene

Everything that lands on the host reads as written by the human engineer: commits, branch names, pull request text, issues, release notes and files.

- Do not name an assistant, a model, a plan, a spec or an internal tool.
- No co-author trailer for an automated tool. No generated-by footer.
- Read every message back before you send it.

## 7. Branches and pull requests

- `release` is the default branch. It holds what the owner merged and tested. Every pull request targets `release`, except the work of a larger series.
- `develop` is cut from `release`. It carries a larger series of work. Only that series, and work that comes from it, targets `develop`. The pull requests of a series stack on each other, and the first one targets `develop`.
- When pull requests merge into `release`, merge `release` into `develop`, build everything and run the full suite once before the next series pull request goes up.
- Merge `release` into an open branch before its mutation run, never after.
- When the series is done and tested, the owner merges `develop` into `release`.
- Only the owner merges. Nobody approves their own pull request. Nobody bypasses or changes branch protection.
- Each pull request:
  - changes one concern and keeps behavior the same unless the change is the behavior,
  - leaves the whole workspace building and the whole suite green,
  - passes `cargo fmt --check`, `cargo clippy --workspace --all-targets` and `cargo xtask check`,
  - adds the register rows, Architecture pages and Learnings entries for the code that it changes.
- Branch names are plain words that say what the work is, such as `foundation/workspace` or `family/ml-kem`.
