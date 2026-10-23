//! End-to-end tests: a whole repository in memory goes through `findings`, and the result is
//! compared with findings written by hand.

use crate::Command;
use crate::MemoryFileSystem;
use crate::RingCheck;
use crate::WorkspaceLayout;
use crate::findings;

const ringRegister: &str = include_str!("../../../Documentation/Registers/RingDependencies.md");
const approvedRegister: &str =
    include_str!("../../../Documentation/Registers/ApprovedDependencies.md");
const acronymRegister: &str = include_str!("../../../Documentation/Registers/Acronyms.md");
const exceptionRegister: &str =
    include_str!("../../../Documentation/Registers/NamingExceptions.md");

fn cleanRepository() -> MemoryFileSystem {
    MemoryFileSystem::withFiles(&[
        ("LIBOQS_VERSION", "0.16.0\n"),
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"Modules/*\"]\n\n[workspace.package]\nversion = \"0.16.0\"\n",
        ),
        ("Documentation/Registers/RingDependencies.md", ringRegister),
        (
            "Documentation/Registers/ApprovedDependencies.md",
            approvedRegister,
        ),
        ("Documentation/Registers/Acronyms.md", acronymRegister),
        (
            "Documentation/Registers/NamingExceptions.md",
            exceptionRegister,
        ),
        (
            "Modules/Entities/Cargo.toml",
            "[package]\nname = \"oqs-native-entities\"\nversion.workspace = true\n\n[package.metadata]\nring = \"entities\"\n\n[lib]\nname = \"OQSNativeEntities\"\n",
        ),
        (
            "Modules/Entities/src/lib.rs",
            "//! Entities.\n#[path = \"PublicKey.rs\"]\nmod publicKey;\n",
        ),
        (
            "Modules/Entities/src/PublicKey.rs",
            "/// A key.\npub struct PublicKey { keyBytes: Vec<u8> }\n",
        ),
        (
            "Modules/Domain/Cargo.toml",
            "[package]\nname = \"oqs-native-domain\"\nversion.workspace = true\n\n[package.metadata]\nring = \"domain\"\n\n[lib]\nname = \"OQSNativeDomain\"\n\n[dependencies]\noqs-native-entities = { path = \"../Entities\" }\n",
        ),
        (
            "Modules/Domain/src/lib.rs",
            "//! Domain.\npub trait KeyEncapsulating { fn encapsulate(&self, publicKey: &[u8]); }\n",
        ),
        ("standards.md", "# Standards\n\nShort sentence.\n"),
    ])
}

#[test]
fn cleanRepositoryPassesEveryCheck() {
    let result = findings(
        Command::everyCheck,
        &cleanRepository(),
        vec!["zorblat".to_string()],
    );
    assert!(result.is_empty(), "{result:?}");
}

#[test]
fn everyCheckReportsItsBrokenRuleInPathOrder() {
    let mut files = cleanRepository();
    files.add(
        "Modules/Entities/Cargo.toml",
        "[package]\nname = \"oqs-native-entities\"\nversion = \"0.15.0\"\n\n[package.metadata]\nring = \"entities\"\n\n[lib]\nname = \"OQSNativeEntities\"\n\n[dependencies]\noqs-native-domain = { path = \"../Domain\" }\n",
    );
    files.add(
        "Modules/Domain/src/lib.rs",
        "//! Domain.\npub trait key_encapsulating {}\n",
    );
    files.add("standards.md", "# Standards\n\nOne; two.\n");
    let result: Vec<String> = findings(Command::everyCheck, &files, Vec::new())
        .into_iter()
        .map(|finding| finding.to_string())
        .collect();
    assert_eq!(
        result,
        vec![
            "Modules/Domain/src/lib.rs:2: [names] `key_encapsulating` must be UpperCamelCase",
            "Modules/Entities/Cargo.toml:0: [versions] the crate must use `version.workspace = true`",
            "Modules/Entities/Cargo.toml:12: [rings] ring `entities` may not depend on ring `domain` (`oqs-native-domain`)",
            "standards.md:3: [hygiene] prose must not use a semicolon",
        ]
    );
}

#[test]
fn oneCommandRunsOnlyItsCheck() {
    let mut files = cleanRepository();
    files.add("standards.md", "One; two.\n");
    files.add("LIBOQS_VERSION", "9.9.9\n");
    let hygieneOnly: Vec<&str> = findings(Command::hygiene, &files, Vec::new())
        .iter()
        .map(|finding| finding.check)
        .collect();
    assert_eq!(hygieneOnly, vec!["hygiene"]);
    let versionsOnly: Vec<&str> = findings(Command::versions, &files, Vec::new())
        .iter()
        .map(|finding| finding.check)
        .collect();
    assert_eq!(versionsOnly, vec!["versions"]);
}

#[test]
fn missingRegisterIsAFindingNotAPass() {
    let mut files = MemoryFileSystem::withFiles(&[("Cargo.toml", "[workspace]\nmembers = []\n")]);
    files.add("LIBOQS_VERSION", "0.16.0");
    let checks: Vec<&str> = findings(Command::rings, &files, Vec::new())
        .iter()
        .map(|finding| finding.check)
        .collect();
    assert_eq!(checks, vec!["rings"]);
}

/// The real ring register must give the same answer for every ring pair as the hand-written
/// table in the `RingCheck` tests. This ties the register to the rule in `standards.md`.
#[test]
fn realRingRegisterAllowsExactlyTheHandWrittenEdges() {
    let allowedByHand: &[(&str, &[&str], &[&str])] = &[
        ("entities", &[], &[]),
        ("domain", &["entities"], &[]),
        ("sharedComponents", &["entities", "sharedComponents"], &[]),
        (
            "infrastructure",
            &["entities", "domain", "sharedComponents"],
            &[],
        ),
        (
            "features",
            &["entities", "domain", "sharedComponents"],
            &["infrastructure"],
        ),
        (
            "composition",
            &[
                "entities",
                "domain",
                "sharedComponents",
                "infrastructure",
                "features",
            ],
            &[],
        ),
        (
            "tooling",
            &[
                "entities",
                "domain",
                "sharedComponents",
                "infrastructure",
                "features",
                "composition",
            ],
            &[],
        ),
    ];
    let rings: Vec<&str> = allowedByHand.iter().map(|(ring, _, _)| *ring).collect();
    for (from, inCode, inTestsOnly) in allowedByHand {
        for to in &rings {
            for isTest in [false, true] {
                let section = if isTest {
                    "dev-dependencies"
                } else {
                    "dependencies"
                };
                let files = MemoryFileSystem::withFiles(&[
                    ("Cargo.toml", "[workspace]\nmembers = [\"Modules/*\"]\n"),
                    (RingCheck::ringRegisterPath, ringRegister),
                    (RingCheck::approvedDependenciesPath, approvedRegister),
                    (
                        "Modules/A/Cargo.toml",
                        &format!(
                            "[package]\nname = \"a\"\n[package.metadata]\nring = \"{from}\"\n[{section}]\nb = {{ path = \"../B\" }}\n"
                        ),
                    ),
                    (
                        "Modules/B/Cargo.toml",
                        &format!("[package]\nname = \"b\"\n[package.metadata]\nring = \"{to}\"\n"),
                    ),
                ]);
                let layout = WorkspaceLayout::load(&files).expect("layout");
                let isReported = !RingCheck::load(&files)
                    .expect("registers")
                    .findings(&layout)
                    .is_empty();
                let isAllowed = inCode.contains(to) || (isTest && inTestsOnly.contains(to));
                assert_eq!(isReported, !isAllowed, "from {from} to {to}, test {isTest}");
            }
        }
    }
}

fn arguments(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| word.to_string()).collect()
}

#[test]
fn runPassesWithStatusZeroAndThePassLine() {
    let report = crate::run(
        &arguments(&["check"]),
        &cleanRepository(),
        Some("zorblat"),
        None,
    );
    assert_eq!(
        report,
        crate::Report {
            standardOutput: "all checks passed\n".to_string(),
            standardError: String::new(),
            exitStatus: 0,
        }
    );
}

#[test]
fn runReportsEachFindingWithStatusOneAndTheCount() {
    let mut files = cleanRepository();
    files.add("standards.md", "One; two.\nThree; four.\n");
    let report = crate::run(
        &arguments(&["check-hygiene"]),
        &files,
        None,
        Some("zorblat\n"),
    );
    assert_eq!(
        report,
        crate::Report {
            standardOutput: "standards.md:1: [hygiene] prose must not use a semicolon\nstandards.md:2: [hygiene] prose must not use a semicolon\n".to_string(),
            standardError: "2 finding(s)\n".to_string(),
            exitStatus: 1,
        }
    );
}

#[test]
fn runPrintsTheWordListNoteOnlyForAHygieneScanWithoutWords() {
    let note = "note: no forbidden word list (HYGIENE_WORDS or .git/info/hygiene-words), so the word scan did not run\n";
    let withoutWords = crate::run(
        &arguments(&["check-hygiene"]),
        &cleanRepository(),
        Some(""),
        None,
    );
    assert_eq!(withoutWords.standardError, note);
    assert_eq!(withoutWords.exitStatus, 0);
    let everyCheckWithoutWords = crate::run(&arguments(&["check"]), &cleanRepository(), None, None);
    assert_eq!(everyCheckWithoutWords.standardError, note);
    let ringsOnly = crate::run(&arguments(&["check-rings"]), &cleanRepository(), None, None);
    assert_eq!(ringsOnly.standardError, "");
    let withLocalWords = crate::run(
        &arguments(&["check-hygiene"]),
        &cleanRepository(),
        None,
        Some("zorblat"),
    );
    assert_eq!(withLocalWords.standardError, "");
}

#[test]
fn runUsesTheWordListToFindAForbiddenWord() {
    let mut files = cleanRepository();
    files.add("README.md", "A Zorblat line.\n");
    let report = crate::run(
        &arguments(&["check-hygiene"]),
        &files,
        Some("zorblat"),
        None,
    );
    assert_eq!(
        report.standardOutput,
        "README.md:1: [hygiene] the line holds the forbidden word `zorblat`\n"
    );
    assert_eq!(report.exitStatus, 1);
}

#[test]
fn runRejectsAWrongCommandWithStatusTwoAndTheUsage() {
    let report = crate::run(&arguments(&["build"]), &cleanRepository(), None, None);
    assert_eq!(report.exitStatus, 2);
    assert!(report.standardOutput.is_empty());
    assert_eq!(
        report.standardError,
        format!("unknown command `build`\n\n{}\n", crate::Command::usage)
    );
}
