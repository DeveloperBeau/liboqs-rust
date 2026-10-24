//! Repository tools for the native liboqs port: the checks of rings, names, versions, hygiene
//! and unsafe code, and the build of the C oracle.
//!
//! Each check reads its rule list from a register in `Documentation/Registers`, so that the
//! register is the one owner of the rule. The tools read files through `FileReading` and run
//! programs through `ProcessRunning`, so that tests run against `MemoryFileSystem` and
//! `RecordingProcesses` and never touch the disk. `main.rs` is the composition root: it builds
//! `DiskFileSystem` and `SystemProcesses` and calls `run`.

#[path = "CargoManifest.rs"]
mod cargoManifest;
#[path = "Command.rs"]
mod command;
#[path = "Declaration.rs"]
mod declaration;
#[path = "DeclarationKind.rs"]
mod declarationKind;
#[path = "DeclarationScanner.rs"]
mod declarationScanner;
#[path = "Dependency.rs"]
mod dependency;
#[path = "DependencyKind.rs"]
mod dependencyKind;
#[path = "DiskFileSystem.rs"]
mod diskFileSystem;
#[path = "FileReading.rs"]
mod fileReading;
#[path = "Finding.rs"]
mod finding;
#[path = "HygieneCheck.rs"]
mod hygieneCheck;
#[path = "IdentifierCasing.rs"]
mod identifierCasing;
#[path = "MarkdownTable.rs"]
mod markdownTable;
#[path = "MemberCrate.rs"]
mod memberCrate;
#[path = "NamingCheck.rs"]
mod namingCheck;
#[path = "OracleBuild.rs"]
mod oracleBuild;
#[path = "ProcessRunning.rs"]
mod processRunning;
#[path = "ProcessStep.rs"]
mod processStep;
#[path = "Report.rs"]
mod report;
#[path = "RingCheck.rs"]
mod ringCheck;
#[path = "RustToken.rs"]
mod rustToken;
#[path = "RustTokenKind.rs"]
mod rustTokenKind;
#[path = "RustTokenizer.rs"]
mod rustTokenizer;
#[path = "SystemProcesses.rs"]
mod systemProcesses;
#[path = "TokenTree.rs"]
mod tokenTree;
#[path = "UnsafeCodeCheck.rs"]
mod unsafeCodeCheck;
#[path = "VersionCheck.rs"]
mod versionCheck;
#[path = "WorkspaceLayout.rs"]
mod workspaceLayout;

#[cfg(test)]
#[path = "MemoryFileSystem.rs"]
mod memoryFileSystem;
#[cfg(test)]
#[path = "RecordingProcesses.rs"]
mod recordingProcesses;
#[cfg(test)]
#[path = "RepositoryFixtureTests.rs"]
mod repositoryFixtureTests;
#[cfg(test)]
#[path = "SeededGenerator.rs"]
mod seededGenerator;

use cargoManifest::CargoManifest;
use command::Command;
use declaration::Declaration;
use declarationKind::DeclarationKind;
use declarationScanner::DeclarationScanner;
use dependency::Dependency;
use dependencyKind::DependencyKind;
pub use diskFileSystem::DiskFileSystem;
pub use fileReading::FileReading;
use finding::Finding;
use hygieneCheck::HygieneCheck;
use markdownTable::MarkdownTable;
use memberCrate::MemberCrate;
#[cfg(test)]
use memoryFileSystem::MemoryFileSystem;
use namingCheck::NamingCheck;
use oracleBuild::OracleBuild;
pub use processRunning::ProcessRunning;
pub use processStep::ProcessStep;
#[cfg(test)]
use recordingProcesses::RecordingProcesses;
pub use report::Report;
use ringCheck::RingCheck;
use rustToken::RustToken;
use rustTokenKind::RustTokenKind;
use rustTokenizer::RustTokenizer;
#[cfg(test)]
use seededGenerator::SeededGenerator;
pub use systemProcesses::SystemProcesses;
use tokenTree::TokenTree;
use unsafeCodeCheck::UnsafeCodeCheck;
use versionCheck::VersionCheck;
use workspaceLayout::WorkspaceLayout;

/// Runs the repository tool for command-line arguments, without the program name.
///
/// The forbidden words for the hygiene check come from two places outside the repository:
/// the comma-separated value of the `HYGIENE_WORDS` variable, and else the lines of the local
/// word file. Each is `None` when it does not exist. Only `fetch-oracle` runs programs.
pub fn run(
    arguments: &[String],
    files: &dyn FileReading,
    environmentWords: Option<&str>,
    localWords: Option<&str>,
    processes: &mut dyn ProcessRunning,
) -> Report {
    let command = match Command::parse(arguments) {
        Ok(command) => command,
        Err(message) => {
            return Report {
                standardOutput: String::new(),
                standardError: format!("{message}\n\n{}\n", Command::usage),
                exitStatus: 2,
            };
        }
    };
    if command == Command::fetchOracle {
        return fetchOracle(files, processes);
    }
    let words = HygieneCheck::forbiddenWords(environmentWords, localWords);
    let mut standardError = String::new();
    if words.is_empty() && command.includes(Command::hygiene) {
        standardError.push_str(
            "note: no forbidden word list (HYGIENE_WORDS or .git/info/hygiene-words), so the word scan did not run\n",
        );
    }
    let findings = findings(command, files, words);
    let mut standardOutput: String = findings
        .iter()
        .map(|finding| format!("{finding}\n"))
        .collect();
    if findings.is_empty() {
        standardOutput.push_str("all checks passed\n");
    } else {
        standardError.push_str(&format!("{} finding(s)\n", findings.len()));
    }
    Report {
        standardOutput,
        standardError,
        exitStatus: u8::from(!findings.is_empty()),
    }
}

/// Runs the steps of the oracle build for the version in `LIBOQS_VERSION`, and stops at the
/// first step that fails.
fn fetchOracle(files: &dyn FileReading, processes: &mut dyn ProcessRunning) -> Report {
    let failure = |standardOutput: String, message: String| Report {
        standardOutput,
        standardError: format!("{message}\n"),
        exitStatus: 1,
    };
    let version = match files.text(std::path::Path::new("LIBOQS_VERSION")) {
        Ok(text) => text.trim().to_string(),
        Err(error) => {
            return failure(
                String::new(),
                format!("LIBOQS_VERSION cannot be read: {error}"),
            );
        }
    };
    let build = OracleBuild::new(&version);
    let steps = match build.steps(files) {
        Ok(steps) => steps,
        Err(message) => return failure(String::new(), message),
    };
    let mut standardOutput = String::new();
    for step in &steps {
        if let Err(message) = processes.run(step) {
            return failure(standardOutput, message);
        }
        standardOutput.push_str(&format!("ran {step}\n"));
    }
    standardOutput.push_str(&format!(
        "the C oracle {version} is ready in {}\n",
        build.folder().display()
    ));
    Report {
        standardOutput,
        standardError: String::new(),
        exitStatus: 0,
    }
}

/// Runs the checks of a command on a repository and returns every finding in path order.
///
/// A register that cannot be read is itself a finding, so a broken register never passes.
fn findings(
    command: Command,
    files: &dyn FileReading,
    forbiddenWords: Vec<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let layout = match WorkspaceLayout::load(files) {
        Ok(layout) => Some(layout),
        Err(finding) => {
            findings.push(finding);
            None
        }
    };
    if let Some(layout) = &layout {
        if command.includes(Command::rings) {
            match RingCheck::load(files) {
                Ok(check) => findings.extend(check.findings(layout)),
                Err(finding) => findings.push(finding),
            }
        }
        if command.includes(Command::names) {
            match NamingCheck::load(files) {
                Ok(check) => findings.extend(check.findings(files, layout)),
                Err(finding) => findings.push(finding),
            }
        }
        if command.includes(Command::versions) {
            findings.extend(VersionCheck::findings(files, layout));
        }
    }
    if command.includes(Command::unsafeCode) {
        match UnsafeCodeCheck::load(files) {
            Ok(check) => findings.extend(check.findings(files)),
            Err(finding) => findings.push(finding),
        }
    }
    if command.includes(Command::hygiene) {
        findings.extend(HygieneCheck::new(forbiddenWords).findings(files));
    }
    findings.sort();
    findings
}
