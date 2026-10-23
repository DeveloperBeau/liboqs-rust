//! The `cargo xtask` command: the composition root of the repository tools.

use RepositoryTools::{DiskFileSystem, SystemProcesses};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = root.canonicalize().unwrap_or(root);
    let files = DiskFileSystem::new(root.clone());
    let mut processes = SystemProcesses::new(root);
    let environmentWords = std::env::var("HYGIENE_WORDS").ok();
    let localWords = files.localGitFileText("info/hygiene-words");
    let report = RepositoryTools::run(
        &arguments,
        &files,
        environmentWords.as_deref(),
        localWords.as_deref(),
        &mut processes,
    );
    print!("{}", report.standardOutput);
    eprint!("{}", report.standardError);
    ExitCode::from(report.exitStatus)
}
