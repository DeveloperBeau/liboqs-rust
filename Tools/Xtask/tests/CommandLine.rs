//! Runs the built `xtask` binary, the composition root, the way a person runs it.
//!
//! These tests use only commands that end before the tool reads the repository, so they give
//! the same result in any copy of the source tree.

use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Runs the tool and waits at most 30 seconds, so a hang fails with a name.
fn runTool(arguments: &[&str]) -> Output {
    let child = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(arguments)
        .env_remove("HYGIENE_WORDS")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the xtask binary starts");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("the xtask binary did not end within 30 seconds")
        .expect("the xtask binary gives its output")
}

#[test]
fn unknownCommandExitsWithStatusTwoAndPrintsTheUsage() {
    let output = runTool(&["build"]);
    assert_eq!(output.status.code(), Some(2));
    let standardError = String::from_utf8_lossy(&output.stderr);
    assert!(
        standardError.starts_with("unknown command `build`\n\nusage: cargo xtask <command>\n"),
        "{standardError}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn missingCommandExitsWithStatusTwo() {
    let output = runTool(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("no command\n"));
}
