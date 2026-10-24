//! Runs the built `parity` program, the composition root of the gate, the way a person runs it.

use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Runs the program and waits at most 120 seconds, so a hang fails with a name.
fn runProgram(arguments: &[&str]) -> Output {
    let child = Command::new(env!("CARGO_BIN_EXE_parity"))
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the parity program starts");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    receiver
        .recv_timeout(Duration::from_secs(120))
        .expect("the parity program did not end within 120 seconds")
        .expect("the parity program gives its output")
}

fn standardOutput(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn wrongCommandsAndOptionsExitWithStatusTwoAndThePrintedUsage() {
    for arguments in [
        vec![],
        vec!["build"],
        vec!["run", "--fast"],
        vec!["run", "--cases"],
    ] {
        let output = runProgram(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        let standardError = String::from_utf8_lossy(&output.stderr);
        assert!(
            standardError.contains("usage: parity <command> [options]"),
            "{standardError}"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn knownAnswersOfOneAlgorithmPassWithItsLine() {
    let output = runProgram(&["known-answers", "--only", "ML-KEM-768"]);
    assert_eq!(output.status.code(), Some(0));
    let text = standardOutput(&output);
    assert!(
        text.starts_with("known answers of 1 C algorithms through the Rust harness\n"),
        "{text}"
    );
    assert!(text.contains("ok    ML-KEM-768 (single, "), "{text}");
}

#[test]
fn processesSplitTheRunAndAllOfThemReport() {
    let output = runProgram(&[
        "known-answers",
        "--only",
        "ML-KEM-512",
        "--only",
        "ML-DSA-44",
        "--processes",
        "2",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = standardOutput(&output);
    assert!(text.contains("ok    ML-KEM-512 (single, "), "{text}");
    assert!(text.contains("ok    ML-DSA-44 (single, "), "{text}");
    assert_eq!(text.matches("known answers of ").count(), 2, "{text}");
}

#[test]
fn snapshotPrintsTheFrozenLineAndTheCheckConfirmsIt() {
    let frozen = include_str!(concat!("../Snapshots/", env!("CARGO_PKG_VERSION"), ".txt"));
    let expected = frozen
        .lines()
        .find(|line| line.starts_with("ML-KEM-512 "))
        .expect("a frozen line");
    let printed = runProgram(&["snapshot", "--only", "ML-KEM-512"]);
    assert_eq!(printed.status.code(), Some(0));
    assert_eq!(standardOutput(&printed), format!("{expected}\n"));
    let checked = runProgram(&["snapshot", "--check", "--only", "ML-DSA-44"]);
    assert_eq!(checked.status.code(), Some(0));
    assert_eq!(
        standardOutput(&checked),
        "ok    ML-DSA-44 matches the frozen snapshot\n"
    );
}

#[test]
fn runOverTheRegistryReportsItsSize() {
    let output = runProgram(&["run", "--cases", "2", "--seed", "5"]);
    assert_eq!(output.status.code(), Some(0));
    let text = standardOutput(&output);
    assert!(
        text.starts_with(&format!(
            "parity of {} algorithms, 2 variations each, seed 0x5\n",
            OQSNative::Registry::mechanisms().len() + OQSNative::Registry::signatureSchemes().len()
        )),
        "{text}"
    );
}
