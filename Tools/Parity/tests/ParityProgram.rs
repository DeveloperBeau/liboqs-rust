//! Runs the built `parity` program, the composition root of the gate, the way a person runs it.

use OQSNativeAlgorithmTests::SuiteSample;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Runs the program and waits at most 120 seconds, so a hang fails with a name.
fn runProgram(arguments: &[&str]) -> Output {
    runProgramWithin(arguments, Duration::from_secs(120))
}

/// Runs the program and waits at most a time, so a hang fails with a name.
fn runProgramWithin(arguments: &[&str], bound: Duration) -> Output {
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
        .recv_timeout(bound)
        .unwrap_or_else(|_| panic!("the parity program did not end within {bound:?}"))
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
        text.starts_with("known answers of 1 C algorithms and their registered Rust algorithms\n"),
        "{text}"
    );
    assert!(
        text.contains("ok    ML-KEM-768 (single, C and Rust, "),
        "{text}"
    );
}

#[test]
fn knownAnswersOfStatefulSchemesReadTheirResponseFiles() {
    let output = runProgram(&[
        "known-answers",
        "--only",
        "XMSS-SHA2_10_256",
        "--only",
        "LMS_SHA256_H5_W1",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = standardOutput(&output);
    assert!(
        text.contains("ok    XMSS-SHA2_10_256 (response file, C and Rust, "),
        "{text}"
    );
    assert!(
        text.contains("ok    LMS_SHA256_H5_W1 (response file, C, "),
        "{text}"
    );
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
fn runInBlocksReportsEachBlockOfAnAlgorithm() {
    let output = runProgram(&[
        "run",
        "--cases",
        "3",
        "--block-size",
        "2",
        "--seed",
        "5",
        "--only",
        "ML-KEM-512",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = standardOutput(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        "parity of 1 algorithms, 3 variations each in blocks of 2, seed 0x5"
    );
    let mut blocks: Vec<&str> = lines[1..].to_vec();
    blocks.sort();
    assert_eq!(blocks.len(), 2, "{text}");
    assert!(
        blocks[0].starts_with("ok    ML-KEM-512 (base case and variations 0 to 1 identical, "),
        "{text}"
    );
    assert!(
        blocks[1].starts_with("ok    ML-KEM-512 (variations 2 to 2 identical, "),
        "{text}"
    );
}

#[test]
fn runOverTheSuiteSampleOfTheRegistryReportsItsSizeAndEachAlgorithm() {
    // A run over the whole registry takes an hour since SLH-DSA, so the program runs the
    // registered algorithms of the suite sample.
    let names: Vec<&str> = OQSNative::Registry::mechanisms()
        .iter()
        .map(|mechanism| mechanism.description().name)
        .chain(
            OQSNative::Registry::signatureSchemes()
                .iter()
                .map(|scheme| scheme.description().name),
        )
        .chain(
            OQSNative::Registry::statefulSignatureSchemes()
                .iter()
                .map(|scheme| scheme.description().name),
        )
        .filter(|name| SuiteSample::contains(name))
        .collect();
    let mut arguments = vec!["run", "--cases", "2", "--seed", "5"];
    for name in &names {
        arguments.extend(["--only", name]);
    }
    // Each stateful set of the sample makes a key pair on each side, with up to six trees of
    // height 10 for the XMSS^MT sets of 60/6, so the run takes minutes in a test build.
    let output = runProgramWithin(&arguments, Duration::from_secs(1200));
    assert_eq!(output.status.code(), Some(0));
    let text = standardOutput(&output);
    assert!(
        text.starts_with(&format!(
            "parity of {} algorithms, 2 variations each, seed 0x5\n",
            names.len()
        )),
        "{text}"
    );
    for name in &names {
        assert!(
            text.contains(&format!(
                "ok    {name} (base case and 2 variations identical, "
            )),
            "{text}"
        );
    }
}
