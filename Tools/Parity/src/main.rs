//! The `parity` program: the full parity gate of the port with the C library.
//!
//! The commands run in release builds, for example
//! `cargo run --release -p oqs-native-parity -- run --processes 4`. The program is the
//! composition root of the gate: it hands the registry to `ParityJob` and prints the lines.

use OQSNative::Registry;
use OQSNativeParity::{ParityJob, ParityOptions, Snapshot};
use std::process::ExitCode;

const usage: &str = "usage: parity <command> [options]

commands:
  run            check each registered algorithm against the C library: the base case and the
                 variations. A stateful scheme runs after the others, and its variations are the
                 signatures of one key, at most its remaining count. A stateful set with a tree
                 of height 20 or more runs only with --large-trees
  snapshot       print the snapshot of the C library, in the format of the Swift and Zig ports
  known-answers  run the liboqs known-answer programs on the C algorithms through the Rust
                 harness and on the registered Rust algorithms, and compare each digest with
                 the digest of liboqs

options:
  --cases N      the variations of each algorithm (run, default 1000)
  --seed S       the seed of the variations (run)
  --shard I/N    check only the jobs at positions I, I + N, I + 2N and so on. A job is an
                 algorithm, or a block of its variations with --block-size
  --block-size N split the variations of each algorithm into blocks of N, which the shards
                 and the processes split (run). The first block also checks the base case
  --only NAME    check only the named algorithm (repeatable)
  --all          also compare the digests of every count (known-answers)
  --check        compare each digest with the frozen snapshot and print no snapshot (snapshot)
  --large-trees  also check the stateful sets with a tree of height 20 or more, whose key
                 generation takes from minutes to a day (run). Without it the run prints a
                 skip line that names each of them
  --processes N  run the command in N processes, which split the jobs of the shard, and
                 fail when one fails. The C library has one global random source, so one
                 process runs one C operation at a time, and more processes use more
                 processors.";

/// The frozen snapshot of the version in `LIBOQS_VERSION`, which is the crate version.
const frozenSnapshot: &str =
    include_str!(concat!("../Snapshots/", env!("CARGO_PKG_VERSION"), ".txt"));

fn printLine(line: String) {
    println!("{line}");
}

fn run(options: &ParityOptions) -> usize {
    let jobs = ParityJob::registryParityJobs(options);
    let skippedLines = ParityJob::skippedLines(Registry::statefulSignatureSchemes(), options);
    let algorithmCount = jobs
        .iter()
        .map(|job| job.name)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let blocks = match options.settings.blockSize {
        Some(size) => format!(" in blocks of {size}"),
        None => String::new(),
    };
    println!(
        "parity of {algorithmCount} algorithms, {} variations each{blocks}, seed {:#x}",
        options.settings.caseCount, options.settings.seed
    );
    for line in skippedLines {
        println!("{line}");
    }
    ParityJob::runAll(jobs, &printLine)
}

fn knownAnswers(options: &ParityOptions) -> usize {
    let jobs = ParityJob::knownAnswerJobs(
        Registry::mechanisms(),
        Registry::signatureSchemes(),
        Registry::statefulSignatureSchemes(),
        options,
    );
    println!(
        "known answers of {} C algorithms and their registered Rust algorithms",
        jobs.len()
    );
    ParityJob::runAll(jobs, &printLine)
}

fn snapshot(options: &ParityOptions) -> usize {
    let (snapshot, failures) = ParityJob::cSnapshot(options);
    if !options.isCheck {
        for failure in &failures {
            eprintln!("{failure}");
        }
        print!("{}", snapshot.text());
        return failures.len();
    }
    let frozen = Snapshot::parse(frozenSnapshot).expect("the frozen snapshot is well formed");
    let (lines, failureCount) = ParityJob::snapshotCheck(&snapshot, &failures, &frozen);
    for line in lines {
        println!("{line}");
    }
    failureCount
}

/// Runs the program again in the processes of `--processes`, with the same command and
/// options, and fails when one process fails.
fn runInProcesses(command: &str, arguments: &[String], options: &ParityOptions) -> ExitCode {
    let program = std::env::current_exe().expect("the path of the program");
    let children: Vec<_> = ParityOptions::processArguments(arguments, options)
        .into_iter()
        .map(|childArguments| {
            std::process::Command::new(&program)
                .arg(command)
                .args(childArguments)
                .spawn()
                .expect("start a shard process")
        })
        .collect();
    let failedCount = children
        .into_iter()
        .map(|mut child| child.wait().expect("wait for a shard process"))
        .filter(|status| !status.success())
        .count();
    if failedCount == 0 {
        ExitCode::SUCCESS
    } else {
        eprintln!("{failedCount} shard process(es) failed");
        ExitCode::FAILURE
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some((commandWord, rest)) = arguments.split_first() else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let options = match ParityOptions::parse(rest) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}\n\n{usage}");
            return ExitCode::from(2);
        }
    };
    let command: fn(&ParityOptions) -> usize = match commandWord.as_str() {
        "run" => run,
        "snapshot" => snapshot,
        "known-answers" => knownAnswers,
        unknown => {
            eprintln!("unknown command `{unknown}`\n\n{usage}");
            return ExitCode::from(2);
        }
    };
    if options.processCount.is_some() {
        return runInProcesses(commandWord, rest, &options);
    }
    let failures = command(&options);
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        eprintln!("{failures} failure(s)");
        ExitCode::FAILURE
    }
}
