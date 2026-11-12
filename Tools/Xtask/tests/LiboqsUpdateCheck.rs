//! Runs `Tools/check-liboqs-update.sh` with a stub `gh` on `PATH`.
//!
//! The comparisons also call `version_is_newer` directly. The seed of that run is printed.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

struct Outcome {
    status: i32,
    standardOutput: String,
    standardError: String,
    ghLog: String,
}

struct Run {
    directory: PathBuf,
}

impl Run {
    fn new(version: Option<&str>) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "liboqs-update-{}-{}",
            std::process::id(),
            nextToken()
        ));
        fs::create_dir_all(directory.join("Tools/bin")).expect("the temporary tools folder");
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../check-liboqs-update.sh");
        fs::copy(script, directory.join("Tools/check-liboqs-update.sh"))
            .expect("the script copies");
        if let Some(version) = version {
            fs::write(directory.join("LIBOQS_VERSION"), version).expect("the version file");
        }
        let stub = include_str!("gh-stub.sh");
        let stubPath = directory.join("Tools/bin/gh");
        fs::write(&stubPath, stub).expect("the stub gh");
        let mut permissions = fs::metadata(&stubPath)
            .expect("the stub metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&stubPath, permissions).expect("the stub is executable");
        Run { directory }
    }

    fn execute(&self, tag: &str, mode: &str, rows: &str) -> Outcome {
        fs::write(self.directory.join("rows.tsv"), rows).expect("the issue rows");
        let script = self.directory.join("Tools/check-liboqs-update.sh");
        let path = format!(
            "{}:{}",
            self.directory.join("Tools/bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let child = Command::new("bash")
            .arg(&script)
            .env("PATH", &path)
            .env("GH_LOG", self.directory.join("gh.log"))
            .env("STUB_TAG", tag)
            .env("STUB_MODE", mode)
            .env("STUB_ROWS", self.directory.join("rows.tsv"))
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .env_remove("GITHUB_REPOSITORY")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("bash starts the check");
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(child.wait_with_output());
        });
        let output = receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("the check did not end within 30 seconds")
            .expect("the check gives its output");
        let ghLog = fs::read_to_string(self.directory.join("gh.log")).unwrap_or_default();
        Outcome {
            status: output.status.code().unwrap_or(127),
            standardOutput: String::from_utf8_lossy(&output.stdout).into_owned(),
            standardError: String::from_utf8_lossy(&output.stderr).into_owned(),
            ghLog,
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn nextToken() -> u64 {
    static token: AtomicU64 = AtomicU64::new(1);
    token.fetch_add(1, Ordering::Relaxed)
}

fn run(version: Option<&str>, tag: &str, mode: &str, rows: &str) -> Outcome {
    Run::new(version).execute(tag, mode, rows)
}

fn created(outcome: &Outcome) -> bool {
    outcome
        .ghLog
        .lines()
        .any(|line| line.starts_with("issue create"))
}

fn edited(outcome: &Outcome) -> Vec<String> {
    outcome
        .ghLog
        .lines()
        .filter(|line| line.starts_with("issue edit"))
        .map(str::to_string)
        .collect()
}

const actionsAuthor: &str = "app/github-actions";

fn row(number: &str, state: &str, title: &str, author: &str) -> String {
    format!("{number}\t{state}\t{title}\t{author}\n")
}

#[test]
fn equalPinPrintsCurrentAndCreatesNothing() {
    let outcome = run(Some("0.16.0\n"), "v0.16.0", "ok", "");
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert_eq!(outcome.standardOutput, "liboqs 0.16.0 is current\n");
    assert!(!created(&outcome));
}

#[test]
fn newerReleaseCreatesOneIssue() {
    let outcome = run(Some("0.16.0\n"), "v0.17.0", "ok", "");
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(created(&outcome), "{}", outcome.ghLog);
    assert!(
        outcome
            .ghLog
            .contains("liboqs 0.17.0 is available (pinned 0.16.0)"),
        "{}",
        outcome.ghLog
    );
}

#[test]
fn olderReleasePrintsThatThePinIsNewer() {
    let outcome = run(Some("0.16.0\n"), "0.9.0", "ok", "");
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert_eq!(
        outcome.standardOutput,
        "pinned liboqs 0.16.0 is newer than the latest release 0.9.0\n"
    );
    assert!(!created(&outcome));
}

#[test]
fn largerMinorNumberIsNewer() {
    let outcome = run(Some("0.16.0\n"), "0.100.0", "ok", "");
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(
        outcome
            .ghLog
            .contains("liboqs 0.100.0 is available (pinned 0.16.0)"),
        "{}",
        outcome.ghLog
    );
}

#[test]
fn apiFailureExitsWithStatusOne() {
    let outcome = run(Some("0.16.0\n"), "", "api-fail", "");
    assert_eq!(outcome.status, 1);
    assert!(outcome.standardError.contains("the GitHub API call"));
    assert!(!created(&outcome));
}

#[test]
fn listFailureExitsWithStatusOne() {
    let outcome = run(Some("0.16.0\n"), "v0.17.0", "list-fail", "");
    assert_eq!(outcome.status, 1, "{}", outcome.standardError);
    assert!(
        outcome
            .standardError
            .contains("the call to list issues failed")
    );
    assert!(!created(&outcome));
}

#[test]
fn editFailureExitsWithStatusOne() {
    let rows = row(
        "4",
        "OPEN",
        "liboqs 0.17.0 is available (pinned 0.16.0)",
        actionsAuthor,
    );
    let outcome = run(Some("0.16.0\n"), "v0.18.0", "edit-fail", &rows);
    assert_eq!(outcome.status, 1, "{}", outcome.standardError);
    assert!(
        outcome
            .standardError
            .contains("the call to update the open liboqs issue failed")
    );
    assert!(!created(&outcome));
}

#[test]
fn releaseCandidateTagExitsWithStatusOne() {
    let outcome = run(Some("0.16.0\n"), "v0.17.0-rc1", "ok", "");
    assert_eq!(outcome.status, 1, "{}", outcome.standardOutput);
    assert!(outcome.standardError.contains("not a numeric version"));
}

#[test]
fn emptyTagExitsWithStatusOne() {
    let outcome = run(Some("0.16.0\n"), "", "ok", "");
    assert_eq!(outcome.status, 1);
    assert!(outcome.standardError.contains("empty tag"));
}

#[test]
fn nullTagExitsWithStatusOne() {
    let outcome = run(Some("0.16.0\n"), "null", "ok", "");
    assert_eq!(outcome.status, 1);
    assert!(outcome.standardError.contains("not a numeric version"));
}

#[test]
fn missingVersionFileExitsWithStatusOne() {
    let outcome = run(None, "v0.17.0", "ok", "");
    assert_eq!(outcome.status, 1);
    assert!(outcome.standardError.contains("LIBOQS_VERSION is missing"));
    assert!(outcome.ghLog.is_empty(), "{}", outcome.ghLog);
}

#[test]
fn nonNumericVersionFileExitsWithStatusOne() {
    let outcome = run(Some("nope\n"), "v0.17.0", "ok", "");
    assert_eq!(outcome.status, 1);
    assert!(outcome.standardError.contains("not a numeric version"));
}

#[test]
fn openExactBotTitleDoesNotCreateOrEdit() {
    let rows = row(
        "7",
        "OPEN",
        "liboqs 0.17.0 is available (pinned 0.16.0)",
        actionsAuthor,
    );
    let outcome = run(Some("0.16.0\n"), "v0.17.0", "ok", &rows);
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(
        outcome
            .standardOutput
            .contains("an open issue already has the title")
    );
    assert!(!created(&outcome));
    assert!(edited(&outcome).is_empty(), "{:?}", edited(&outcome));
}

#[test]
fn closedExactBotTitleDoesNotCreate() {
    let rows = row(
        "8",
        "CLOSED",
        "liboqs 0.17.0 is available (pinned 0.16.0)",
        "github-actions[bot]",
    );
    let outcome = run(Some("0.16.0\n"), "v0.17.0", "ok", &rows);
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(
        outcome
            .standardOutput
            .contains("a closed issue already has the title")
    );
    assert!(!created(&outcome), "{}", outcome.ghLog);
    assert!(edited(&outcome).is_empty());
}

#[test]
fn openOlderBotIssueIsEdited() {
    let rows = row(
        "4",
        "OPEN",
        "liboqs 0.17.0 is available (pinned 0.16.0)",
        "github-actions",
    );
    let outcome = run(Some("0.16.0\n"), "v0.18.0", "ok", &rows);
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(!created(&outcome), "{}", outcome.ghLog);
    let edits = edited(&outcome);
    assert_eq!(edits.len(), 1, "{edits:?}");
    assert!(edits[0].contains("issue edit 4"), "{}", edits[0]);
    assert!(
        edits[0].contains("liboqs 0.18.0 is available (pinned 0.16.0)"),
        "{}",
        edits[0]
    );
}

#[test]
fn humanIssueIsNotEdited() {
    let older = row(
        "12",
        "OPEN",
        "liboqs 0.17.0 is available (pinned 0.16.0)",
        "monalisa",
    );
    let outcome = run(Some("0.16.0\n"), "v0.18.0", "ok", &older);
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(created(&outcome), "{}", outcome.ghLog);
    assert!(edited(&outcome).is_empty(), "{:?}", edited(&outcome));

    let exact = row(
        "12",
        "OPEN",
        "liboqs 0.17.0 is available (pinned 0.16.0)",
        "monalisa",
    );
    let outcome = run(Some("0.16.0\n"), "v0.17.0", "ok", &exact);
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(created(&outcome), "{}", outcome.ghLog);
    assert!(
        !outcome
            .standardOutput
            .contains("an open issue already has the title")
    );
    assert!(edited(&outcome).is_empty(), "{:?}", edited(&outcome));
}

#[test]
fn missingAuthorIsNotOurs() {
    let rows = row(
        "3",
        "OPEN",
        "liboqs 0.17.0 is available (pinned 0.16.0)",
        "",
    );
    let outcome = run(Some("0.16.0\n"), "v0.18.0", "ok", &rows);
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(created(&outcome), "{}", outcome.ghLog);
    assert!(edited(&outcome).is_empty(), "{:?}", edited(&outcome));
}

#[test]
fn nullAuthorIsNotOurs() {
    let rows = row(
        "3",
        "OPEN",
        "liboqs 0.17.0 is available (pinned 0.16.0)",
        "null",
    );
    let outcome = run(Some("0.16.0\n"), "v0.18.0", "ok", &rows);
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(created(&outcome));
    assert!(edited(&outcome).is_empty(), "{:?}", edited(&outcome));
}

#[test]
fn valueEqualTagPrintsCurrent() {
    for tag in ["v0.16", "v0.16.0.0", "v0.16.00", "00.16.0"] {
        let outcome = run(Some("0.16.0\n"), tag, "ok", "");
        assert_eq!(outcome.status, 0, "{tag}: {}", outcome.standardError);
        assert_eq!(
            outcome.standardOutput, "liboqs 0.16.0 is current\n",
            "{tag}"
        );
        assert!(!created(&outcome), "{tag}: {}", outcome.ghLog);
    }
}

#[test]
fn wildcardPinTitleIsNotEdited() {
    let rows = row(
        "9",
        "OPEN",
        "liboqs 0.17.0 is available (pinned 0x16y0)",
        actionsAuthor,
    );
    let outcome = run(Some("0.16.0\n"), "v0.18.0", "ok", &rows);
    assert_eq!(outcome.status, 0, "{}", outcome.standardError);
    assert!(created(&outcome), "{}", outcome.ghLog);
    assert!(edited(&outcome).is_empty(), "{:?}", edited(&outcome));
}

#[test]
fn versionIsNewerMatchesIntegerTuples() {
    let seed: u64 = 0x160A_1107;
    println!("seed {seed}");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../check-liboqs-update.sh");
    let mut pairs = vec![
        (vec![0, 16], vec![0, 16, 0]),
        (vec![0, 16, 0], vec![0, 16, 0, 0]),
        (vec![0, 16, 0], vec![0, 16, 0]),
        (vec![0, 8], vec![0, 8]),
        (vec![0, 8], vec![0, 10]),
        (vec![0, 9, 0], vec![0, 10, 0]),
        (vec![0, 100, 0], vec![0, 16, 0]),
    ];
    let mut state = seed;
    for _ in 0..200 {
        pairs.push((randomParts(&mut state), randomParts(&mut state)));
    }
    let mut input = String::new();
    for (left, right) in &pairs {
        pushPair(&mut input, left, right, &mut state);
        pushPair(&mut input, right, left, &mut state);
    }
    let mut child = Command::new("bash")
        .arg("-c")
        .arg(
            "source \"$1\"\n\
while IFS=$'\\t' read -r left right expect; do\n\
  got=not\n\
  if version_is_newer \"$left\" \"$right\"; then got=newer; fi\n\
  if [[ \"$got\" != \"$expect\" ]]; then\n\
    echo \"mismatch $left vs $right expected $expect got $got\" >&2\n\
    exit 1\n\
  fi\n\
done\n",
        )
        .arg("bash")
        .arg(&script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("bash starts the comparison");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("the pairs are written");
    let output = child.wait_with_output().expect("the comparison ends");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn randomParts(state: &mut u64) -> Vec<u32> {
    let count = (nextNumber(state) % 4) + 1;
    (0..count).map(|_| nextNumber(state) % 41).collect()
}

fn nextNumber(state: &mut u64) -> u32 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    (*state >> 33) as u32
}

fn tupleIsNewer(left: &[u32], right: &[u32]) -> bool {
    let count = left.len().max(right.len());
    for index in 0..count {
        let leftPart = left.get(index).copied().unwrap_or(0);
        let rightPart = right.get(index).copied().unwrap_or(0);
        if leftPart > rightPart {
            return true;
        }
        if leftPart < rightPart {
            return false;
        }
    }
    false
}

fn pushPair(input: &mut String, left: &[u32], right: &[u32], state: &mut u64) {
    let expect = if tupleIsNewer(left, right) {
        "newer"
    } else {
        "not"
    };
    input.push_str(&displayParts(left, state));
    input.push('\t');
    input.push_str(&displayParts(right, state));
    input.push('\t');
    input.push_str(expect);
    input.push('\n');
}

fn displayParts(parts: &[u32], state: &mut u64) -> String {
    parts
        .iter()
        .map(|part| {
            if nextNumber(state).is_multiple_of(3) {
                format!("{part:03}")
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}
