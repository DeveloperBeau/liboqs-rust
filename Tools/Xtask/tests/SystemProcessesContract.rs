//! Contract tests of `SystemProcesses`: the adapter must run real programs, so these tests call
//! the operating system.

use RepositoryTools::{ProcessRunning, ProcessStep, SystemProcesses};

fn runner() -> SystemProcesses {
    SystemProcesses::new(std::env::temp_dir())
}

#[test]
fn aProgramThatSucceedsIsOk() {
    assert_eq!(
        runner().run(&ProcessStep::new("sh", &["-c", "exit 0"])),
        Ok(())
    );
}

#[test]
fn aProgramThatFailsIsAnErrorWithItsStatus() {
    let result = runner().run(&ProcessStep::new("sh", &["-c", "exit 3"]));
    assert_eq!(
        result,
        Err("`sh -c exit 3` failed with exit status: 3".to_string())
    );
}

#[test]
fn aMissingProgramIsAnErrorThatNamesTheStep() {
    let result = runner().run(&ProcessStep::new("no-such-program-of-the-port", &[]));
    let message = result.expect_err("a missing program fails");
    assert!(
        message.starts_with("`no-such-program-of-the-port` did not start:"),
        "{message}"
    );
}

#[test]
fn theProgramRunsInTheFolderOfTheRunner() {
    let folder = std::env::temp_dir();
    let marker = format!("oqs-native-runner-{}", std::process::id());
    let mut processes = SystemProcesses::new(folder.clone());
    processes
        .run(&ProcessStep::new("sh", &["-c", &format!("touch {marker}")]))
        .expect("touch runs");
    let path = folder.join(&marker);
    assert!(path.exists());
    std::fs::remove_file(path).expect("remove the marker");
}
