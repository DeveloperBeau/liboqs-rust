//! The contract test of the `DiskFileSystem` adapter.
//!
//! This is the one test that writes to the disk and runs git, because an adapter of an outside
//! service can be proved only against that service. Each test makes its own git repository in
//! a temporary folder, and the folder is deleted when the test ends, also when it fails.

use RepositoryTools::{DiskFileSystem, FileReading};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

/// A git repository in a temporary folder that is deleted when the value is dropped.
struct TemporaryRepository {
    root: PathBuf,
}

impl TemporaryRepository {
    fn new(name: &str, isGitRepository: bool) -> Self {
        let root =
            std::env::temp_dir().join(format!("xtaskContract-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the temporary folder is made");
        if isGitRepository {
            git(&root, &["init", "--quiet"]);
        }
        TemporaryRepository { root }
    }

    fn write(&self, path: &str, text: &str) {
        let fullPath = self.root.join(path);
        fs::create_dir_all(fullPath.parent().expect("a file has a folder"))
            .expect("the folder is made");
        fs::write(fullPath, text).expect("the file is written");
    }

    fn files(&self) -> DiskFileSystem {
        DiskFileSystem::new(self.root.clone())
    }
}

impl Drop for TemporaryRepository {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Runs a test body on its own thread and fails with the test name when the body takes more
/// than 30 seconds, so a git command that hangs fails with a name.
fn withinDeadline(name: &'static str, body: impl FnOnce() + Send + 'static) {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        body();
        let _ = sender.send(());
    });
    match receiver.recv_timeout(Duration::from_secs(30)) {
        Ok(()) => {}
        Err(RecvTimeoutError::Timeout) => panic!("{name} did not end within 30 seconds"),
        Err(RecvTimeoutError::Disconnected) => panic!("{name} failed, see the panic above"),
    }
}

fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {arguments:?} failed");
}

#[test]
fn filePathsListTrackedAndNewFilesButNotIgnoredExcludedOrDeletedFiles() {
    withinDeadline(
        "filePathsListTrackedAndNewFilesButNotIgnoredExcludedOrDeletedFiles",
        || {
            let repository = TemporaryRepository::new("filePaths", true);
            repository.write(".gitignore", "/target\n");
            repository.write("Cargo.toml", "[workspace]\n");
            repository.write("gone.txt", "deleted later\n");
            git(&repository.root, &["add", "Cargo.toml", "gone.txt"]);
            fs::remove_file(repository.root.join("gone.txt")).expect("the file is deleted");
            repository.write("src/A.rs", "fn a() {}\n");
            repository.write("target/build.txt", "ignored\n");
            repository.write(".git/info/exclude", "local.md\n");
            repository.write("local.md", "excluded\n");
            let paths = repository.files().filePaths().expect("git lists the files");
            let expected: Vec<PathBuf> = [".gitignore", "Cargo.toml", "src/A.rs"]
                .iter()
                .map(PathBuf::from)
                .collect();
            assert_eq!(paths, expected);
        },
    );
}

#[test]
fn filePathsFailOutsideAGitRepository() {
    withinDeadline("filePathsFailOutsideAGitRepository", || {
        let folder = TemporaryRepository::new("noGit", false);
        folder.write("Cargo.toml", "[workspace]\n");
        assert!(folder.files().filePaths().is_err());
    });
}

#[test]
fn textReadsAFileAndFailsForAMissingFile() {
    withinDeadline("textReadsAFileAndFailsForAMissingFile", || {
        let repository = TemporaryRepository::new("text", true);
        repository.write("Folder/Notes.md", "first line\nsecond line\n");
        let files = repository.files();
        assert_eq!(
            files
                .text(Path::new("Folder/Notes.md"))
                .expect("the file is read"),
            "first line\nsecond line\n"
        );
        assert!(files.text(Path::new("Folder/Missing.md")).is_err());
    });
}

#[test]
fn localGitFileTextReadsTheGitFolderAndIsNoneWithoutTheFile() {
    withinDeadline(
        "localGitFileTextReadsTheGitFolderAndIsNoneWithoutTheFile",
        || {
            let repository = TemporaryRepository::new("localGitFile", true);
            repository.write(".git/info/hygiene-words", "alpha\nbeta\n");
            let files = repository.files();
            assert_eq!(
                files.localGitFileText("info/hygiene-words").as_deref(),
                Some("alpha\nbeta\n")
            );
            assert_eq!(files.localGitFileText("info/missing"), None);
            let folder = TemporaryRepository::new("localGitFileNoGit", false);
            assert_eq!(folder.files().localGitFileText("info/hygiene-words"), None);
        },
    );
}
