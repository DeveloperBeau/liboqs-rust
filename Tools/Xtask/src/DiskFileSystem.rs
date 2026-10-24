use crate::FileReading;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository on disk, with its file list taken from git.
pub struct DiskFileSystem {
    root: PathBuf,
}

impl DiskFileSystem {
    /// Makes a file source for the repository at a root folder.
    pub fn new(root: PathBuf) -> Self {
        DiskFileSystem { root }
    }
}

impl DiskFileSystem {
    /// Returns the text of a file in the git folder of the repository, such as
    /// `info/hygiene-words`, or `None` when the file or the git folder does not exist.
    ///
    /// A worktree reads the git folder that it shares with its clone.
    pub fn localGitFileText(&self, relativePath: &str) -> Option<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
            .output()
            .ok()
            .filter(|output| output.status.success())?;
        let folder = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        std::fs::read_to_string(folder.join(relativePath)).ok()
    }
}

impl FileReading for DiskFileSystem {
    fn text(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(self.root.join(path))
    }

    fn filePaths(&self) -> io::Result<Vec<PathBuf>> {
        // Tracked files and new files that git does not ignore, so a check sees a file before
        // its first commit and never sees a local excluded file.
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args([
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("git ls-files failed"));
        }
        let mut paths: Vec<PathBuf> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| PathBuf::from(String::from_utf8_lossy(entry).into_owned()))
            .filter(|path| self.root.join(path).is_file())
            .collect();
        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    fn resolvedPath(&self, path: &Path) -> PathBuf {
        // The longest start of the path that exists is resolved, so a folder that a later step
        // makes still resolves through a link above it.
        let fullPath = self.root.join(path);
        let mut existing = fullPath.as_path();
        let mut missingParts = Vec::new();
        loop {
            if let Ok(resolved) = existing.canonicalize() {
                return missingParts
                    .iter()
                    .rev()
                    .fold(resolved, |folder, part| folder.join(part));
            }
            match (existing.parent(), existing.file_name()) {
                (Some(parent), Some(part)) => {
                    missingParts.push(part);
                    existing = parent;
                }
                _ => return fullPath,
            }
        }
    }
}
