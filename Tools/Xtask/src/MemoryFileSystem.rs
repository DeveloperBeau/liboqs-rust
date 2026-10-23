use crate::FileReading;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// A repository held in memory, the test double for `DiskFileSystem`.
#[derive(Default)]
pub struct MemoryFileSystem {
    files: BTreeMap<PathBuf, String>,
}

impl MemoryFileSystem {
    /// Makes a repository that holds each file of a list of path and text pairs.
    pub fn withFiles(files: &[(&str, &str)]) -> Self {
        let mut repository = MemoryFileSystem::default();
        for (path, text) in files {
            repository.add(path, text);
        }
        repository
    }

    /// Adds a file, or replaces the text of a file at the same path.
    pub fn add(&mut self, path: &str, text: &str) {
        self.files.insert(PathBuf::from(path), text.to_string());
    }
}

impl FileReading for MemoryFileSystem {
    fn text(&self, path: &Path) -> io::Result<String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.display().to_string()))
    }

    fn filePaths(&self) -> io::Result<Vec<PathBuf>> {
        Ok(self.files.keys().cloned().collect())
    }
}
