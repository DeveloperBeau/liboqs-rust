use std::io;
use std::path::{Path, PathBuf};

/// A source of repository files, so that the checks never touch the disk directly.
pub trait FileReading {
    /// Returns the text of the file at a path relative to the repository root.
    fn text(&self, path: &Path) -> io::Result<String>;

    /// Returns the path of every file in the repository, relative to the root, in sorted order.
    ///
    /// Files that git ignores are not part of the repository and are not in the list.
    fn filePaths(&self) -> io::Result<Vec<PathBuf>>;
}
