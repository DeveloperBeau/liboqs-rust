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

    /// Returns the path that a path relative to the repository root names when every link in
    /// it is resolved, for a program that records the paths that it is given.
    ///
    /// The end of the path that does not exist yet stays as it is, after the resolved start.
    fn resolvedPath(&self, path: &Path) -> PathBuf;
}
