use std::fmt;
use std::path::{Path, PathBuf};

/// A rule violation at one place in the repository.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The file that holds the violation, relative to the repository root.
    pub path: PathBuf,
    /// The line of the violation, or zero when the rule applies to the whole file.
    pub line: usize,
    /// The name of the check that found the violation.
    pub check: &'static str,
    /// What is wrong, in one sentence.
    pub message: String,
}

impl Finding {
    /// Makes a finding for a check at a line of a file.
    pub fn new(check: &'static str, path: &Path, line: usize, message: impl Into<String>) -> Self {
        Finding {
            path: path.to_path_buf(),
            line,
            check,
            message: message.into(),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}: [{}] {}",
            self.path.display(),
            self.line,
            self.check,
            self.message
        )
    }
}
