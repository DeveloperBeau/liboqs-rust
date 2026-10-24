use crate::FileReading;
use crate::Finding;
use crate::MarkdownTable;
use crate::RustTokenizer;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Checks that `unsafe` code appears only in the files that the unsafe code register lists, and
/// that each listed file still holds `unsafe` code.
#[derive(Debug)]
pub struct UnsafeCodeCheck {
    allowedFiles: BTreeSet<PathBuf>,
}

impl UnsafeCodeCheck {
    /// The name of the check in each finding.
    pub const name: &'static str = "unsafe";
    /// The register of the files that may hold `unsafe` code, each with its reason.
    pub const registerPath: &'static str = "Documentation/Registers/UnsafeCode.md";

    /// Reads the allowed files from the register.
    pub fn load(files: &dyn FileReading) -> Result<Self, Finding> {
        let registerPath = Path::new(Self::registerPath);
        let registerFinding = |message: String| Finding::new(Self::name, registerPath, 0, message);
        let text = files
            .text(registerPath)
            .map_err(|error| registerFinding(error.to_string()))?;
        let table = MarkdownTable::firstTable(&text)
            .ok_or_else(|| registerFinding("the register has no table".to_string()))?;
        let column = table
            .column("File")
            .ok_or_else(|| registerFinding("the register has no column File".to_string()))?;
        let allowedFiles = column
            .into_iter()
            .map(|cell| PathBuf::from(cell.trim_matches('`')))
            .collect();
        Ok(UnsafeCodeCheck { allowedFiles })
    }

    /// Returns a finding for each file with `unsafe` code outside the register, and for each
    /// register row whose file has no `unsafe` code.
    pub fn findings(&self, files: &dyn FileReading) -> Vec<Finding> {
        let filePaths = match files.filePaths() {
            Ok(paths) => paths,
            Err(error) => {
                return vec![Finding::new(
                    Self::name,
                    Path::new("."),
                    0,
                    error.to_string(),
                )];
            }
        };
        let mut findings = Vec::new();
        let mut filesWithUnsafeCode = BTreeSet::new();
        for path in filePaths
            .iter()
            .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        {
            let Ok(source) = files.text(path) else {
                continue;
            };
            let firstUnsafe = RustTokenizer::tokens(&source)
                .into_iter()
                .find(|token| token.isWord("unsafe"));
            if let Some(token) = firstUnsafe {
                filesWithUnsafeCode.insert(path.clone());
                if !self.allowedFiles.contains(path) {
                    findings.push(Finding::new(
                        Self::name,
                        path,
                        token.line,
                        "`unsafe` code in a file that the unsafe code register does not list",
                    ));
                }
            }
        }
        for allowed in self.allowedFiles.difference(&filesWithUnsafeCode) {
            findings.push(Finding::new(
                Self::name,
                Path::new(Self::registerPath),
                0,
                format!(
                    "the register lists `{}`, which has no `unsafe` code",
                    allowed.display()
                ),
            ));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::UnsafeCodeCheck;
    use crate::MemoryFileSystem;

    const register: &str =
        "| File | Reason |\n|---|---|\n| `Modules/A/src/Wipe.rs` | volatile writes |\n";

    fn messages(files: &[(&str, &str)]) -> Vec<String> {
        let mut repository = MemoryFileSystem::withFiles(files);
        repository.add(UnsafeCodeCheck::registerPath, register);
        let check = UnsafeCodeCheck::load(&repository).expect("register");
        check
            .findings(&repository)
            .into_iter()
            .map(|finding| finding.to_string())
            .collect()
    }

    #[test]
    fn unsafeCodeInARegisteredFileHasNoFinding() {
        assert!(messages(&[("Modules/A/src/Wipe.rs", "fn w() { unsafe { x() } }\n")]).is_empty());
    }

    #[test]
    fn unsafeCodeInAnotherFileIsAFindingAtItsLine() {
        assert_eq!(
            messages(&[
                ("Modules/A/src/Wipe.rs", "fn w() { unsafe { x() } }\n"),
                ("Modules/B/src/Other.rs", "fn a() {}\nunsafe fn b() {}\n"),
            ]),
            vec![
                "Modules/B/src/Other.rs:2: [unsafe] `unsafe` code in a file that the unsafe code register does not list"
            ]
        );
    }

    #[test]
    fn unsafeInACommentStringOrRawIdentifierIsNotCode() {
        let source = "// unsafe here\nlet text = \"unsafe\";\nlet r#unsafe = 1;\n#[allow(unsafe_code)]\nfn a() {}\n";
        assert_eq!(
            messages(&[
                ("Modules/A/src/Wipe.rs", "unsafe fn w() {}\n"),
                ("Modules/B/src/Clean.rs", source)
            ]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn registeredFileWithoutUnsafeCodeIsAStaleRow() {
        assert_eq!(
            messages(&[("Modules/A/src/Wipe.rs", "fn w() {}\n")]),
            vec![
                "Documentation/Registers/UnsafeCode.md:0: [unsafe] the register lists `Modules/A/src/Wipe.rs`, which has no `unsafe` code"
            ]
        );
    }

    #[test]
    fn loadFailsWithoutTheRegisterOrItsColumn() {
        let missing = MemoryFileSystem::withFiles(&[]);
        assert!(UnsafeCodeCheck::load(&missing).is_err());
        let wrongColumn = MemoryFileSystem::withFiles(&[(
            UnsafeCodeCheck::registerPath,
            "| Path |\n|---|\n| a |\n",
        )]);
        assert!(
            UnsafeCodeCheck::load(&wrongColumn)
                .expect_err("column")
                .message
                .contains("File")
        );
    }
}
