use crate::{FileReading, MarkdownTable};
use OQSNativeSHA2::SHA256;
use std::path::{Path, PathBuf};

/// One file of test vectors of `Documentation/Registers/TestVectors.md`: its name, its
/// download address and its SHA-256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestVector {
    /// The name of the file in the vector folder.
    pub fileName: String,
    /// The address that the file comes from.
    pub address: String,
    /// The SHA-256 of the file in lower-case hexadecimal.
    pub digest: String,
}

impl TestVector {
    /// The register of the test vector files.
    pub const registerPath: &'static str = "Documentation/Registers/TestVectors.md";

    /// Reads every row of the register.
    pub fn load(files: &dyn FileReading) -> Result<Vec<TestVector>, String> {
        let text = files
            .text(Path::new(Self::registerPath))
            .map_err(|error| format!("{} cannot be read: {error}", Self::registerPath))?;
        let table = MarkdownTable::firstTable(&text)
            .ok_or_else(|| format!("{} has no table", Self::registerPath))?;
        let column = |header: &str| {
            table
                .column(header)
                .ok_or_else(|| format!("{} has no column `{header}`", Self::registerPath))
        };
        let fileNames = column("File")?;
        let addresses = column("Address")?;
        let digests = column("SHA-256")?;
        Ok(fileNames
            .iter()
            .zip(addresses)
            .zip(digests)
            .map(|((fileName, address), digest)| TestVector {
                fileName: fileName.trim_matches('`').to_string(),
                address: address.to_string(),
                digest: digest.trim_matches('`').to_string(),
            })
            .collect())
    }

    /// The path of the file in a vector folder.
    pub fn path(&self, folder: &Path) -> PathBuf {
        folder.join(&self.fileName)
    }

    /// The SHA-256 of the file in a vector folder, or `None` when it cannot be read.
    pub fn digestOfFile(&self, files: &dyn FileReading, folder: &Path) -> Option<String> {
        let text = files.text(&self.path(folder)).ok()?;
        Some(
            SHA256::hash(text.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        )
    }

    /// True when the file in a vector folder has the SHA-256 of the register.
    pub fn isPresent(&self, files: &dyn FileReading, folder: &Path) -> bool {
        self.digestOfFile(files, folder).as_deref() == Some(self.digest.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::TestVector;
    use crate::MemoryFileSystem;
    use std::path::Path;

    const register: &str = "# Test vectors\n\n| File | Address | SHA-256 | Source |\n|---|---|---|---|\n| `a.json` | https://example.org/a | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | test |\n| `b.json` | https://example.org/b | `00` | test |\n";

    #[test]
    fn loadReadsEachRowOfTheRegister() {
        let files = MemoryFileSystem::withFiles(&[(TestVector::registerPath, register)]);
        let vectors = TestVector::load(&files).expect("the register");
        assert_eq!(
            vectors[0],
            TestVector {
                fileName: "a.json".to_string(),
                address: "https://example.org/a".to_string(),
                digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    .to_string(),
            }
        );
        assert_eq!(vectors.len(), 2);
    }

    #[test]
    fn aMissingRegisterOrColumnIsAnError() {
        assert!(TestVector::load(&MemoryFileSystem::withFiles(&[])).is_err());
        let withoutDigests = "| File | Address |\n|---|---|\n| `a` | b |\n";
        assert_eq!(
            TestVector::load(&MemoryFileSystem::withFiles(&[(
                TestVector::registerPath,
                withoutDigests
            )])),
            Err(format!(
                "{} has no column `SHA-256`",
                TestVector::registerPath
            ))
        );
        assert_eq!(
            TestVector::load(&MemoryFileSystem::withFiles(&[(
                TestVector::registerPath,
                "no table\n"
            )])),
            Err(format!("{} has no table", TestVector::registerPath))
        );
    }

    #[test]
    fn aFileIsPresentOnlyWithTheDigestOfTheRegister() {
        let files = MemoryFileSystem::withFiles(&[
            (TestVector::registerPath, register),
            ("vectors/a.json", "abc"),
            ("vectors/b.json", "abc"),
        ]);
        let vectors = TestVector::load(&files).expect("the register");
        let folder = Path::new("vectors");
        assert!(vectors[0].isPresent(&files, folder));
        assert!(!vectors[1].isPresent(&files, folder));
        assert!(!vectors[0].isPresent(&files, Path::new("elsewhere")));
        assert_eq!(
            vectors[1].digestOfFile(&files, Path::new("elsewhere")),
            None
        );
    }
}
