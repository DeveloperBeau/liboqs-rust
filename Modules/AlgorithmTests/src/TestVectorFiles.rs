use crate::JSONValue;
use alloc::format;
use alloc::string::String;
use std::path::PathBuf;

/// The test vector files that `cargo xtask fetch-oracle` downloads, in the folder `vectors` of
/// the oracle folder.
///
/// The oracle folder is the folder of `OQS_ORACLE_DIR`, or else `target/oracle/<version>` in
/// the workspace. `Documentation/Registers/TestVectors.md` lists the files.
pub struct TestVectorFiles;

impl TestVectorFiles {
    /// The vector folder.
    pub fn folder() -> PathBuf {
        let oracleFolder = match std::env::var_os("OQS_ORACLE_DIR") {
            Some(folder) => PathBuf::from(folder),
            None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/oracle")
                .join(env!("CARGO_PKG_VERSION")),
        };
        oracleFolder.join("vectors")
    }

    /// The parsed document of a vector file. A missing file is an error that names the command
    /// that downloads it.
    pub fn document(fileName: &str) -> Result<JSONValue, String> {
        let path = Self::folder().join(fileName);
        let text = std::fs::read_to_string(&path).map_err(|error| {
            format!(
                "the test vector file {} cannot be read ({error}). Run `cargo xtask fetch-oracle` first.",
                path.display()
            )
        })?;
        JSONValue::parse(&text).map_err(|error| format!("{fileName}: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::TestVectorFiles;
    use std::path::PathBuf;

    #[test]
    fn folderIsTheVectorFolderOfTheOracleFolder() {
        let expected = match std::env::var_os("OQS_ORACLE_DIR") {
            Some(folder) => PathBuf::from(folder),
            None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/oracle")
                .join(env!("CARGO_PKG_VERSION")),
        };
        assert_eq!(TestVectorFiles::folder(), expected.join("vectors"));
    }

    #[test]
    fn aMissingFileIsAnErrorThatNamesTheDownloadCommand() {
        let message = TestVectorFiles::document("no-such-file.json").expect_err("no such file");
        assert!(message.contains("no-such-file.json"), "{message}");
        assert!(
            message.ends_with("Run `cargo xtask fetch-oracle` first."),
            "{message}"
        );
    }
}
