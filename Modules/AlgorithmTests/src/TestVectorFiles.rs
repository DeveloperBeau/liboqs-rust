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
    /// The oracle folder: the folder of `OQS_ORACLE_DIR`, or else `target/oracle/<version>`.
    fn oracleFolder() -> PathBuf {
        match std::env::var_os("OQS_ORACLE_DIR") {
            Some(folder) => PathBuf::from(folder),
            None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/oracle")
                .join(env!("CARGO_PKG_VERSION")),
        }
    }

    /// The vector folder.
    pub fn folder() -> PathBuf {
        Self::oracleFolder().join("vectors")
    }

    /// The path of the response file of a stateful scheme in the liboqs source of the oracle,
    /// `tests/KATs/sig_stfl/<family>/<name>.rsp`, with each `/` of the name written as `-`.
    pub fn responseFilePath(algorithm: &str) -> PathBuf {
        let family = if algorithm.starts_with("LMS") {
            "lms"
        } else {
            "xmss"
        };
        Self::oracleFolder()
            .join("source/tests/KATs/sig_stfl")
            .join(family)
            .join(format!("{}.rsp", algorithm.replace('/', "-")))
    }

    /// The text of the response file of a stateful scheme. A missing file is an error that
    /// names the command that downloads the liboqs source.
    pub fn responseFile(algorithm: &str) -> Result<String, String> {
        let path = Self::responseFilePath(algorithm);
        std::fs::read_to_string(&path).map_err(|error| {
            format!(
                "the response file {} cannot be read ({error}). Run `cargo xtask fetch-oracle` first.",
                path.display()
            )
        })
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
    fn responseFilesAreInTheLiboqsSourceWithADashForEachSlash() {
        let source = TestVectorFiles::folder()
            .parent()
            .expect("the oracle folder")
            .join("source/tests/KATs/sig_stfl");
        assert_eq!(
            TestVectorFiles::responseFilePath("XMSSMT-SHA2_20/2_256"),
            source.join("xmss/XMSSMT-SHA2_20-2_256.rsp")
        );
        assert_eq!(
            TestVectorFiles::responseFilePath("LMS_SHA256_H5_W1"),
            source.join("lms/LMS_SHA256_H5_W1.rsp")
        );
        let message = TestVectorFiles::responseFile("XMSS-NONE_0_0").expect_err("no such file");
        assert!(message.contains("XMSS-NONE_0_0.rsp"), "{message}");
        assert!(
            message.ends_with("Run `cargo xtask fetch-oracle` first."),
            "{message}"
        );
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
