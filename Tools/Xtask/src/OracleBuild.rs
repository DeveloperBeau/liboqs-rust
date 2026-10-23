use crate::{FileReading, ProcessStep, TestVector};
use std::path::{Path, PathBuf};

/// The build of the C oracle: liboqs at the version of the repository, built as a portable
/// static library in `target/oracle/<version>`, with the test vector files of the register.
///
/// The source goes to `source`, the build to `build` and the vector files to `vectors`. A
/// second run builds again, which CMake does in a few seconds when nothing changed, and
/// downloads only a vector file that is missing or that has another SHA-256.
pub struct OracleBuild {
    version: String,
}

impl OracleBuild {
    /// The repository of liboqs.
    pub const repositoryURL: &'static str = "https://github.com/open-quantum-safe/liboqs.git";

    /// The CMake options. The library is the portable C code of every algorithm, with no CPU
    /// extension and no OpenSSL, and with key generation and signing of the stateful schemes.
    pub const configurationOptions: [&'static str; 10] = [
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        "-DOQS_BUILD_ONLY_LIB=ON",
        "-DOQS_DIST_BUILD=OFF",
        "-DOQS_OPT_TARGET=generic",
        "-DOQS_USE_OPENSSL=OFF",
        "-DOQS_ENABLE_SIG_STFL_XMSS=ON",
        "-DOQS_ENABLE_SIG_STFL_LMS=ON",
        "-DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON",
    ];

    /// Makes the build of a liboqs version.
    pub fn new(version: &str) -> Self {
        OracleBuild {
            version: version.to_string(),
        }
    }

    /// The oracle folder, relative to the repository root.
    pub fn folder(&self) -> PathBuf {
        Path::new("target/oracle").join(&self.version)
    }

    /// The folder of the test vector files, relative to the repository root.
    pub fn vectorFolder(&self) -> PathBuf {
        self.folder().join("vectors")
    }

    /// The version that a liboqs `CMakeLists.txt` declares, such as `0.16.0`.
    pub fn declaredVersion(cmakeText: &str) -> Option<String> {
        let value = |name: &str| -> Option<String> {
            let prefix = format!("set({name} ");
            cmakeText.lines().find_map(|line| {
                let rest = line.trim().strip_prefix(&prefix)?.strip_suffix(')')?;
                Some(rest.trim_matches('"').to_string())
            })
        };
        Some(format!(
            "{}.{}.{}{}",
            value("OQS_VERSION_MAJOR")?,
            value("OQS_VERSION_MINOR")?,
            value("OQS_VERSION_PATCH")?,
            value("OQS_VERSION_PRE_RELEASE").unwrap_or_default()
        ))
    }

    /// The steps that make the oracle ready: the clone when the source is missing, then the
    /// configuration and the build, then a download of each vector file that is not present.
    ///
    /// A source of another version is an error, because the oracle must be the version of
    /// the repository.
    pub fn steps(&self, files: &dyn FileReading) -> Result<Vec<ProcessStep>, String> {
        let source = self.folder().join("source");
        let build = self.folder().join("build");
        let sourceText = source.to_string_lossy().to_string();
        let buildText = build.to_string_lossy().to_string();
        let mut steps = Vec::new();
        match files.text(&source.join("CMakeLists.txt")) {
            Ok(cmakeText) => {
                let declared = Self::declaredVersion(&cmakeText);
                if declared.as_deref() != Some(self.version.as_str()) {
                    return Err(format!(
                        "{sourceText} holds liboqs {}, not {}. Delete the folder and run the command again.",
                        declared.as_deref().unwrap_or("of an unknown version"),
                        self.version
                    ));
                }
            }
            Err(_) => steps.push(ProcessStep::new(
                "git",
                &[
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    &self.version,
                    Self::repositoryURL,
                    &sourceText,
                ],
            )),
        }
        let mut configure = vec!["-S", sourceText.as_str(), "-B", buildText.as_str()];
        configure.extend(Self::configurationOptions);
        steps.push(ProcessStep::new("cmake", &configure));
        steps.push(ProcessStep::new(
            "cmake",
            &["--build", &buildText, "--parallel"],
        ));
        let vectorFolder = self.vectorFolder();
        for vector in TestVector::load(files)? {
            if !vector.isPresent(files, &vectorFolder) {
                let path = vector.path(&vectorFolder).to_string_lossy().to_string();
                steps.push(ProcessStep::new(
                    "curl",
                    &[
                        "-fsSL",
                        "--retry",
                        "3",
                        "--create-dirs",
                        "-o",
                        &path,
                        &vector.address,
                    ],
                ));
            }
        }
        Ok(steps)
    }
}

#[cfg(test)]
mod tests {
    use super::OracleBuild;
    use crate::{MemoryFileSystem, TestVector};

    /// A register of two vector files, `a.json` with the text `abc` and `b.json`.
    const register: &str = "| File | Address | SHA-256 | Source |\n|---|---|---|---|\n| `a.json` | https://example.org/a | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | test |\n| `b.json` | https://example.org/b | `00` | test |\n";

    const cmakeLines: &str = "set(OQS_VERSION_MAJOR 0)\nset(OQS_VERSION_MINOR 16)\nset(OQS_VERSION_PATCH 0)\nset(OQS_VERSION_PRE_RELEASE \"\")\n";

    #[test]
    fn declaredVersionJoinsTheFourParts() {
        assert_eq!(
            OracleBuild::declaredVersion(cmakeLines),
            Some("0.16.0".to_string())
        );
        let preRelease = cmakeLines.replace("\"\"", "\"-rc1\"");
        assert_eq!(
            OracleBuild::declaredVersion(&preRelease),
            Some("0.16.0-rc1".to_string())
        );
        assert_eq!(
            OracleBuild::declaredVersion("set(OQS_VERSION_MAJOR 0)\n"),
            None
        );
    }

    #[test]
    fn missingSourceIsClonedAtTheVersionTagAndThenBuilt() {
        let steps = OracleBuild::new("0.16.0")
            .steps(&MemoryFileSystem::withFiles(&[(
                TestVector::registerPath,
                register,
            )]))
            .expect("steps");
        let lines: Vec<String> = steps.iter().map(|step| step.to_string()).collect();
        assert_eq!(
            lines[0],
            "git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git target/oracle/0.16.0/source"
        );
        assert!(lines[1].starts_with(
            "cmake -S target/oracle/0.16.0/source -B target/oracle/0.16.0/build -DCMAKE_BUILD_TYPE=Release"
        ));
        assert!(lines[1].ends_with("-DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON"));
        assert_eq!(
            lines[2],
            "cmake --build target/oracle/0.16.0/build --parallel"
        );
        assert_eq!(
            lines[3],
            "curl -fsSL --retry 3 --create-dirs -o target/oracle/0.16.0/vectors/a.json https://example.org/a"
        );
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn presentSourceOfTheVersionIsBuiltWithoutAClone() {
        let files = MemoryFileSystem::withFiles(&[
            ("target/oracle/0.16.0/source/CMakeLists.txt", cmakeLines),
            (TestVector::registerPath, register),
            ("target/oracle/0.16.0/vectors/a.json", "abc"),
        ]);
        let steps = OracleBuild::new("0.16.0").steps(&files).expect("steps");
        // The vector file with the right digest is not downloaded again, the other one is.
        let programs: Vec<&str> = steps.iter().map(|step| step.program.as_str()).collect();
        assert_eq!(programs, vec!["cmake", "cmake", "curl"]);
        assert!(steps[2].to_string().ends_with("https://example.org/b"));
    }

    #[test]
    fn presentSourceOfAnotherVersionIsAnError() {
        let files = MemoryFileSystem::withFiles(&[(
            "target/oracle/0.17.0/source/CMakeLists.txt",
            cmakeLines,
        )]);
        assert_eq!(
            OracleBuild::new("0.17.0").steps(&files),
            Err("target/oracle/0.17.0/source holds liboqs 0.16.0, not 0.17.0. Delete the folder and run the command again.".to_string())
        );
        let unreadable = MemoryFileSystem::withFiles(&[(
            "target/oracle/0.17.0/source/CMakeLists.txt",
            "project(liboqs)\n",
        )]);
        assert_eq!(
            OracleBuild::new("0.17.0").steps(&unreadable),
            Err("target/oracle/0.17.0/source holds liboqs of an unknown version, not 0.17.0. Delete the folder and run the command again.".to_string())
        );
    }
}
