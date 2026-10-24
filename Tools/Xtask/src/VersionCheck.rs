use crate::FileReading;
use crate::Finding;
use crate::WorkspaceLayout;
use std::path::Path;

/// Checks that every copy of the version agrees with `LIBOQS_VERSION`, the one owner of the
/// version.
pub struct VersionCheck;

impl VersionCheck {
    /// The name of the check in each finding.
    pub const name: &'static str = "versions";
    /// The file that holds the liboqs version that the port matches.
    pub const versionPath: &'static str = "LIBOQS_VERSION";

    /// Returns a finding for each copy of the version that disagrees with `LIBOQS_VERSION`.
    ///
    /// The copies are the workspace package version, the version of each member crate, which
    /// must come from the workspace, and the name of each snapshot file.
    pub fn findings(files: &dyn FileReading, layout: &WorkspaceLayout) -> Vec<Finding> {
        let versionPath = Path::new(Self::versionPath);
        let version = match files.text(versionPath) {
            Ok(text) => text.trim().to_string(),
            Err(error) => return vec![Finding::new(Self::name, versionPath, 0, error.to_string())],
        };
        let mut findings = Vec::new();
        if !Self::isReleaseVersion(&version) {
            findings.push(Finding::new(
                Self::name,
                versionPath,
                1,
                format!("`{version}` is not a MAJOR.MINOR.PATCH version"),
            ));
        }
        let rootPath = Path::new(WorkspaceLayout::rootManifestPath);
        match layout.rootManifest.value("workspace.package", "version") {
            Some(workspaceVersion) if workspaceVersion == version => {}
            Some(workspaceVersion) => findings.push(Finding::new(
                Self::name,
                rootPath,
                layout
                    .rootManifest
                    .line("workspace.package", "version")
                    .unwrap_or(0),
                format!(
                    "workspace version `{workspaceVersion}` differs from LIBOQS_VERSION `{version}`"
                ),
            )),
            None => findings.push(Finding::new(
                Self::name,
                rootPath,
                0,
                "the workspace sets no [workspace.package] version",
            )),
        }
        for member in &layout.members {
            if !member.manifest.inheritsWorkspaceVersion() {
                findings.push(Finding::new(
                    Self::name,
                    &member.manifestPath,
                    0,
                    "the crate must use `version.workspace = true`",
                ));
            }
        }
        for path in files.filePaths().unwrap_or_default() {
            let isSnapshot = path
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|folder| folder == "Snapshots");
            let stem = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            if isSnapshot
                && path.extension().is_some_and(|extension| extension == "txt")
                && stem != version
            {
                findings.push(Finding::new(
                    Self::name,
                    &path,
                    0,
                    format!("snapshot `{stem}` differs from LIBOQS_VERSION `{version}`"),
                ));
            }
        }
        findings
    }

    fn isReleaseVersion(version: &str) -> bool {
        let parts: Vec<&str> = version.split('.').collect();
        parts.len() == 3
            && parts.iter().all(|part| {
                !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::VersionCheck;
    use crate::MemoryFileSystem;
    use crate::WorkspaceLayout;

    const root: &str =
        "[workspace]\nmembers = [\"Modules/*\"]\n\n[workspace.package]\nversion = \"0.16.0\"\n";
    const member: &str = "[package]\nname = \"alpha\"\nversion.workspace = true\n";

    fn messages(files: &MemoryFileSystem) -> Vec<String> {
        let layout = WorkspaceLayout::load(files).expect("layout");
        VersionCheck::findings(files, &layout)
            .into_iter()
            .map(|finding| finding.message)
            .collect()
    }

    #[test]
    fn agreeingVersionsHaveNoFinding() {
        let files = MemoryFileSystem::withFiles(&[
            ("LIBOQS_VERSION", "0.16.0\n"),
            ("Cargo.toml", root),
            ("Modules/A/Cargo.toml", member),
            ("Tests/Snapshots/0.16.0.txt", ""),
        ]);
        assert!(messages(&files).is_empty());
    }

    #[test]
    fn workspaceVersionThatDiffersIsAFinding() {
        let files =
            MemoryFileSystem::withFiles(&[("LIBOQS_VERSION", "0.17.0\n"), ("Cargo.toml", root)]);
        assert_eq!(
            messages(&files),
            vec!["workspace version `0.16.0` differs from LIBOQS_VERSION `0.17.0`"]
        );
    }

    #[test]
    fn crateWithItsOwnVersionIsAFinding() {
        let files = MemoryFileSystem::withFiles(&[
            ("LIBOQS_VERSION", "0.16.0"),
            ("Cargo.toml", root),
            (
                "Modules/A/Cargo.toml",
                "[package]\nname = \"alpha\"\nversion = \"0.16.0\"\n",
            ),
        ]);
        assert_eq!(
            messages(&files),
            vec!["the crate must use `version.workspace = true`"]
        );
    }

    #[test]
    fn snapshotOfAnotherVersionIsAFinding() {
        let files = MemoryFileSystem::withFiles(&[
            ("LIBOQS_VERSION", "0.16.0"),
            ("Cargo.toml", root),
            ("Tests/Snapshots/0.15.0.txt", ""),
        ]);
        assert_eq!(
            messages(&files),
            vec!["snapshot `0.15.0` differs from LIBOQS_VERSION `0.16.0`"]
        );
    }

    #[test]
    fn malformedOrMissingVersionIsAFinding() {
        let malformed =
            MemoryFileSystem::withFiles(&[("LIBOQS_VERSION", "0.16"), ("Cargo.toml", root)]);
        assert_eq!(
            messages(&malformed),
            vec![
                "`0.16` is not a MAJOR.MINOR.PATCH version",
                "workspace version `0.16.0` differs from LIBOQS_VERSION `0.16`"
            ]
        );
        let missing = MemoryFileSystem::withFiles(&[("Cargo.toml", root)]);
        assert_eq!(messages(&missing).len(), 1);
        let noWorkspaceVersion = MemoryFileSystem::withFiles(&[
            ("LIBOQS_VERSION", "0.16.0"),
            ("Cargo.toml", "[workspace]\n"),
        ]);
        assert_eq!(
            messages(&noWorkspaceVersion),
            vec!["the workspace sets no [workspace.package] version"]
        );
    }
    #[test]
    fn versionWithAnEmptyOrNonNumericPartIsAFinding() {
        for version in ["0..16", "0.16.x", "0.16.0-rc1", "0.16.0.1", ""] {
            let files =
                MemoryFileSystem::withFiles(&[("LIBOQS_VERSION", version), ("Cargo.toml", root)]);
            let expected = format!("`{version}` is not a MAJOR.MINOR.PATCH version");
            assert!(messages(&files).contains(&expected), "{version}");
        }
    }
}
