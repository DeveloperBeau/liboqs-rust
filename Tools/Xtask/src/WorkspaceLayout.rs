use crate::CargoManifest;
use crate::FileReading;
use crate::Finding;
use crate::MemberCrate;
use std::path::Path;

/// The root manifest of the workspace and every member crate.
#[derive(Debug)]
pub struct WorkspaceLayout {
    /// The parsed root `Cargo.toml`.
    pub rootManifest: CargoManifest,
    /// The member crates, in path order.
    pub members: Vec<MemberCrate>,
}

impl WorkspaceLayout {
    /// The path of the root manifest.
    pub const rootManifestPath: &'static str = "Cargo.toml";

    /// Reads the root manifest and the manifest of every crate that the member patterns match.
    ///
    /// A pattern is a folder path, or a folder path that ends in `/*` to match each child folder.
    pub fn load(files: &dyn FileReading) -> Result<Self, Finding> {
        let rootPath = Path::new(Self::rootManifestPath);
        let unreadable =
            |error: std::io::Error| Finding::new("workspace", rootPath, 0, error.to_string());
        let rootManifest = CargoManifest::parse(&files.text(rootPath).map_err(unreadable)?);
        let filePaths = files.filePaths().map_err(unreadable)?;
        let mut members = Vec::new();
        for path in &filePaths {
            if path.file_name().is_some_and(|name| name == "Cargo.toml")
                && path != rootPath
                && rootManifest
                    .workspaceMembers()
                    .iter()
                    .any(|pattern| Self::matches(pattern, path))
            {
                let text = files
                    .text(path)
                    .map_err(|error| Finding::new("workspace", path, 0, error.to_string()))?;
                members.push(MemberCrate {
                    manifestPath: path.clone(),
                    manifest: CargoManifest::parse(&text),
                });
            }
        }
        Ok(WorkspaceLayout {
            rootManifest,
            members,
        })
    }

    fn matches(pattern: &str, manifestPath: &Path) -> bool {
        let Some(folder) = manifestPath.parent() else {
            return false;
        };
        match pattern.strip_suffix("/*") {
            Some(parent) => folder.parent() == Some(Path::new(parent)),
            None => folder == Path::new(pattern),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WorkspaceLayout;
    use crate::MemoryFileSystem;
    use std::path::PathBuf;

    #[test]
    fn loadFindsMembersOfWildcardAndPlainPatternsOnly() {
        let files = MemoryFileSystem::withFiles(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"Modules/*\", \"Tools/Xtask\"]\n",
            ),
            (
                "Modules/Entities/Cargo.toml",
                "[package]\nname = \"entities\"\n",
            ),
            (
                "Modules/Entities/Nested/Cargo.toml",
                "[package]\nname = \"nested\"\n",
            ),
            ("Tools/Xtask/Cargo.toml", "[package]\nname = \"xtask\"\n"),
            ("Tools/Other/Cargo.toml", "[package]\nname = \"other\"\n"),
        ]);
        let layout = WorkspaceLayout::load(&files).expect("layout");
        let paths: Vec<PathBuf> = layout
            .members
            .iter()
            .map(|member| member.manifestPath.clone())
            .collect();
        assert_eq!(
            paths,
            vec![
                PathBuf::from("Modules/Entities/Cargo.toml"),
                PathBuf::from("Tools/Xtask/Cargo.toml")
            ]
        );
    }

    #[test]
    fn loadFailsWithAFindingWhenTheRootManifestIsMissing() {
        let error = WorkspaceLayout::load(&MemoryFileSystem::default()).expect_err("missing root");
        assert_eq!(error.check, "workspace");
        assert_eq!(error.path, PathBuf::from("Cargo.toml"));
    }
}
