use crate::CargoManifest;
use std::path::PathBuf;

/// One crate of the workspace and its manifest.
#[derive(Debug)]
pub struct MemberCrate {
    /// The path of the `Cargo.toml` file, relative to the repository root.
    pub manifestPath: PathBuf,
    /// The parsed manifest.
    pub manifest: CargoManifest,
}
