use crate::DependencyKind;

/// One dependency that a crate manifest declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dependency {
    /// The package name of the dependency. A `package = "..."` rename is resolved.
    pub packageName: String,
    /// The section that declares the dependency.
    pub kind: DependencyKind,
    /// True when the manifest gives a local `path` for the dependency.
    pub hasPath: bool,
    /// True when the dependency comes from `[workspace.dependencies]`.
    pub isInheritedFromWorkspace: bool,
    /// The manifest line that declares the dependency.
    pub line: usize,
}
