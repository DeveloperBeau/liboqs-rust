/// The manifest section that declares a dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyKind {
    /// A dependency of the library or binary code, from `[dependencies]`.
    normal,
    /// A dependency of the tests only, from `[dev-dependencies]`.
    development,
    /// A dependency of the build script, from `[build-dependencies]`.
    build,
}
