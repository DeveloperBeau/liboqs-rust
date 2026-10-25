# Versioning

## Purpose

Each version of this port matches one version of liboqs. The tests always compare with the C library at the same version, and a reader can see from the version which liboqs release the port follows.

## The owner

`LIBOQS_VERSION` holds the version as `MAJOR.MINOR.PATCH`. It is the one owner of the value.

## The copies

- `[workspace.package] version` in the root `Cargo.toml`.
- The version of each member crate, which must be `version.workspace = true`.
- The `version` of each local entry in `[workspace.dependencies]`. The registry refuses a dependency with only a path, and Cargo cannot take a dependency version from `[workspace.package]`, so each entry repeats the value.
- The name of each snapshot file in a `Snapshots` folder, which must be `<version>.txt`.

`cargo xtask check-versions` fails when a copy disagrees with `LIBOQS_VERSION`.

## A fix to the port alone

A fix that does not come from a new liboqs release keeps the version. It ships with the next liboqs release. If a fix cannot wait, it gets a git tag such as `v0.16.0-port.1` and is not published to the registry.

## Publishing

Each crate that has no `publish = false` goes to crates.io. These rules make the packages valid:

- A shipped crate takes each shipped crate that it uses from `[workspace.dependencies]`, so the dependency has a path for the workspace and a version for the registry.
- A dev-dependency on a test crate, such as `oqs-native-algorithm-tests`, has only a path. `cargo package` leaves such a dev-dependency out of the published manifest. A crate whose tests use a test crate excludes its `tests/` folder, because those tests cannot build from the package.
- Each crate folder holds links to `LICENSE` and `THIRD_PARTY_NOTICES.md` of the root, and each crate whose license expression names Apache-2.0 holds a link `LICENSE-APACHE` to `Licenses/Apache-2.0.txt`. `cargo package` copies the file that a link names, so each package carries the text and the repository holds one copy. `include` cannot name a file outside the crate folder.
- Each crate has a short `README.md`, its own keywords, and the categories of `[workspace.package]`.

A crate goes to the registry after every crate that it depends on. `cargo publish --workspace` finds that order.

## Tests

`VersionCheck` unit tests cover agreement, a different workspace version, a local workspace dependency of another version, a crate with its own version, a snapshot of another version, a malformed version and a missing file.
