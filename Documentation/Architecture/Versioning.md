# Versioning

## Purpose

Each version of this port matches one version of liboqs. The tests always compare with the C library at the same version, and a reader can see from the version which liboqs release the port follows.

## The owner

`LIBOQS_VERSION` holds the version as `MAJOR.MINOR.PATCH`. It is the one owner of the value.

## The copies

- `[workspace.package] version` in the root `Cargo.toml`.
- The version of each member crate, which must be `version.workspace = true`.
- The name of each snapshot file in a `Snapshots` folder, which must be `<version>.txt`.

`cargo xtask check-versions` fails when a copy disagrees with `LIBOQS_VERSION`.

## A fix to the port alone

A fix that does not come from a new liboqs release keeps the version. It ships with the next liboqs release. If a fix cannot wait, it gets a git tag such as `v0.16.0-port.1` and is not published to the registry.

## Tests

`VersionCheck` unit tests cover agreement, a different workspace version, a crate with its own version, a snapshot of another version, a malformed version and a missing file.
