# Rings

## Purpose

The rings keep each crate small and testable. A crate depends only on a ring further in, so an algorithm never reaches an outside service except through an interface.

## Crates

The workspace root `Cargo.toml` lists the member folders `Modules/*` and `Tools/*`.

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-entities` | `Modules/Entities` | `entities` |
| `oqs-native-domain` | `Modules/Domain` | `domain` |
| `oqs-native-aes` | `Modules/AES` | `sharedComponents` |
| `oqs-native-sha2` | `Modules/SHA2` | `sharedComponents` |
| `oqs-native-sha3` | `Modules/SHA3` | `sharedComponents` |
| `oqs-native-kat-random` | `Modules/KATRandom` | `infrastructure` |
| `oqs-native-system-random` | `Modules/SystemRandom` | `infrastructure` |
| `oqs-native-c-oracle` | `Modules/COracle` | `infrastructure` |
| `oqs-native-algorithm-tests` | `Modules/AlgorithmTests` | `infrastructure` |
| `oqs-native-hqc` | `Modules/HQC` | `features` |
| `oqs-native-ml-kem` | `Modules/MLKEM` | `features` |
| `oqs-native-frodokem` | `Modules/FrodoKEM` | `features` |
| `oqs-native` | `Modules/OQSNative` | `composition` |
| `oqs-native-parity` | `Tools/Parity` | `tooling` |
| `xtask` | `Tools/Xtask` | `tooling` |

Each crate states its ring in its own manifest:

```toml
[package.metadata]
ring = "features"
```

## Data flow

1. `cargo xtask check-rings` reads the root manifest and finds each member manifest.
2. It reads `Documentation/Registers/RingDependencies.md` for the allowed edges and `Documentation/Registers/ApprovedDependencies.md` for the approved third-party crates.
3. For each dependency of each crate, it decides if the dependency is local or third-party.
   - A local dependency has a `path`, or comes from a workspace dependency that has a `path`.
   - Every other dependency is third-party. A dependency with only a version comes from the registry, also when a member has the same name, because Cargo resolves it that way.
4. A local dependency must point to a ring that the register allows for its section. A `[dev-dependencies]` entry may also use the rings in the `May use in tests` column.
5. A third-party dependency must have a row in the approved register that names the crate, or `*`.

## Edge cases

- A crate with no ring, or a ring that is not in the register, is a finding.
- A local path that is not a workspace member is a finding.
- A register that is missing, has no table or lacks a column is a finding. The check never passes without its rules.
- A `package = "..."` rename is resolved to the real package name before the check.
- Target tables such as `[target.'cfg(unix)'.dependencies]` count as their plain section.

## Tests

- `RingCheck` unit tests: each allowed and each forbidden edge kind, test-only edges, workspace path inheritance, unknown rings, stray paths and third-party approval.
- `everyRingPairMatchesTheHandWrittenTable`: all 98 combinations of ring pair and section against a table written by hand in the test.
- `randomWorkspacesReportExactlyTheForbiddenEdges`: 200 seeded random workspaces. The count of findings must equal the count of forbidden edges that the hand-written table predicts.
- `realRingRegisterAllowsExactlyTheHandWrittenEdges`: the real register, through `include_str!`, against the hand-written table. A change to the register without a change to the test fails.
