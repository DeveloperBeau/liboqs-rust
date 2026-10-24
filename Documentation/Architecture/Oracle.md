# The C oracle

## Purpose

The parity tests compare each Rust algorithm with the C algorithm of the same name. The C side is the liboqs library at the version in `LIBOQS_VERSION`, built from its source. Only tests use it. No shipped crate depends on it.

## Crates

| Crate | Folder | Ring | Role |
|---|---|---|---|
| `oqs-native-c-oracle` | `Modules/COracle` | `infrastructure` | Links the C library and gives it a Rust interface |
| `xtask` | `Tools/Xtask` | `tooling` | `cargo xtask fetch-oracle` clones and builds the C library |

## The build

`cargo xtask fetch-oracle` runs these steps in the repository root:

1. When `target/oracle/<version>/source` is missing, it clones liboqs at the tag of the version with `git clone --depth 1`. A source of another version is an error, because the oracle must be the version of the repository.
2. It configures the build in `target/oracle/<version>/build` with CMake. `OracleBuild::configurationOptions` holds the options: a release build of the portable C code of every algorithm as a static library, with no CPU extension and no OpenSSL, and with key generation and signing of the stateful schemes.
3. It builds the library. A second run takes a few seconds when nothing changed.
4. It downloads each test vector file of `Documentation/Registers/TestVectors.md` that is missing from `target/oracle/<version>/vectors/` or that has another SHA-256, and then checks the SHA-256 of every file.

CMake gets the source and build folders with every link resolved, because CMake records the folders that it is given. Several worktrees can then link `target/oracle` to one shared folder, and a fetch from any of them gives CMake the same paths, so nothing builds again.

`OracleBuild` decides the steps from the files of the repository, and `ProcessRunning` runs them. The tests use `RecordingProcesses` in place of the real programs.

The build script of `oqs-native-c-oracle` finds the folder through `OQS_ORACLE_DIR`, or else at `target/oracle/<version>` in the workspace. A missing folder stops the build with the command to run. The script compiles two C files with the system C compiler and links them with `liboqs.a` and `liboqs-internal.a`:

- `Shim/OracleShim.c` wraps each liboqs call in a plain function, so that Rust never depends on the layout of a liboqs struct.
- `tests/test_helpers.c` of liboqs holds the generators of the liboqs known-answer programs, such as the SHAKE256 generator of HQC.

Without the `std` feature the crate is empty and links nothing.

## Data flow

1. A test makes a `COracle` with an `OracleRandomness`. `COracle::new` waits for the lock of the C library and sets its random source.
2. The test calls operations by liboqs name, such as `generateKEMKeyPair("ML-KEM-768")`. Each operation checks the length of each input that the C code reads, and returns `OQSError::invalidLength` before any call when a length is wrong.
3. Dropping the oracle sets the random source back to a fixed generator and releases the lock.

The random sources are:

- `nist`: the NIST AES-256 CTR DRBG of liboqs, seeded with 48 bytes.
- `knownAnswer`: the generator that the liboqs known-answer programs use for an algorithm, the SHAKE256 generator for HQC and the NIST DRBG for the others.
- `source`: a Rust `RandomGenerating`, which the C code reads through a callback.

`OracleMechanism`, `OracleSignatureScheme` and `OracleStatefulScheme` put a C algorithm behind the Rust capability interfaces, with the `source` randomness. The tests of the harnesses run against them before any Rust family exists. The secret key of `OracleStatefulScheme` is the serialized key of liboqs. Each signature deserializes it, and the key advances before the store of the caller runs, as in the C library.

The C verification of a stateful signature reads the public key from a buffer of the length of the scheme. `isValidStatefulSignature` gives a shorter key to the C code with zeros after it, because liboqs accepts a raw LMS public key, four bytes shorter than the HSS key, and reads only its bytes.

## Edge cases

- The C library has one global random source. `COracle` holds the lock for its whole life, so two tests never share the source. This lock is the one global state of the crate, and its declaration says why.
- A thread that holds an oracle and makes a second one would wait for itself. `COracle::new` panics at once with the reason.
- An unknown name, or a name with a zero byte, gives `OQSError::operationFailed`, or `None` for a description.
- Some C algorithms keep several megabytes on the stack. The callers run each check on a thread with a large stack. See `LargeStack` in [Parity.md](Parity.md).

## Tests

`Modules/COracle/tests/OracleContract.rs` calls the real C library:

- `nistRandomGivesTheSeedsOfTheNISTKnownAnswerFiles`: the first two seeds of every NIST KAT response file.
- `knownAnswerRandomIsSHAKE256ForHQCAndTheNISTDRBGForOthers`: the HQC generator against the C SHAKE256 of the seed and the domain byte.
- `sourceRandomFeedsTheCCodeInItsOwnRequests`: ML-KEM asks for 64 bytes for a key pair and 32 for an encapsulation.
- Round trips and changed inputs of a KEM, a signature scheme and a stateful scheme, the seeded forms, wrong lengths, unknown names, the second oracle on one thread, and the standard answers of the primitives.
