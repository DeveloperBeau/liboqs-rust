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

- `Shim/OracleShim.c` wraps each liboqs call in a plain function, so that Rust never depends on the layout of a liboqs struct. Its LMS working keys use the hash-sigs code of liboqs, so the script adds the folder `source/src/sig_stfl/lms/external` of the oracle with `-iquote`. That flag serves only quoted includes, because the folder holds an `endian.h` that must not hide the `endian.h` of the system.
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

`OracleMechanism`, `OracleSignatureScheme` and `OracleStatefulScheme` put a C algorithm behind the Rust capability interfaces, with the `source` randomness. An `OracleWorkingKey` signs many messages with one LMS key at the cost of one load, see the section on LMS working keys. The tests of the harnesses run against them before any Rust family exists. The secret key of `OracleStatefulScheme` is the serialized key of liboqs. Each signature deserializes it, and the key advances before the store of the caller runs, as in the C library.

The C verification of a stateful signature reads the public key from a buffer of the length of the scheme. `isValidStatefulSignature` gives a shorter key to the C code with zeros after it, because liboqs accepts a raw LMS public key, four bytes shorter than the HSS key, and reads only its bytes.

## LMS working keys

`OQS_SIG_STFL_sign` of LMS loads a working key of hash-sigs from the private key for each signature, and a load costs about one key generation. An `OracleWorkingKey` holds a working key for many signatures:

1. `COracle::loadLMSWorkingKey` loads the working key once from a serialized key, with the aux data that the serialized key carries, and with a memory target of 64 MiB. The aux data and the larger target make the load fast and give large subtrees. The working key holds the public key of its key pair.
2. `COracle::signWithWorkingKey` signs with the steps of `oqs_sig_stfl_lms_sign` after its load: `hss_sign_init`, `hss_sign_update` and `hss_sign_finalize`. hash-sigs advances the private key, the first 64 bytes of the serialized key, in place. The aux data never changes, so the serialized key stays the key that `OQS_SIG_STFL_sign` stores.
3. The shim verifies each signature. When the signature fails or does not verify, it sets the private key back to its state before the signature, loads the working key again and signs again. A working key of liboqs does not sign on past a subtree boundary, see `Documentation/Learnings/COracle.md`.
4. `remainingSignatureCountOfWorkingKey` and `totalSignatureCountOfWorkingKey` count as `OQS_SIG_STFL_sigs_remaining` and `OQS_SIG_STFL_sigs_total`, with the `max_count` of the loaded working key in place of a new load. A count above `max_count` is refused, as the load of liboqs refuses it. After the last signature the private key is all `0xFF` bytes, so its count is above `max_count` too.

The working key is a model of the keys that a key generation gives, not of hostile keys. The drop frees the working key without the lock, because the free touches only the memory of that key.

## Edge cases

- The C library has one global random source. `COracle` holds the lock for its whole life, so two tests never share the source. This lock is the one global state of the crate, and its declaration says why.
- A thread that holds an oracle and makes a second one would wait for itself. `COracle::new` panics at once with the reason.
- An unknown name, or a name with a zero byte, gives `OQSError::operationFailed`, or `None` for a description.
- An empty context reaches the C library as the null pointer, as `tests/test_sig.c` passes it. The liboqs wrapper of a scheme without context support refuses every other pointer, and the pointer of an empty Rust slice is not null.
- The CROSS code verifies the whole signature of its scheme before liboqs refuses a length other than its own. A verification gives the C code a copy of a shorter signature with zeros after it, up to the signature length of the scheme, and the length of the signature itself. The other schemes read only the bytes of that length, so the zeros change nothing for them.
- Some C algorithms keep several megabytes on the stack. The callers run each check on a thread with a large stack. See `LargeStack` in [Parity.md](Parity.md).

## Tests

`Modules/COracle/tests/OracleContract.rs` calls the real C library:

- `nistRandomGivesTheSeedsOfTheNISTKnownAnswerFiles`: the first two seeds of every NIST KAT response file.
- `knownAnswerRandomIsSHAKE256ForHQCAndTheNISTDRBGForOthers`: the HQC generator against the C SHAKE256 of the seed and the domain byte.
- `sourceRandomFeedsTheCCodeInItsOwnRequests`: ML-KEM asks for 64 bytes for a key pair and 32 for an encapsulation.
- `anEmptyContextIsTheNullContextOfTheCLibrary`: `Falcon-512` and `ML-DSA-44` sign and verify with the empty context, and `Falcon-512` refuses a context of one byte.
- `aShortSignatureReachesTheCVerificationWithItsWholeLength`: `cross-rsdp-128-balanced` refuses copies of 0, 1 and all but one byte of a valid signature, in both forms. Without the copy, the empty signature stopped the test with a memory fault.
- `aWorkingKeySignsEachSignatureOfTheWholeKeyAsTheCLibraryDoes`: all 32 signatures of a key of `LMS_SHA256_H5_W1`, on the path of `OQS_SIG_STFL_sign` and with a working key, each path with its own advanced key. Each signature, each advanced key and each count is byte-identical, and both paths refuse a 33rd signature.
- `aTwoLevelWorkingKeySignsAcrossItsBottomTreesAsTheCLibraryDoes`: a working key of `LMS_SHA256_H5_W8_H5_W8` signs 67 signatures, and the path of `OQS_SIG_STFL_sign` signs from the same serialized key at the signatures around the ends of the first two bottom trees.
- `aTwoLevelWorkingKeySignsEachSignatureOfTheWholeKeyAsTheCLibraryDoes` compares all 1024 signatures of a key of `LMS_SHA256_H5_W8_H5_W8` as the first test compares them. It is ignored by default, because `OQS_SIG_STFL_sign` loads a new working key for each signature, and the run takes about a quarter of an hour of C time.
- `aWorkingKeyRefusesWhatTheCLibraryRefuses`: an XMSS name, an unknown name, a public key of another length, a key of zeros and a key of 63 bytes.
- Round trips and changed inputs of a KEM, a signature scheme and a stateful scheme, the seeded forms, wrong lengths, unknown names, the second oracle on one thread, and the standard answers of the primitives.
