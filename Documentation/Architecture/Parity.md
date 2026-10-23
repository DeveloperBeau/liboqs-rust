# Parity with the C library

## Purpose

Each Rust algorithm must give the same bytes as the C algorithm of the same name. The crate `oqs-native-parity` checks every algorithm of the registry against the C oracle: the base case of the Swift and Zig ports, and seeded variations.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-parity` | `Tools/Parity` | `tooling` |

| Type | Role |
|---|---|
| `KEMParity` | The checks of one KEM |
| `SignatureParity` | The checks of one signature scheme |
| `ParitySettings` | The case count, the seed, the block size and the shard of a run |
| `VariationGenerator` | SplitMix64, the generator of the variation inputs |
| `ParityMismatch` | The first difference: algorithm, case, seed, step and bytes |
| `Snapshot` | The snapshot format of the Swift and Zig ports |
| `LargeStack` | A thread with a 256 MiB stack for each check |

## The base case

The base case is the scheme of the Swift and Zig ports. Each side seeds the NIST DRBG with the bytes 0 to 47 before the key pair, and seeds it again before the encapsulation or the signature. A signature scheme signs the 19 bytes `the quick brown fox`.

The snapshot `Tools/Parity/Snapshots/<version>.txt` has one line for each KEM and signature scheme of the C library: the name and the SHA-256 of the fields of its base case in sorted order of the field names. A KEM has the fields `ct`, `pk`, `sk`, `ss` and `ss2`, and a signature scheme has `pk`, `sig` and `sk`. The file of 0.16.0 is byte-identical to the snapshot of the Zig port.

## The variations

Each variation draws its inputs from `VariationGenerator::forCase`, which mixes the run seed, the algorithm name and the case number. A case gives the same inputs in any shard and in any order. Each side uses the generator of the liboqs known-answer programs for the algorithm.

For a KEM, a variation checks in order:

1. The key pair from an entropy input.
2. The encapsulation from a second entropy input.
3. The decapsulation of the Rust ciphertext by C, and of the C ciphertext by Rust.
4. The decapsulation of a ciphertext with one changed bit. Both sides give the same implicit-rejection secret, or both fail.
5. The decapsulation of a ciphertext one byte short. Both sides fail.
6. The key pair and the encapsulation from seeds, or the same refusal on both sides.

For a signature scheme, a variation draws a message of 0 to 9280 bytes and, for a scheme with context support, a context of 0 to 255 bytes. A scheme without context support asks for a context in one case of eight, and both sides must refuse it. A variation checks in order:

1. The key pair.
2. The signature, with the plain form or the context form.
3. The verification of the Rust signature by C, and of the C signature by Rust.
4. The verdicts of both sides on a changed signature, a changed message, a longer context and a short signature. Each change keeps the form of the signature, except the longer context, which is always verified in the context form, so a plain signature also meets a context that it was not made under.

The first difference stops the check with a `ParityMismatch`, which names the algorithm, the case, the seed and the step.

## Coverage

`Tools/Parity/NotYetPorted.txt` lists each algorithm of the C library that the registry does not hold, in liboqs order. `everyCAlgorithmIsRegisteredOrListedAsNotYetPorted` fails when the list and the registry do not cover the C library exactly, and prints the right list. Each family removes its names, and the port is complete when the list is empty.

## The parity program

`cargo run --release -p oqs-native-parity -- <command>` runs the full gate:

- `run` checks each registered algorithm, the base case and 1000 variations by default.
- `snapshot` prints the snapshot of the C library. With `--check` it compares each digest with the frozen file.
- `known-answers` runs the liboqs known-answer programs on the C algorithms through the Rust harness, and on the registered Rust algorithm of each name, and compares each digest with the digest of liboqs. A job fails when either side differs. See [KnownAnswerPrograms.md](KnownAnswerPrograms.md).

`--block-size N` splits the variations of each algorithm into blocks of N cases, and each block is a job of its own. The first block also checks the base case. Without the option, each algorithm is one job.

`--shard I/N` takes the jobs at positions `I`, `I + N` and so on. The positions count the blocks, so the blocks of a slow algorithm go to different shards. `--processes N` splits the run into N processes. One process runs one C operation at a time, because of the lock of the oracle, so more processes use more processors.

## Edge cases

- Some C algorithms keep several megabytes on the stack, more than the 2 MiB of a spawned thread. Each check runs on a `LargeStack` thread.
- The NIST DRBG updates its state after each request, so its output depends on how the requests split the bytes. A Rust algorithm must ask for its random bytes in the same requests as the C code. The base case and the variations both check this.
- A variation of a small set of SLH-DSA signs once in C and once in Rust. In a release build the C library signs a small set in 0.55 to 1.6 seconds and the port in 0.73 to 1.97 seconds, so a variation takes 1.5 to 4 seconds of one processor, and 1000 variations of the 78 small sets take about 60 hours. The default test suite checks the algorithms of `SuiteSample` only.

## Tests

- `PrimitiveParity.rs`: SHA-3, SHAKE in one piece and in pieces, SHA-2, AES blocks and AES counter mode, 1000 seeded inputs each.
- `RandomParity.rs`: the NIST DRBG and the HQC generator against the C generators, 1000 seeded entropy inputs and request patterns each.
- `HarnessValidation.rs`: the C algorithms behind the Rust interfaces pass every check, and each kind of defect in a mechanism or a scheme fails at its own step.
- `AlgorithmCoverage.rs`: the registry and `NotYetPorted.txt` against the C library, and the facts of each registered algorithm against the C facts.
- `SnapshotParity.rs`: the names of the frozen snapshot, and the snapshot line of each registered algorithm of `SuiteSample`. The ignored test checks every registered algorithm.
- `RegisteredParity.rs`: every registered KEM and each registered signature scheme of `SuiteSample` with the cases of `PARITY_CASES`, 2 by default, and the seed of `PARITY_SEED`. The suite runs in the dev profile, where a variation of a large family takes a large part of a second, so the release runs of `parity run` carry the 1000 variations. The ignored test checks every registered signature scheme.
- `HostileInputParity.rs`: keys and ciphertexts of the right length with any bytes, only ones, only zeros or seeded bytes, give the result of the C library for every registered KEM: the same bytes or a failure on both sides. It also covers the HQC keys whose bits above `n` reach the reduction of the C code, see [HQC.md](HQC.md), and the Classic McEliece keys of the identity network, which take each decision of the decoder, see [ClassicMcEliece.md](ClassicMcEliece.md).
- `MalformedKeyParity.rs`: ML-DSA signs secret keys that no key generation gives, with coefficients out of range or random bytes, as the C library does. UOV signs secret keys of random bytes, fails for a secret key whose block S is zero, and judges public keys made by hand, as the C library does. The variations sign only with generated keys.
- `ParityProgram.rs`: the program itself, with `run` over the registered algorithms of `SuiteSample`.
- `HostileSignatureParity.rs`: public keys and signatures of the right length with only ones, only zeros or seeded bytes, or with the high bit of the last byte set, get the verdict of the C library for every registered signature scheme. That bit is a padding bit of every CROSS public key, which the variations never change.

CI runs the test suite on every pull request, then `known-answers --all` and `snapshot --check`, and `run` with 100 variations in blocks of 10, in four shards of four processes.

One build job of each workflow builds the C oracle and the release `parity` program once. The other jobs restore the oracle from the cache that it fills and run the program from its artifact, so no shard builds either again.

The gate workflow runs `run` with 1000 variations in blocks of 25, in fifteen shards of four processes. It runs on each push to `release` and `develop`, on each push to a branch under `gate/`, and on demand. A push of a branch under `gate/` gives the gate of any commit before it merges. The slow families, such as SLH-DSA and Classic McEliece, take hours of processor time for 1000 variations, so each pull request runs 100.
