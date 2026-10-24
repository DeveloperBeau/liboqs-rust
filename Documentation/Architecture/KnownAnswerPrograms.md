# Test programs

## Purpose

liboqs checks each algorithm with test programs in its `tests/` folder. The crate `oqs-native-algorithm-tests` replicates the programs that every algorithm of a kind runs, on the Rust capability interfaces, so each family runs the same tests with one call.

The known-answer programs `tests/kat_kem.c` and `tests/kat_sig.c` come with the SHA-256 of their output in `tests/KATs/kem/kats.json` and `tests/KATs/sig/kats.json`. The crate holds copies of the digest files, so a family test compares its digest with the digest of liboqs with no C code in the test.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-algorithm-tests` | `Modules/AlgorithmTests` | `infrastructure` |

The crate is test-only. A family crate may use it in its tests, as the ring register allows.

| Type | Role |
|---|---|
| `KEMKnownAnswerTest` | The program `kat_kem` |
| `SignatureKnownAnswerTest` | The program `kat_sig` |
| `KnownAnswerRandom` | The rules of `tests/test_helpers.c`: the generator of an algorithm and its number of counts |
| `SignedMessageForm` | The layout of the signed message `sm` of `kat_sig`, by scheme name |
| `KnownAnswerText` | The lines of the output, as the C program prints them |
| `KnownAnswerDigests` | The digests of `Data/KEMKnownAnswers.json` and `Data/SignatureKnownAnswers.json` |
| `KEMCorrectnessTest` | The program `test_kem`: the random and the seeded round trips, and a random ciphertext |
| `KEMFuzzTest` | The program `fuzz_test_kem`, with seeded cases, and hostile inputs of each length |
| `KEMMemoryTest` | The program `test_kem_mem`: the three steps with the values in files between them |
| `SignatureCorrectnessTest` | The program `test_sig` with its extended tests: bit flips, each context length and the refused contexts |
| `SignatureFuzzTest` | The program `fuzz_test_sig`, with seeded cases, and hostile signatures and keys |
| `SignatureMemoryTest` | The program `test_sig_mem`: the three steps with the values in files between them |
| `FuzzRandom` | The random source of the fuzz cases: all zeros, all ones, or seeded SplitMix64 bytes, and the hostile values and wrong lengths of a case |
| `TestVectorFiles` | The vector files that `cargo xtask fetch-oracle` downloads, see `Documentation/Registers/TestVectors.md` |
| `JSONValue` | A small JSON reader for the vector files |

## Data flow

1. The program seeds an outer generator with the bytes 0 to 47. HQC uses the SHAKE256 generator, and every other algorithm uses the NIST DRBG.
2. For each count, the outer generator gives a 48-byte seed, and for `kat_sig` also a message of `33 * (count + 1)` bytes.
3. An inner generator, seeded with the seed, gives the random bytes of the key pair and of the encapsulation or the signature.
4. The program prints each value in upper-case hexadecimal in the layout of the NIST response files, with an empty line between counts.
5. The digest is the SHA-256 of the whole text in lower-case hexadecimal. The `single` run prints count 0, and the `all` run prints 100 counts, or 10 for Classic McEliece.

## The behavior programs

- `KEMCorrectnessTest` runs `kem_test_correctness` twice, as `test_kem` does. The first pass uses the random forms. The second pass uses the seeded forms, and a mechanism with no seed length must refuse them. The guard bytes of the C test have no Rust counterpart, because a slice cannot be written past its end.
- `KEMFuzzTest` drives the key pair and the encapsulation with a `FuzzRandom` source in each case, as the C program drives them with `rand()`. Case 0 uses zeros and case 1 uses ones. Each case then decapsulates and encapsulates random values of the right length, which must not panic, and values of wrong lengths, which must give the length error.
- `KEMMemoryTest` writes each value to a file between the steps and removes the files at the end.
- `SignatureCorrectnessTest` runs `sig_test_correctness` with the extended tests on, the default of `test_sig`. After the plain signature it flips 50 random bits of the message, and 50 of the signature for a scheme that claims SUF-CMA, and each flip must fail the verification. The index of a flip is a little-endian `u64` of 8 random bytes, modulo the number of bits, as `test_sig_bitflip` reads it. A scheme with context support signs under each context length from 0 to 255, or for a name that starts with `SLH_DSA` under every 61st length and 255, and must refuse 256 bytes. A scheme without it must refuse one byte. Every scheme signs and verifies with the empty context.
- `SignatureFuzzTest` drives the key pair and the signature with a `FuzzRandom` source, as `fuzz_test_sig` drives them with `rand()`. The message of case `n` has `n` bytes. Hostile signatures and public keys, of the right length and of a wrong length, must be refused, and a secret key of a wrong length must give the length error.
- `SignatureMemoryTest` writes the keys, the message and the signature to files between the steps and removes the files at the end.
- The hostile values of a fuzz case come from `FuzzRandom::hostile(seed, case)`, and a wrong length from `FuzzRandom::wrongLength(case, length)`, so the inputs of a reported case can be made again.

## Test vectors

Some liboqs tests read vector files that they download, the ACVP files of NIST and the Wycheproof files of C2SP. `Documentation/Registers/TestVectors.md` holds the address and the SHA-256 of each file. `cargo xtask fetch-oracle` downloads each missing file to `target/oracle/<version>/vectors/` and rejects a file with another digest. `TestVectorFiles::document` reads a file, or names the command to run when the file is missing.

## Edge cases

- `kat_kem` fails when decapsulation does not recover the shared secret, and `kat_sig` fails when the signature does not verify.
- `kat_sig` has a signed-message layout for 65 schemes only. A scheme without one, such as SLH-DSA, has no known-answer run, and the run is an error.
- The Falcon layout moves the 40-byte salt before the message and puts a header byte after it.
- An empty value prints as `00`, as `OQS_fprintBstr` does.

## Tests

- `Modules/AlgorithmTests/tests/KnownAnswerProcedures.rs`: the programs on small mechanisms and schemes whose output the test follows by hand, and each failure path.
- `knownAnswerHarnessReproducesTheDigestsOfLiboqsForEachForm` in `Tools/Parity`: one KEM of each generator and one scheme of each layout, with the C algorithms behind the Rust interfaces.
- `parity known-answers --all` runs both programs on all 106 C algorithms of the digest files and compares the `single` and the `all` digests. CI runs it on every pull request.
