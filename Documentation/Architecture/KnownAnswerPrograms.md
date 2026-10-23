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
| `StatefulKnownAnswerTest` | The program `kat_sig_stfl` |
| `ResponseFile` | The values of a response file of a stateful scheme, read as the C program reads them |
| `StatefulKnownAnswerDigests` | The digests of `Data/StatefulSignatureKnownAnswers.json` |
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
| `StatefulSignatureCorrectnessTest` | The program `test_sig_stfl`: the correctness test, the invalid signatures of XMSS, the saved secret key, and the signatures with their counts |
| `StatefulSignatureFuzzTest` | The programs `fuzz_test_sig_stfl_xmss` and `fuzz_test_sig_stfl_lms`, with seeded cases on the values of the response file, and hostile signatures, public keys and secret keys |
| `FuzzRandom` | The random source of the fuzz cases: all zeros, all ones, or seeded SplitMix64 bytes, and the hostile values and wrong lengths of a case |
| `SuiteSample` | The algorithms that the default test suite runs through the programs and the parity checks |
| `TestVectorFiles` | The vector files that `cargo xtask fetch-oracle` downloads, see `Documentation/Registers/TestVectors.md`, and the response files of the stateful schemes in the liboqs source of the oracle |
| `JSONValue` | A small JSON reader for the vector files |
| `LinearCongruentialSequence` | The seeded inputs of the C programs that give the known answers of the unit tests of the families |
| `OutputDigest` | The digest that those C programs print: 32 bytes of SHAKE128, in hexadecimal |
| `VectorRandom` | The random source of `tests/vectors_sig.c`: the seed or the randomness of a vector, in order |

## Data flow

1. The program seeds an outer generator with the bytes 0 to 47. HQC uses the SHAKE256 generator, and every other algorithm uses the NIST DRBG.
2. For each count, the outer generator gives a 48-byte seed, and for `kat_sig` also a message of `33 * (count + 1)` bytes.
3. An inner generator, seeded with the seed, gives the random bytes of the key pair and of the encapsulation or the signature.
4. The program prints each value in upper-case hexadecimal in the layout of the NIST response files, with an empty line between counts.
5. The digest is the SHA-256 of the whole text in lower-case hexadecimal. The `single` run prints count 0, and the `all` run prints 100 counts, or 10 for Classic McEliece.

## The behavior programs

- `KEMCorrectnessTest` runs `kem_test_correctness` twice, as `test_kem` does. The first pass uses the random forms. The second pass uses the seeded forms, and a mechanism with no seed length must refuse them. The guard bytes of the C test have no Rust counterpart, because a slice cannot be written past its end.
- `KEMFuzzTest` drives the key pair and the encapsulation with a `FuzzRandom` source in each case, as the C program drives them with `rand()`. Case 0 uses zeros and case 1 uses ones. Each case then decapsulates and encapsulates random values of the right length, which must not panic, and values of wrong lengths, which must give the length error. `KEMFuzzTest::run` runs the cases from 0, and `KEMFuzzTest::runCases` runs a range of cases. A mechanism that cannot run the constant bytes, as in its C code, runs the seeded cases from 2 up. NTRU-HPS is such a mechanism: its `f` of constant bytes is 0. So is Classic McEliece: its encapsulation draws random bytes until they give a valid value, and with only zeros or only ones it never ends, in the C code as well.
- `KEMMemoryTest` writes each value to a file between the steps and removes the files at the end.
- `SignatureCorrectnessTest` runs `sig_test_correctness` with the extended tests on, the default of `test_sig`. After the plain signature it flips 50 random bits of the message, and 50 of the signature for a scheme that claims SUF-CMA, and each flip must fail the verification. The index of a flip is a little-endian `u64` of 8 random bytes, modulo the number of bits, as `test_sig_bitflip` reads it. A scheme with context support signs under each context length from 0 to 255, or for a name that starts with `SLH_DSA` under every 61st length and 255, and must refuse 256 bytes. A scheme without it must refuse one byte. Every scheme signs and verifies with the empty context.
- `SignatureFuzzTest` drives the key pair and the signature with a `FuzzRandom` source, as `fuzz_test_sig` drives them with `rand()`. The message of case `n` has `n` bytes. Hostile signatures and public keys, of the right length and of a wrong length, must be refused, and a secret key of a wrong length must give the length error.
- `SignatureMemoryTest` writes the keys, the message and the signature to files between the steps and removes the files at the end.
- The hostile values of a fuzz case come from `FuzzRandom::hostile(seed, case)`, and a wrong length from `FuzzRandom::wrongLength(case, length)`, so the inputs of a reported case can be made again.

## The stateful program

`tests/kat_sig_stfl.c` reads a response file of `tests/KATs/sig_stfl` for each scheme, and `tests/KATs/sig_stfl/kats.json` holds the SHA-256 of what it prints. The files of 55 of the 70 schemes are in the liboqs source. `TestVectorFiles::responseFile` reads them from the source folder of the oracle, so the repository holds only the copy of the digest file.

1. For XMSS and XMSS^MT, the file holds a public key, a secret key, a seed, a message and its signature. The program checks that the known-answer generator of the seed gives the message, signs it with the secret key, compares the signature with the file and verifies it. It prints the values, the signature and the remaining and total counts of the advanced key.
2. For LMS, the file holds no secret key. The program verifies the signature of the file and prints the message, the signature and the public key in lower-case hexadecimal, each followed by an empty line.

`ResponseFile` finds a value after the first match of its marker, skips the characters before the first hexadecimal digit, such as a quote, and shifts each digit into a value of a fixed length, as `ReadHex` does. A value with fewer digits than its length gets zeros in front. Two LMS files, of `LMS_SHA256_H5_W1` and `LMS_SHA256_H10_W1`, hold a raw LMS signature, four bytes shorter than the HSS signature, so it reads as the HSS signature of one level. Their raw LMS public key is four bytes shorter than the HSS key, and liboqs accepts it.

## The stateful behavior programs

`StatefulSignatureCorrectnessTest` replicates `tests/test_sig_stfl.c`. It runs the parts of the C program in the order of its threads:

1. `sig_stfl_test_correctness`: a key pair, the signature of a random message of 100 bytes, its verification with the public key and with the stored copy of the public key, and 50 random bit flips of the message, and of the signature for a scheme that claims SUF-CMA. The C program only prints a failure of the second verification, and the test fails on it. The flips follow `test_sig_stfl_bitflip`, the rule of `test_sig_bitflip`, so both programs use `SignatureCorrectnessTest::checkBitFlips`.
2. `test_invalid_sig`, for a name that holds `XMSS`: a signature of 10 zero bytes, and a zero signature of the scheme length for the 68-byte zero public key with the object identifier 2 in its fourth byte. The verification must refuse both.
3. `sig_stfl_test_secret_key`: a key pair and its two counts. The C program saves the serialized key in a file and restores a key from it. The test saves keys through a `KeyStatePersisting` store, the Rust form of the store callback: a signature comes back with exactly one saved key, equal to the key in memory, and the key in memory changes. A key reloaded from the saved bytes signs on, and its signature verifies. A refused save gives `OQSError::persistenceFailed` and no signature, and the key in memory still changes, as the C library advances it before it calls the store.
4. `sig_stfl_test_sig_gen` and `sig_stfl_test_query_key`: a key pair, the counts, the signatures of the two messages of the C program with the zero byte that ends each C string, the counts after each signature, and the verification of both signatures. The C program checks only that each count succeeds. The test also checks that a new key has its whole total left, that the total stays the same, and that each signature uses one.

`sig_stfl_KATs_keygen` reads the key pair of 18 slow XMSS and XMSS^MT sets from the response file, the sets of height 16 and 20 and the XMSS^MT sets `40/2` and `60/3`, and generates every other key pair. The test does the same, and like the C program it needs a response file for every name that holds `XMSS`. liboqs runs the program without a response file for LMS.

The C program also tests the lock callbacks of its secret key object and signs from several threads, in `sig_stfl_test_secret_key_lock` and the threads of `main`. Those tests concern the C key object, which the Rust API has no form of: the Rust secret key is a value, and `&mut` gives one signer at a time. The test has no replacement for them. The guard bytes of the C program have no Rust counterpart either.

`StatefulSignatureFuzzTest` replicates `tests/fuzz_test_sig_stfl_xmss.c` and `tests/fuzz_test_sig_stfl_lms.c`. The C programs write the bytes of a fuzz input over the public key, the signature and the message of the response file and verify the result, and a crash is their only failure. The first byte of the input picks one of the two schemes of each program: `XMSS-SHA2_10_256` and `XMSSMT-SHA2_20/2_256`, or `LMS_SHA256_H5_W2` and `LMS_SHA256_H5_W8_H5_W8`. The test takes the scheme as its input, so it has no such byte. The XMSS program writes in that order. The LMS program reads one more byte, which picks the order modulo 3: the public key, the signature and the message for 0, the signature, the message and the public key for 1, and the message, the public key and the signature for 2.

1. The test reads the values of the response file as `test_lms_kat` reads them, through `StatefulKnownAnswerTest::verificationValues`, and they must verify.
2. In each case a `FuzzRandom` source gives the bytes of the fuzz input: zeros for case 0, ones for case 1 and seeded bytes for every other case. For an LMS name the first byte picks the order. The hostile values of the case give the length of the input, from 0 to the length of the three values. The verification must refuse the result when the bytes change the values.
3. Hostile signatures and public keys of the right length and of a wrong length must be refused.
4. The counts and the signature of hostile secret keys, of the right length and of a wrong length, give a result or an error and never a panic. A signature that comes back must come with its saved key.

## Test vectors

Some liboqs tests read vector files that they download, the ACVP files of NIST and the Wycheproof files of C2SP. `Documentation/Registers/TestVectors.md` holds the address and the SHA-256 of each file. `cargo xtask fetch-oracle` downloads each missing file to `target/oracle/<version>/vectors/` and rejects a file with another digest. `TestVectorFiles::document` reads a file, or names the command to run when the file is missing.

`tests/vectors_sig.c` replaces the random source of liboqs with the bytes of the vector, so a key pair takes the seed of a vector and a signature takes its randomness. `VectorRandom` gives the same bytes through the Rust interface. A request past the end of the vector is a defect of the caller, and the source panics with the two lengths.

## Edge cases

- `kat_kem` fails when decapsulation does not recover the shared secret, and `kat_sig` fails when the signature does not verify.
- `kat_sig` has a signed-message layout for 65 schemes only. A scheme without one, such as SLH-DSA, has no known-answer run, and the run is an error. `tests/test_kat.py` skips SLH-DSA, and its ACVP vectors test it instead.
- `SuiteSample` holds every algorithm except most SLH-DSA schemes. The small sets of SLH-DSA sign in one to two seconds each, and the 144 pre-hash forms differ from the pure forms only in the message that they sign. So the sample holds the six pure fast sets and each pre-hash function with `SHA2_128F`. The tests of every scheme are behind `#[ignore]`, and `parity run` checks every scheme in release builds.
- The Falcon layout moves the 40-byte salt before the message and puts a header byte after it.
- An empty value prints as `00`, as `OQS_fprintBstr` does.

## Tests

- `Modules/AlgorithmTests/tests/KnownAnswerProcedures.rs`: the programs on small mechanisms and schemes whose output the test follows by hand, and each failure path.
- `Modules/AlgorithmTests/tests/KEMBehaviorProcedures.rs`: the behavior programs of KEMs on a small correct mechanism and on each kind of defect, and the exact cases of a range of `KEMFuzzTest::runCases`.
- `knownAnswerHarnessReproducesTheDigestsOfLiboqsForEachForm` in `Tools/Parity`: one KEM of each generator and one scheme of each layout, with the C algorithms behind the Rust interfaces.
- `Modules/AlgorithmTests/tests/StatefulKnownAnswerProcedures.rs`: the stateful program on a small scheme whose output the test follows by hand, and each failure path of both runs.
- `Modules/AlgorithmTests/tests/StatefulBehaviorProcedures.rs`: the C schemes `XMSS-SHA2_10_256`, `XMSSMT-SHA2_20/2_256`, `LMS_SHA256_H5_W1` and `LMS_SHA256_H5_W8_H5_W8` pass both stateful programs, and a C scheme with each kind of fault fails at the step that the fault breaks. The bit of the first accepted flip comes from a separate model of the random words. The C scheme of height 10 under the name of a set of height 16 takes its key pair from the response file, so its failing key generation never runs. The test crate uses the C oracle in its tests for these runs.
- `parity known-answers --all` runs the three programs on all 161 C algorithms of the digest files: the `single` and the `all` digests of 106 KEMs and signature schemes, and the digest of the response file of 55 stateful schemes. It runs them again on the registered Rust algorithm of each name, so the release run proves the `all` digests of each port, which are too slow for the dev profile of the large families. CI runs it on every pull request.
