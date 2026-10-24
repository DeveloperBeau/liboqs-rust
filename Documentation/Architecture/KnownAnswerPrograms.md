# Known-answer programs

## Purpose

liboqs checks each algorithm with two programs, `tests/kat_kem.c` and `tests/kat_sig.c`, and with the SHA-256 of their output in `tests/KATs/kem/kats.json` and `tests/KATs/sig/kats.json`. The crate `oqs-native-algorithm-tests` replicates the programs on the Rust capability interfaces and holds copies of the digest files. A family test runs a program on a Rust algorithm and compares the digest with the digest of liboqs, with no C code in the test.

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

## Data flow

1. The program seeds an outer generator with the bytes 0 to 47. HQC uses the SHAKE256 generator, and every other algorithm uses the NIST DRBG.
2. For each count, the outer generator gives a 48-byte seed, and for `kat_sig` also a message of `33 * (count + 1)` bytes.
3. An inner generator, seeded with the seed, gives the random bytes of the key pair and of the encapsulation or the signature.
4. The program prints each value in upper-case hexadecimal in the layout of the NIST response files, with an empty line between counts.
5. The digest is the SHA-256 of the whole text in lower-case hexadecimal. The `single` run prints count 0, and the `all` run prints 100 counts, or 10 for Classic McEliece.

## Edge cases

- `kat_kem` fails when decapsulation does not recover the shared secret, and `kat_sig` fails when the signature does not verify.
- `kat_sig` has a signed-message layout for 65 schemes only. A scheme without one, such as SLH-DSA, has no known-answer run, and the run is an error.
- The Falcon layout moves the 40-byte salt before the message and puts a header byte after it.
- An empty value prints as `00`, as `OQS_fprintBstr` does.

## Tests

- `Modules/AlgorithmTests/tests/KnownAnswerProcedures.rs`: the programs on small mechanisms and schemes whose output the test follows by hand, and each failure path.
- `knownAnswerHarnessReproducesTheDigestsOfLiboqsForEachForm` in `Tools/Parity`: one KEM of each generator and one scheme of each layout, with the C algorithms behind the Rust interfaces.
- `parity known-answers --all` runs both programs on all 106 C algorithms of the digest files and compares the `single` and the `all` digests. CI runs it on every pull request.
