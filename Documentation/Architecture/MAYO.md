# MAYO

## Purpose

`oqs-native-mayo` ports the four MAYO signature schemes of liboqs: `MAYO-1`, `MAYO-2`, `MAYO-3` and `MAYO-5`. Each gives the bytes of the C algorithm of the same name, whose code is the portable implementation of the MAYO team in `src/sig/mayo/pqmayo_mayo-<n>_opt`. MAYO is an oil and vinegar scheme of round 2 of the NIST call for additional signatures.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-mayo` | `Modules/MAYO` | `features` |

| Type or module | Role |
|---|---|
| `MAYO` | MAYO of round 2, with the constants `mayo1`, `mayo2`, `mayo3` and `mayo5` and the `Signing` interface |
| `Parameters` | The parameters of `mayo.h`, the lengths that follow from them, and the liboqs facts of a set |
| `InternalAlgorithms` | The public key of a seed, the expanded keys, the signature with given randomness and the verification, as `mayo.c` |
| `Field` | The arithmetic of GF(16) of `simple_arithmetic.h`, and the encoding of two elements to a byte of `mayo.c` |
| `PackedVectors` | The packed vectors of m elements of `arithmetic_fixed.h`, 16 elements to a 64-bit word |
| `MatrixProducts` | The products of the public map with matrices of elements of `generic_arithmetic.h`, and `m_upper` |
| `LinearSystem` | The matrix A and the right-hand side y of a signature attempt, `compute_A` and `compute_rhs` |
| `EchelonForm` | The echelon form of `echelon_form.h` and the solution of `sample_solution` |

## Parameter sets

| Set | m | n | o | k | f(z) | Salt | Digest | NIST level | Public key | Secret key | Signature |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `MAYO-1` | 78 | 86 | 8 | 10 | z^78 + z^2 + z + x^3 | 24 | 32 | 1 | 1420 | 24 | 454 |
| `MAYO-2` | 64 | 81 | 17 | 4 | z^64 + x^3 z^3 + x z^2 + x^3 | 24 | 32 | 1 | 4912 | 24 | 186 |
| `MAYO-3` | 108 | 118 | 10 | 11 | z^108 + (x^2 + x + 1) z^3 + z^2 + x^3 | 32 | 48 | 3 | 2986 | 32 | 681 |
| `MAYO-5` | 142 | 154 | 12 | 12 | z^142 + z^3 + x^3 z^2 + x^2 | 40 | 64 | 5 | 5554 | 40 | 964 |

The field is GF(16) = F2[x] / (x^4 + x + 1), and v = n - o is the number of vinegar variables. The descriptions hold the facts of `sig_mayo_1.c`, `sig_mayo_2.c`, `sig_mayo_3.c` and `sig_mayo_5.c`: the version text `round2`, the claim EUF-CMA without SUF-CMA, and no context support. `MAYO-2` claims the NIST level 1, as `MAYO-1` does.

## Data flow

1. A key pair draws the secret seed in one request: 24 bytes for `MAYO-1` and `MAYO-2`, 32 for `MAYO-3` and 40 for `MAYO-5`. The secret key is the seed.
2. SHAKE256 of the seed gives the public seed of 16 bytes and the oil space O, a matrix of v rows and o columns.
3. AES-128 in counter mode gives the bytes of P1 and P2: the key is the public seed and the vector is 12 zero bytes, as `AES_128_CTR` of `aes_ctr.h` calls `OQS_AES128_CTR_inc_stream_iv`. `fillCounterKeystream` of `Modules/AES` is that function. Each entry of P1 and P2 is a packed vector of m elements that covers the m matrices of the public map at one place.
4. The key pair computes `P3 = O^T (P1 O + P2)`. The public key is the public seed and the packed upper triangle of P3.
5. A signature checks the length of the secret key, then draws the randomness of the salt in one request of the length of the salt. It expands the seed again, with `L = (P1 + P1^T) O + P2` in place of P2.
6. The salt is SHAKE256 of the digest of the message, the randomness and the seed. The target t is SHAKE256 of the digest and the salt.
7. Attempt c, from 0 to 255, hashes the digest, the salt, the seed and the byte c into k vinegar vectors and the randomizer r. It builds the linear system `A x = y` of `compute_A` and `compute_rhs` and solves it as `sample_solution` does. The first attempt with a solution gives the signature: the k vectors `(v_i + O x_i, x_i)` and the salt. When no attempt has a solution, the signature fails, as `MAYO_ERR` of the C code.
8. A verification checks the lengths of the signature and the public key, expands the public map from the public key, and compares the value of the whipped map at the vectors of the signature with the target of the digest and the salt.

Each product in GF(16) is exact, and the packed operations work on each nibble alone. The bytes therefore follow from the steps of the C code, and the port keeps them: the order of the k (k + 1) / 2 products in the system, the reduction of the powers past z^(m - 1) with f(z), and the echelon form and the back substitution with their limits.

## Edge cases

- Every input of a wrong length is `OQSError::invalidLength`. The length of the secret key is checked before the random request.
- Any bytes of the length of the secret key are a secret key, because the secret key is the seed of a key pair.
- MAYO signs without a context string. A context of one byte or more is `OQSError::contextNotSupported`, before any random request, and a verification under it is false. The empty context is the plain form, as the NULL context of the C code.
- A signature or a public key of a wrong length is not valid. Any bytes of the right length decode into elements, so the verification of hostile bytes runs to the comparison, and it never panics. The comparison covers each of the m elements.
- When no attempt of the 256 finds a solution, the signature is `OQSError::operationFailed`. No known input makes every attempt fail, so a unit test gives the attempt loop a solver that always fails.
- The pivot search of the echelon form reads at most 33 rows, and the back substitution looks for the first entry of a row in at most `32 / (m - row)` columns after the diagonal. A matrix that needs more gives the result of the C code, which is then not a solution, and the signature is not valid. The unit tests give matrices with a zero column, with five zero columns, with a first pivot at the last row of the search and just after it, with a pivot far below the search, with a low rank and with zero rows, and compare each result with the C code.
- The back substitution reads and writes the rows after m, up to the next multiple of 8, which the C buffer holds. The matrix of the port has these zero rows.
- liboqs builds `MAYO-1`, `MAYO-3` and `MAYO-5` with `HAVE_STACKEFFICIENT` and `MAYO-2` without it, so the C code of `MAYO-2` computes `S P S^T` in another order. The port uses the form of the other three sets for all four. The products are exact, and the known answers of the C code of `MAYO-2` show that the two forms agree.
- The C code keeps P1 and P2 on the stack, 853704 bytes for `MAYO-5`. The port keeps them, L, the system and the bins on the heap, so it runs on a thread with the default stack.

## Tests

Each test file names the liboqs test that it replicates.

- `KATSig.rs`: `tests/kat_sig.c`. The `single` and `all` digests of the four sets equal `tests/KATs/sig/kats.json`.
- `TestSig.rs`: `tests/test_sig.c` through `SignatureCorrectnessTest`, the random requests, the refused context and its order with the random request, the length errors, and a change in each part of a signature and of a public key.
- `FuzzTestSig.rs`: `tests/fuzz_test_sig.c` through `SignatureFuzzTest`, random seeds that sign for the public keys of their key pairs, and random signatures, salts and public keys that are not valid.
- `TestSigMem.rs`: `tests/test_sig_mem.c` through `SignatureMemoryTest`.
- liboqs has no vector test for MAYO, so the crate has no `VectorsSig.rs`.
- Unit tests of `Field` and `PackedVectors`: each product against the definition of the field, the inverse against the table of the C code, and the packed operations and the bins against the products of each nibble.
- Unit tests of `MatrixProducts`, `LinearSystem`, `EchelonForm` and `InternalAlgorithms`: the digests of the C functions of the MAYO team on seeded inputs, for each set. `LinearCongruentialSequence` makes the inputs and `OutputDigest` the digests, as for every family. A C program built `mayo.c` and `arithmetic.c` with the flags of each set and gave the digests, see `Documentation/Learnings/Families.md`.
- Unit tests of the attempt loop: a solver that always fails sees 256 attempts, each with its own randomizer, and the signature fails with `OQSError::operationFailed`. A solver that fails three times gives another valid signature with the same salt. A solver for a right-hand side with one element changed gives a signature whose value differs from the target in that element alone, at the first, a middle and the last place, and the verification refuses it.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library.
