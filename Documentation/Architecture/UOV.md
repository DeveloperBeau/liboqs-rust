# UOV

## Purpose

`oqs-native-uov` ports the twelve UOV signature schemes of liboqs: `OV-Is`, `OV-Ip`, `OV-III` and `OV-V`, each with classic keys, with a compressed public key (`-pkc`) and with compressed keys (`-pkc-skc`). Each gives the bytes of the C algorithm of the same name. The C code is the reference code of the pqov project, commit `33fa5278`, with the version text `Round 2`. The oracle build of liboqs enables this reference code only, not the AVX2 or the NEON code.

The twelve folders `src/sig/uov/pqov_ov_<set>_ref` hold the same files. The build of each set chooses the field and the shape with one of the macros `_OV16_160_64` to `_OV256_244_96`, and the form of the keys with `_OV_CLASSIC`, `_OV_PKC` or `_OV_PKC_SKC`. The macro `_UTILS_OQS_` takes SHAKE256, AES-128 and the random bytes from liboqs. The port shares one code for the twelve sets and takes these choices from `Parameters`.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-uov` | `Modules/UOV` | `features` |

| Type | Role |
|---|---|
| `UOV` | The scheme, with the twelve constants from `ovIs` to `ovVCompressedKeys` |
| `Parameters` | The field, the variables, the form of the keys and the liboqs facts of a set, and the lengths of `params.h` |
| `Field` | GF(16) or GF(256), the `_USE_GF16` choice |
| `KeyForm` | The classic keys, the compressed public key, or the compressed public key and the compressed secret key |
| `FieldArithmetic` | The arithmetic of a field on one element and, lane by lane, on words of packed elements, from `gf16.h` and `blas_u32.h` |
| `GF16` | GF(16) = GF(2)[x] / (x^4 + x + 1), with two elements in a byte |
| `GF256` | GF(256) = GF(2)[x] / (x^8 + x^4 + x^3 + x + 1), with one element in a byte |
| `GeneratorPowers` | An entry of a block times x^0 to x^7, so that its product with each scalar is a sum of masked words |
| `PaddedEntries` | Entries of a block in words, each padded to a whole number of words |
| `OilMatrix` | The secret matrix O of v rows and o columns, read where the secret key holds it |
| `BatchedMatrix` | The products of the batched matrices of `parallel_matrix_op.c` and `blas_matrix_ref.c` |
| `LinearSystem` | The Gaussian elimination and the back substitution of `blas_matrix_ref.c` |
| `PublicMap` | The evaluation of the public map of `ov_publicmap.c` and the verification of `ov_verify` |
| `SaltedMessage` | SHAKE256 of the message and the salt: the target of the map and the start of each vinegar hash |
| `KeyGenerator` | The key pairs of `ov_keypair.c`, `expand_sk` and `expand_pk` |
| `Signer` | `ov_sign` and its loop of attempts |

## Parameter sets

| Set | Field | n | m = o | v | Classic public key | Compressed public key | Classic secret key | Compressed secret key | Signature | NIST level |
|---|---|---|---|---|---|---|---|---|---|---|
| `OV-Is` | GF(16) | 160 | 64 | 96 | 412160 | 66576 | 348704 | 32 | 96 | 1 |
| `OV-Ip` | GF(256) | 112 | 44 | 68 | 278432 | 43576 | 237896 | 32 | 128 | 1 |
| `OV-III` | GF(256) | 184 | 72 | 112 | 1225440 | 189232 | 1044320 | 32 | 200 | 3 |
| `OV-V` | GF(256) | 244 | 96 | 148 | 2869440 | 446992 | 2436704 | 32 | 260 | 5 |

A classic set has the classic keys. A `-pkc` set has the compressed public key and the classic secret key. A `-pkc-skc` set has the compressed public key and the compressed secret key. The descriptions hold the facts of `sig_uov_ov_<set>.c`: the version text `Round 2`, the claim EUF-CMA only, and no context support.

## Keys

- A vector packs its elements into bytes: two elements in a byte for GF(16), the first in the low half, and one element in a byte for GF(256).
- An entry of a block is a vector of m elements, one for each equation of the public map. A block stores its entries row after row, and an upper triangular block stores each row from the diagonal on.
- The public map is the upper triangular matrix of the n variables: the block P1 of the pairs of vinegar variables, the block P2 of a vinegar and an oil variable, and the block P3 of the pairs of oil variables. Its value at a point w is the sum over i <= j of `w_i w_j P(i, j)`.
- A classic public key is P1, P2 and P3. A compressed public key is the 16-byte public seed and P3.
- A classic secret key is the 32-byte secret seed, the oil matrix O, the block P1 and the block `S = (P1 + P1^T) O + P2`. O has v rows and o columns and is stored column by column. A compressed secret key is the secret seed.

## Data flow

A key pair:

1. A key pair draws a 32-byte secret seed in one request.
2. SHAKE256 of the secret seed gives the 16-byte public seed and then O.
3. AES-128 in counter mode, keyed with the public seed, gives P1 and then P2. The counter block starts at zero, with a 32-bit big-endian counter in its last four bytes. The generator of the C code keeps the rest of a block for its next call, so P1 and P2 in two calls are one stream.
4. As `calculate_F2_P3` does, the key pair computes `S = P1 O + P2`, then P3, then `S += P1^T O`. P3 is the upper triangular fold of `M = O^T S`: the entry (i, j) is `M(i, j) + M(j, i)` above the diagonal and `M(i, i)` on it.

A signature:

1. The secret key must have the length of the set. A compressed secret key becomes the classic secret key first, as `expand_sk` makes it with `S = P2 + (P1 + P1^T) O`.
2. The signature draws a 16-byte salt in one request.
3. The target y is the first m elements of SHAKE256 of the message and the salt.
4. Attempt n, with the counter byte n, hashes the message, the salt, the secret seed and the counter into the v vinegar values. The oil variables meet a linear system: its matrix is the sum of the rows of S times the vinegar values, and its constant is y plus P1 at the vinegar values.
5. The Gaussian elimination brings the system to row echelon form, with no branch on an element. A singular system starts the next attempt. A nonsingular system gives the oil values x by back substitution.
6. The point is `w = (v + O x, x)`, and the signature is w and the salt.

A verification needs a signature and a public key of the lengths of the set. A compressed public key becomes the classic public key first, as `expand_pk` makes it. The verification evaluates the public map at w and compares the value with SHAKE256 of the message and the salt. The comparison folds the differences of the bytes with an or.

The products compute the same sums as the C functions, in another order where that is faster. The field arithmetic is exact, so the order does not change a byte. A key pair keeps the sums of a row of S in words, and multiplies each entry of P1 by every element of a row of O through the powers of the entry. No branch and no memory index depends on a secret value, except the count of attempts, which the C code also takes from the result of each attempt. The evaluation of the public map adds each entry to the sum of the entries with the same factor `w_i w_j`, as the C code does, because the point is public.

## Edge cases

- A secret key of a wrong length is `OQSError::invalidLength`, with no random byte drawn.
- Every byte string of the right length is a key. A classic secret key of random bytes signs, as in the C library.
- When no attempt finds a nonsingular system, the signature is `OQSError::operationFailed`, as `ov_sign` returns -1. A secret key whose S is zero makes every system zero, so it fails after it draws its salt.
- The C loop counts an attempt before it runs it, and fails when the count reaches 256 after the attempt that succeeds. So a success of the last attempt, of the counter 255, is a failure too. No known input reaches that case, and `theFirstSuccessGivesItsResultExceptAtTheLastAttempt` feeds it to the loop.
- A signature of another length than the set gives `false`, also one that starts with a valid signature, as `crypto_sign_verify` refuses it. A public key of another length gives `false`.
- UOV has no context string. A non-empty context is `OQSError::contextNotSupported` for a signature and `false` for a verification. The empty context gives the plain signature.
- The classic secret key of a compressed secret key is wiped when it is dropped, as the C code frees it with `OQS_MEM_secure_free`.

## Tests

Each test file names the liboqs test that it replicates.

- `KATSig.rs`: `tests/kat_sig.c`. The `single` and `all` digests of all twelve sets equal `tests/KATs/sig/kats.json`. The `all` digests take about 160 seconds of processor time in a test build, so the fast suite ignores them. `cargo test -p oqs-native-uov --test KATSig -- --ignored` runs them, and `parity known-answers --all` proves them in a release build.
- `TestSig.rs`: `tests/test_sig.c` through `SignatureCorrectnessTest`, the facts of each set, the random requests, the length errors, the keys and the signatures that the three forms of a shape share, the failure of a zero S, and a public key made by hand that accepts one signature and refuses it when the same bit changes in two bytes.
- `FuzzTestSig.rs`: `tests/fuzz_test_sig.c` through `SignatureFuzzTest`, with 16 cases for the sets of OV-Is and OV-Ip and 4 cases for the sets of OV-III and OV-V. Random secret keys sign, and a public key made by hand refuses hostile signatures.
- `TestSigMem.rs`: `tests/test_sig_mem.c` through `SignatureMemoryTest`.
- Unit tests: every product and every inverse of both fields against the definition and against the C code, the word products of `gf16v_mul_u32`, and the known answers of the C code for the products of the batched matrices, ten random and four crafted systems of the elimination, the public map, the generator of the public blocks in pieces and in one call, the expansions, the key pairs and the signatures of each shape. A C program that called the internal functions of the liboqs library gave the known answers, see `TestInputs.rs`.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library. `MalformedKeyParity.rs` signs secret keys of random bytes and secret keys with a zero S on both sides, and gives both sides public keys made by hand.
