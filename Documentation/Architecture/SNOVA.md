# SNOVA

## Purpose

`oqs-native-snova` ports the twelve SNOVA signature schemes of liboqs, from `SNOVA_24_5_4` to `SNOVA_29_6_5`. Each gives the bytes of the C algorithm of the same name. The C code is the optimized code of the SNOVA team, commit `1c3ca6f4` of vacuas/SNOVA, with the version text `round2`. liboqs compiles one copy of the same code for each set, with the switches `v_SNOVA`, `o_SNOVA`, `l_SNOVA`, `PK_EXPAND_SHAKE` and `sk_is_seed` of `src/sig/snova/CMakeLists.txt`. The oracle build of liboqs enables the portable code with `OPTIMISATION=1`, not the AVX2 or the NEON code.

The C code computes in GF(16), the field `Z2[x] / (x^4 + x + 1)`, in two forms. An element in a nibble multiplies with the table `mt4b`. The spread form holds coefficient `i` of an element at bit `3 i` of a 32-bit integer, so one integer product is a product of polynomials, and many products add with an exclusive or before one reduction. The port keeps each form where the C code uses it, so every intermediate value is the value of the C code.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-snova` | `Modules/SNOVA` | `features` |

| Type | Role |
|---|---|
| `SNOVA` | The scheme, with the constants `snova24x5x4`, `snova24x5x4SHAKE`, `snova24x5x4WithExpandedSecretKey`, `snova24x5x4SHAKEWithExpandedSecretKey`, `snova37x17x2`, `snova25x8x3`, `snova56x25x2`, `snova49x11x3`, `snova37x8x4`, `snova24x5x5`, `snova60x10x4` and `snova29x6x5` |
| `Parameters` | The numbers v, o and l, the two switches and the liboqs facts of a set, and the sizes of `deriv_params.h` |
| `PublicKeyExpansion` | The expansion of the public seed, AES-128 or SHAKE128 in counter mode, `pk_expand` |
| `SecretKeyForm` | The secret key as the two seeds or as the expanded key, `sk_is_seed` |
| `FieldArithmetic` | GF(16) in nibbles with the table `mt4b`, and in the spread form of `snova_kernel.h` |
| `MatrixRing` | The `l x l` matrices: the powers of S, the determinant, `be_invertible_by_add_aS`, and the elements of F16[S] of `gen_a_FqS` and `gen_a_FqS_ct` |
| `NibblePacking` | The four `convert_*` packings of `snova_common.c` |
| `PublicMap` | P11, P12, P21, A, B, Q1 and Q2 of a public seed, `gen_A_B_Q_P`, with the fixed matrices of `gen_ABQ` |
| `CentralMap` | F11, F12 and F21 of `gen_F_opt` |
| `SigningKey` | The secret key that a signature uses, `sk_gf16`, and the packing of the expanded key |
| `KeyGenerator` | T12 of `gen_seeds_and_T12`, P22 of `gen_P22_opt`, and the key pair of `generate_keys_core` |
| `MessageHashing` | The SHAKE256 hashes: the digest of the message, the signed hash and the vinegar values |
| `Signer` | `sign_digest_core_opt`: the attempts, the linear system of the oil values and its solution |
| `Verifier` | `verify_signture_opt_core`: the public map at the variables of a signature |

## Parameter sets

| Set | v | o | l | Public seed | Secret key | NIST level | Public key | Secret key | Signature |
|---|---|---|---|---|---|---|---|---|---|
| `SNOVA_24_5_4` | 24 | 5 | 4 | AES-128 | seeds | 1 | 1016 | 48 | 248 |
| `SNOVA_24_5_4_SHAKE` | 24 | 5 | 4 | SHAKE128 | seeds | 1 | 1016 | 48 | 248 |
| `SNOVA_24_5_4_esk` | 24 | 5 | 4 | AES-128 | expanded | 1 | 1016 | 36848 | 248 |
| `SNOVA_24_5_4_SHAKE_esk` | 24 | 5 | 4 | SHAKE128 | expanded | 1 | 1016 | 36848 | 248 |
| `SNOVA_37_17_2` | 37 | 17 | 2 | AES-128 | seeds | 1 | 9842 | 48 | 124 |
| `SNOVA_25_8_3` | 25 | 8 | 3 | AES-128 | seeds | 1 | 2320 | 48 | 165 |
| `SNOVA_56_25_2` | 56 | 25 | 2 | AES-128 | seeds | 3 | 31266 | 48 | 178 |
| `SNOVA_49_11_3` | 49 | 11 | 3 | AES-128 | seeds | 3 | 6006 | 48 | 286 |
| `SNOVA_37_8_4` | 37 | 8 | 4 | AES-128 | seeds | 3 | 4112 | 48 | 376 |
| `SNOVA_24_5_5` | 24 | 5 | 5 | AES-128 | seeds | 3 | 1579 | 48 | 379 |
| `SNOVA_60_10_4` | 60 | 10 | 4 | AES-128 | seeds | 5 | 8016 | 48 | 576 |
| `SNOVA_29_6_5` | 29 | 6 | 5 | AES-128 | seeds | 5 | 2716 | 48 | 454 |

The descriptions hold the facts of `sig_snova_<set>.c`: the version text `round2`, the claim EUF-CMA and not SUF-CMA, and no context support. A set has `n = v + o` variables, `m = o` equations, and `alpha = l^2 + l` terms in each equation.

## Data flow

A key pair:

1. A key pair draws 48 bytes in one request: the 16-byte public seed, then the 32-byte secret seed.
2. The public seed expands into the public map. The SHAKE sets take SHAKE128 in counter mode: block `i` is the first 168 bytes of SHAKE128 of the seed and `i` in 8 little-endian bytes. The other sets take AES-128 in counter mode, with the seed as the key and a zero vector. The elements give P11, P12, P21, A and B in that order, and the last bytes give `l` coefficients for each matrix Q1 and Q2.
3. A matrix A or B with determinant zero gets `1 S`, `2 S` and so on added in turn until its determinant is not zero. Each Q1 and Q2 is `c0 + c1 S + ... + c(l-1) S^(l-1)`, with a last coefficient of zero replaced by `16 - c0`, or 15 for `c0 = 0`. For a rank below 4, SHAKE256 of the text `SNOVA_ABQ` gives fixed matrices A, B, Q1 and Q2 in place of those of the seed.
4. SHAKE256 of the secret seed gives `l` coefficients for each of the `v x o` matrices T12, each an element of F16[S] in the same way, computed with no branch.
5. The central map is `F11 = P11`, `F12 = P12 + P11 T12` and `F21 = P21 + T12' P11`, where `T12'` takes the blocks of T12 in transposed places. The blocks P22 are `T12' F12 + P21 T12`.
6. The public key is the public seed and the packed P22. The secret key of a set with seeds is the 48 bytes of the seeds. The expanded key of an `_esk` set is A, B, Q1, Q2, T12, F11, F12 and F21 packed in halves, then the two seeds.

A signature:

1. The secret key must have the length of the set. The digest of the message is SHAKE256 of 64 bytes.
2. The signature draws a 16-byte salt in one request.
3. A key of seeds expands as in the key pair. An expanded key unpacks with no check.
4. The signed hash is SHAKE256 of the public seed, the digest and the salt, `o l^2` elements.
5. Attempt `k`, from 1 to 254, takes the vinegar values from SHAKE256 of the secret seed, the digest, the salt and the byte `k`. The central map at the vinegar values gives a linear system of `o l^2` equations in the oil values, which a Gaussian elimination in constant time solves. A singular system starts the next attempt. When all 254 attempts fail, the signature fails, as the return value -1 of the C code.
6. The signature is the vinegar values plus T12 times the oil values, then the oil values, packed, then the salt.

A verification checks the lengths of the signature and of the public key. It expands the public map of the public seed of the key, unpacks P22, evaluates the public map at the variables of the signature and compares the packed result with the signed hash of the public seed, the digest and the salt of the signature.

## Edge cases

- A secret key of a wrong length is `OQSError::invalidLength`, before any random byte. A signature or a public key of a wrong length gives `false`.
- SNOVA has no context string. A non-empty context is `OQSError::contextNotSupported` for a signature and `false` for a verification. The empty context gives the plain signature.
- Any 48 bytes are a secret key of the seed form. An expanded key unpacks with no check, so any bytes sign. An expanded key with zero matrices makes every linear system zero, so all 254 attempts fail with `OQSError::operationFailed`, in the C library and in the port. A key pair never fails.
- An odd count of elements leaves the high half of the last byte unread. The signatures of `SNOVA_24_5_5`, `SNOVA_25_8_3` and `SNOVA_29_6_5` and the public keys of `SNOVA_24_5_5` and `SNOVA_49_11_3` have an odd count, so a signature or a public key with that half changed verifies, in the C library and in the port. SNOVA claims EUF-CMA only.
- When `o l` is odd, the comparison clears the high half of the last byte of the signed hash, as `verify_signture_opt_core` does for `SNOVA_24_5_5` and `SNOVA_49_11_3`.
- The fixed matrices Q1 and Q2 of the ranks below 4 take their coefficients from the byte `alpha l^2` of the output of SHAKE256, inside the bytes of the matrices A, as `gen_ABQ` reads them.
- The C code of the verification has a second loop order for `l = 4`. It exclusive-ors the same products into each value, so the port has one loop order.
- The packing of an expanded key in the C code reads `2 ceil(N / 2)` elements of a structure, for `N` elements of the matrices. `N` is even for the only rank with an expanded key, so no byte of the public key follows them.
- `oqs_snova.c` passes the length of the message to `shake256` as an `int`. The oracle build sign-extends its low 32 bits, so for a message of `2^31` bytes or more the C code reads past the message or hashes only a part of it. The port hashes the whole message. No test reaches that length.

## Tests

Each test file names the liboqs test that it replicates.

- `KATSig.rs`: `tests/kat_sig.c`. The `single` digests of the twelve sets equal `tests/KATs/sig/kats.json`. The `all` digests take about 70 seconds of processor time in a test build, so the fast suite ignores them, and `cargo test -p oqs-native-snova --test KATSig -- --ignored` runs them. `parity known-answers` proves them in a release build.
- `TestSig.rs`: `tests/test_sig.c` through `SignatureCorrectnessTest` for each set, the facts of each set, the random requests, the keys of each form, the length errors, each changed part of a signature or a key, the unread high halves on both sides of their rule, the refused context, and the expanded keys of any bytes and of zero matrices.
- `FuzzTestSig.rs`: `tests/fuzz_test_sig.c` through `SignatureFuzzTest`, six cases for each set, random secret keys that sign, and random signatures and public keys that are refused.
- `TestSigMem.rs`: `tests/test_sig_mem.c` through `SignatureMemoryTest`.
- Unit tests: the product table and the spread form against the polynomial products, the reduction for every polynomial up to degree 10, the inverse, the matrices S and their powers, the determinant against the sum over all permutations, the additions of `be_invertible_by_add_aS`, both forms of the elements of F16[S] for every coefficient list of the ranks 2 to 4, the packings against the examples of `snova_common.c`, and the attempt loop and a singular first attempt. The known answers of the C code are digests of `OutputDigest` of the outputs of the internal functions of the oracle library for each set: `AES_128_CTR` and `snova_shake` at each length, the keys of `generate_keys_ssk` and `generate_keys_esk`, the expanded keys of `expand_public_pack` and `expand_secret`, and the signature of `sign_digest_ssk` and `sign_digest_esk`.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library. `MalformedKeyParity.rs` signs expanded keys of random bytes and of zero matrices on both sides. `UnreadBitParity.rs` verifies signatures and public keys with a changed high half of their last byte on both sides.
