# SLH-DSA

## Purpose

`oqs-native-slh-dsa` ports the 156 SLH-DSA schemes of liboqs, the stateless hash-based signature scheme of FIPS 205. Each gives the bytes of the C scheme of the same name. The C code is slhdsa-c of the PQ Code Package, with the liboqs patch `internal_api.patch` and the generated wrappers of each scheme.

## Parameter sets and schemes

FIPS 205 has twelve parameter sets: SHA2 and SHAKE, each in categories 1, 3 and 5, each small (`s`) or fast (`f`). liboqs gives each set two kinds of scheme:

- The pure form `SLH_DSA_PURE_<set>`, such as `SLH_DSA_PURE_SHA2_128S`, which signs the message with a context, FIPS 205, Algorithm 22.
- The pre-hash form `SLH_DSA_<function>_PREHASH_<set>`, such as `SLH_DSA_SHA2_256_PREHASH_SHAKE_192F`, HashSLH-DSA of FIPS 205, Algorithm 23, which signs the digest of the message with one of twelve hash functions.

| Set | `n` | `h` | `d` | `h'` | `a` | `k` | `m` | Category | Signature |
|---|---|---|---|---|---|---|---|---|---|
| `SHA2_128S`, `SHAKE_128S` | 16 | 63 | 7 | 9 | 12 | 14 | 30 | 1 | 7856 |
| `SHA2_128F`, `SHAKE_128F` | 16 | 66 | 22 | 3 | 6 | 33 | 34 | 1 | 17088 |
| `SHA2_192S`, `SHAKE_192S` | 24 | 63 | 7 | 9 | 14 | 17 | 39 | 3 | 16224 |
| `SHA2_192F`, `SHAKE_192F` | 24 | 66 | 22 | 3 | 8 | 33 | 42 | 3 | 35664 |
| `SHA2_256S`, `SHAKE_256S` | 32 | 64 | 8 | 8 | 14 | 22 | 47 | 5 | 29792 |
| `SHA2_256F`, `SHAKE_256F` | 32 | 68 | 17 | 4 | 9 | 35 | 49 | 5 | 49856 |

Every set has `lg_w = 4`, a public key of `2 n` bytes and a secret key of `4 n` bytes. The pre-hash functions are SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 with 32 bytes and SHAKE256 with 64 bytes. Every scheme has the version `FIPS205`, claims EUF-CMA and not SUF-CMA, and takes a context of up to 255 bytes.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-slh-dsa` | `Modules/SLHDSA` | `features` |

| Type | Role |
|---|---|
| `SLHDSA` | One scheme: a parameter set and the pure form or a pre-hash function. The constants `sha2128s` to `shake256f`, `preHashed`, and `schemes`, all 156 schemes in liboqs order |
| `PreHash` | The twelve hash functions of the pre-hash form, with their object identifiers |
| `Parameters` | The parameter sets of FIPS 205, Table 2, and the lengths that follow from them |
| `HashContext` | The `slh_var_t` of the C code: the key parts, the address, and the functions `F`, `H`, `T_l`, `PRF`, `PRF_msg` and `H_msg` of the SHA2 or the SHAKE sets |
| `Hypertree` | WOTS+, the XMSS trees and the hypertree, FIPS 205, Algorithms 5 to 13 |
| `FORS` | The forest of random subsets, FIPS 205, Algorithms 14 to 17 |
| `Address` | The address `ADRS` and its compressed form of the SHA2 sets |
| `ByteConversion` | `toInt`, `toByte` and `base_2b` of FIPS 205, Section 4.4 |
| `HashFamily` | SHA2 or SHAKE |
| `SchemeName` | The liboqs name of a scheme, built at compile time from the name of the set and of the function |

The crate uses `SHA224` to `SHA512256` of `oqs-native-sha2` and `SHA3224` to `SHAKE256` of `oqs-native-sha3` in place of the SHA-2 and SHA-3 code of the C folder. `signInternal` and `isValidSignatureInternal` are the internal functions `slh_sign_internal` and `slh_verify_internal`, which the vector tests call, as the C vector program does.

## Data flow

1. A key pair draws `SK.seed || SK.prf || PK.seed` in one request of `3 n` bytes. `PK.root` is the root of the top XMSS tree. The secret key is `SK.seed || SK.prf || PK.seed || PK.root` and the public key is `PK.seed || PK.root`.
2. A signature draws the additional randomness `addrnd` in one request of `n` bytes, before the check of the context.
3. The pure form passes the context to `PRF_msg` and `H_msg`, which hash `toByte(0, 1) || toByte(|ctx|, 1) || ctx` before the message. The pre-hash form signs the message `toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M)` with the internal function.
4. `PRF_msg` gives the randomizer `R`, the first `n` bytes of the signature, and `H_msg` gives the digest of `m` bytes. The digest selects the FORS leaves, the XMSS tree and the leaf of the bottom layer.
5. `FORS` signs the digest, and the hypertree signs the FORS public key, which the C code computes from the FORS signature. Each layer of the hypertree signs the root of the layer below, which it computes from the signature of that layer.
6. A verification computes the FORS public key and each root from the signature, and compares the last root with `PK.root`.

A SHA2 set hashes `PK.seed` padded to a whole block before each input of `F`, `H`, `T_l` and `PRF`. `HashContext` keeps the SHA-256 and the SHA-512 state after that block, as the C code does, and starts each hash from a copy. Each function of the C code changes the address in the same order, and the port keeps that order, so every hash sees the address of the C code.

## Edge cases

- A secret key of a wrong length is `OQSError::invalidLength`, before any random request. The C code reads `4 n` bytes and checks nothing.
- A context of more than 255 bytes is `OQSError::contextTooLong`, after the random request of `addrnd`, as in the C code. A verification with such a context is false.
- A verification of a signature or a public key of a wrong length is false. The C code reads `R` from the signature before it checks the length. The port checks the lengths first, so a short signature is false, never a read past its end.
- The signature uses the `PK.root` and the `PK.seed` of the secret key. A secret key with another root signs, and the public key rejects the signature, as in the C code. A changed `SK.prf` changes only `R`, so the signature stays valid.
- For `SHA2_256F` and `SHAKE_256F` the tree index has 64 bits, `h - h' = 64`, so the digest gives it with no mask.
- The C code computes `len_2` with a shortcut for `lg_w = 4`. The port has the one width of FIPS 205, so `len_2 = 3` for every set.

## Tests

Each test file names the liboqs test that it replicates. `SuiteSample` of `oqs-native-algorithm-tests` picks the schemes of the default suite: the six pure fast sets, and each pre-hash function with `SHA2_128F`. The tests of every scheme are behind `#[ignore]`, with the reason.

- `KATSig.rs`: `tests/kat_sig.c` and `tests/test_kat.py`. liboqs has no known answers for SLH-DSA: `kat_sig` has no signed-message form for it, `kats.json` has no digest, and the Python tests skip it. The test proves that the port gives the same refusal.
- `TestSig.rs`: `tests/test_sig.c` through `SignatureCorrectnessTest`, which steps through the context lengths by 61, and the rejection paths: the lengths, the context, the random requests, changed signatures, messages, contexts and keys, the forms of a set against each other, and the messages of FIPS 205, Algorithms 22 and 23.
- `FuzzTestSig.rs`: `tests/fuzz_test_sig.c` through `SignatureFuzzTest`, and random secret keys, signatures, public keys and contexts.
- `TestSigMem.rs`: `tests/test_sig_mem.c` through `SignatureMemoryTest`, for the sample and the pure small sets.
- `VectorsSig.rs`: `tests/test_acvp_vectors.py` and `tests/vectors_sig.c`. All 120 key generation vectors, 624 signature vectors and 504 verification vectors of ACVP-Server, and the key generation vectors with all 13 forms of each set. The 312 signature vectors of the small sets and the forms of the small sets are behind `#[ignore]`. The Python script maps the hash names `SHA2-512/224` and `SHA2-512/256` to no liboqs name and skips their 48 signature vectors and 26 verification vectors. The Rust test runs them.
- Unit tests: the parameters and lengths of FIPS 205, Table 2, the address layout and its compressed form, `base_2b` and the checksum digits by hand, the object identifiers, HMAC against RFC 4231, MGF1 against an independent model, and the round trips of WOTS+, XMSS, the hypertree and FORS.
- `Tools/Parity`: the base case and seeded variations of each scheme against the C library.
