# ML-DSA

## Purpose

`oqs-native-ml-dsa` ports the three lattice signature schemes of liboqs of FIPS 204: `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87`. Each gives the bytes of the C algorithm of the same name, whose code is mldsa-native.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-ml-dsa` | `Modules/MLDSA` | `features` |

| Type | Role |
|---|---|
| `MLDSA` | ML-DSA of FIPS 204, with the constants `mldsa44`, `mldsa65` and `mldsa87`, the `Signing` interface and the internal forms of the vector tests |
| `PreHashAlgorithm` | The twelve hash functions of HashML-DSA, each with its object identifier and its hash length |
| `Parameters` | The parameters of FIPS 204, Table 1, the lengths of the keys and the signature of Table 2, the number of signing attempts of mldsa-native, and the liboqs facts of a set |
| `InternalAlgorithms` | ML-DSA.KeyGen_internal, ML-DSA.Sign_internal and ML-DSA.Verify_internal of FIPS 204, Algorithms 6 to 8, and the hint encoding |
| `Polynomial` | The arithmetic modulo q of mldsa-native: the NTT in the Montgomery domain, the reductions, the rounding, the norm check, the sampling and the bit packing |

## Parameter sets

| Set | k | l | eta | tau | gamma1 | gamma2 | omega | NIST level | Public key | Secret key | Signature |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `ML-DSA-44` | 4 | 4 | 2 | 39 | 2^17 | (q - 1) / 88 | 80 | 2 | 1312 | 2560 | 2420 |
| `ML-DSA-65` | 6 | 5 | 4 | 49 | 2^19 | (q - 1) / 32 | 55 | 3 | 1952 | 4032 | 3309 |
| `ML-DSA-87` | 8 | 7 | 2 | 60 | 2^19 | (q - 1) / 32 | 75 | 5 | 2592 | 4896 | 4627 |

The descriptions hold the facts of `sig_ml_dsa_44.c`, `sig_ml_dsa_65.c` and `sig_ml_dsa_87.c`: the version text `FIPS204`, the claims EUF-CMA and SUF-CMA, and context support.

## Data flow

1. A key pair draws 32 random bytes in one request, the seed. SHAKE256 of the seed, k and l gives rho, rho' and K.
2. The matrix A comes from SHAKE128 of rho and two index bytes, by rejection sampling. s1 and s2 come from SHAKE256 of rho' and a nonce, by rejection sampling of half bytes.
3. t = A s1 + s2 is computed row by row, with the reductions of mldsa-native, and Power2Round splits it into t1 for the public key and t0 for the secret key. The secret key is rho, K, tr = H(pk), s1, s2 and t0.
4. A signature checks the length of the secret key and the context first. Then it draws 32 random bytes in one request, the randomness rnd. A context of more than 255 bytes is refused before the request, as in the C code.
5. The message representative is mu = SHAKE256(tr || M', 64). For a signature, M' is the byte 0, the context length, the context and the message. For a pre-hash signature, M' is the byte 1, the context length, the context, the object identifier of the hash function and the hash.
6. The signing seed is rho'' = SHAKE256(K || rnd || mu, 64). Attempt n of the rejection loop samples the mask y from rho'' with the nonces `l n` to `l n + l - 1`. It computes w = A y, the commitment hash of mu and w1, the challenge c, z = y + c s1 and the hints. A norm check or the hint count can reject the attempt, and then the next attempt starts. After `(2^16 - 1 - l) / l` rejected attempts the signature fails, as `MLD_ERR_SIGN_ATTEMPTS_EXHAUSTED` of the C code.
7. A verification checks the lengths, the norm of z and the hint encoding. Then it computes w1 from A z - c t1 2^d and the hints, and compares the commitment hash with no branch on the bytes.

The arithmetic keeps the signed representatives of mldsa-native at each step: the Montgomery reduction, `reduce32`, `caddq`, the inner products in 64 bits and the decomposition by multiplication. Each intermediate value is the value of the C code, not only the same value modulo q, so the bytes agree also for a malformed secret key.

## Edge cases

- Every input of a wrong length is `OQSError::invalidLength`: the secret key, the randomness of the internal forms, an external mu of other than 64 bytes and a hash of other than the length of its function.
- A context of more than 255 bytes is `OQSError::contextTooLong`, and a verification under it is false.
- The secret key is decoded with no range check, as in mldsa-native, so a key with coefficients out of the range of eta signs. `MalformedKeyParity.rs` in `Tools/Parity` shows that the C library gives the same signatures.
- A signature or a public key of a wrong length is not valid. A verification never panics.
- When every attempt of the rejection loop fails, the signature is `OQSError::operationFailed`. A secret key decodes to bounded coefficients, and no known input makes each of the thousands of attempts fail, so the path has no test. A unit test of `Parameters` checks the number of attempts against `MLD_NONCE_UB` of the C code.
- liboqs has no public API for the internal forms. `internalSignature`, `isValidInternalSignature`, `preHashSignature` and `isValidPreHashSignature` give the entry points that `tests/vectors_sig.c` calls, `signature_internal` with the external mu flag, `verify_internal`, `signature_pre_hash_internal` and `verify_pre_hash_internal`, each with an empty prefix where the C test passes none.

## Tests

Each test file names the liboqs test that it replicates.

- `KATSig.rs`: `tests/kat_sig.c`. The `single` and `all` digests of the three sets equal `tests/KATs/sig/kats.json`.
- `TestSig.rs`: `tests/test_sig.c` through `SignatureCorrectnessTest`, the random requests, the length errors, the order of the context check and the randomness, and each form as the internal signature of its formatted message.
- `FuzzTestSig.rs`: `tests/fuzz_test_sig.c` through `SignatureFuzzTest`, random secret keys that sign, and random signatures, keys and representatives that are not valid.
- `TestSigMem.rs`: `tests/test_sig_mem.c` through `SignatureMemoryTest`.
- `VectorsSig.rs`: `tests/test_acvp_vectors.py` and `tests/vectors_sig.c`. The 75 key generation, 360 signature generation and 180 verification vectors of ACVP-Server, in the external, pre-hash and internal forms. The Python test hashes the message of a pre-hash vector with `hashlib`, and this test hashes it with `Modules/SHA2` and `Modules/SHA3`.
- `WycheproofVectors.rs`: `tests/test_wycheproof_vectors.py`. The sign vectors with expanded keys and with seeds, and the verify vectors, valid and invalid.
- Unit tests of `Parameters`: each constant of each set against `params.h` of mldsa-native and FIPS 204, Table 1, with the number of signing attempts, the lengths against Table 2, and the facts of each liboqs file.
- Unit tests of `Polynomial`: the twiddle factors of mldsa-native and their definition, every value of the decomposition, of UseHint and of Power2Round against FIPS 204, the reductions on seeded values and on the edges of their domains, the NTT product against the schoolbook product, the packing against the packing functions of mldsa-native, and the uniform sampling of two seeds whose streams hold a candidate of q against `poly_uniform` of mldsa-native.
- Unit tests of `InternalAlgorithms`: the hint encoding and each malformed hint encoding that mldsa-native refuses.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library. `MalformedKeyParity.rs` signs on both sides with secret keys whose s1 or s2 hold coefficients out of range, whose t0 does not belong to the key pair, or whose bytes are all random.
