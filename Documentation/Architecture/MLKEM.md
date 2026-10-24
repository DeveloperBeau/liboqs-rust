# ML-KEM and Kyber

## Purpose

`oqs-native-ml-kem` ports the six lattice KEMs of liboqs: `ML-KEM-512`, `ML-KEM-768` and `ML-KEM-1024` of FIPS 203, and `Kyber512`, `Kyber768` and `Kyber1024` of round 3 of the NIST process. Each gives the bytes of the C algorithm of the same name.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-ml-kem` | `Modules/MLKEM` | `features` |

| Type | Role |
|---|---|
| `MLKEM` | ML-KEM of FIPS 203, with the constants `mlkem512`, `mlkem768` and `mlkem1024` |
| `Kyber` | Kyber of round 3, with the constants `kyber512`, `kyber768` and `kyber1024` |
| `Parameters` | The rank, the noise widths, the compression widths and the liboqs facts of a set |
| `PublicKeyEncryption` | K-PKE of FIPS 203, Algorithms 13 to 15, which both KEMs share |
| `Polynomial` | The arithmetic modulo 3329: the NTT, the products, the encodings, the compression and the sampling |

## Data flow

1. A key pair of ML-KEM draws 64 random bytes in one request: the seed `d` and the rejection seed `z`. A key pair of Kyber draws two requests of 32 bytes, `d` and then `z`, as its reference code does.
2. K-PKE expands `d` with SHA3-512. ML-KEM hashes `d` with the rank byte, as FIPS 203 says, and Kyber hashes `d` alone.
3. The matrix comes from SHAKE128 by rejection sampling, and the secret and noise vectors from SHAKE256 by the centered binomial distribution.
4. The secret key is the K-PKE key, the public key, the SHA3-256 of the public key, and `z`.
5. An encapsulation of ML-KEM draws the 32-byte message and uses it as it is. Kyber hashes it with SHA3-256 first, and its shared secret is the SHAKE256 of the key and of the SHA3-256 of the ciphertext.
6. Decapsulation decrypts, encrypts again and compares the two ciphertexts with no branch on the result. A difference gives the rejection secret: `SHAKE256(z || c)` for ML-KEM, and the SHAKE256 of `z` and of the ciphertext hash for Kyber.

The arithmetic keeps each coefficient canonical below `q`. The outputs of FIPS 203 are canonical values, so a correct implementation gives the bytes of mlkem-native, the C code of ML-KEM in liboqs.

## Edge cases

- ML-KEM checks that each coefficient of a public key is below `q`, the modulus check of FIPS 203, Section 7.2. A failed check is `OQSError::operationFailed`.
- ML-KEM checks the SHA3-256 of the public key in a secret key, the hash check of FIPS 203, Section 7.3. A failed check is `OQSError::operationFailed`.
- Kyber checks neither key, as its reference code does. A coefficient above `q` is reduced, which gives the bytes of the C code.
- liboqs gives Kyber no seeded forms, so both seeded methods of Kyber return `OQSError::seedNotSupported`.
- liboqs names a different reference commit as the version of Kyber512 than of Kyber768 and Kyber1024. `Parameters` keeps each one.
- Every input of a wrong length is `OQSError::invalidLength`.

## Tests

Each test file names the liboqs test that it replicates.

- `KATKEM.rs`: `tests/kat_kem.c`. The `single` and `all` digests of all six sets equal `tests/KATs/kem/kats.json`.
- `TestKEM.rs`: `tests/test_kem.c` through `KEMCorrectnessTest`, the rejection cases of ML-KEM in that file, the rejection of Kyber, the key checks, the seeded forms and the length errors.
- `FuzzTestKEM.rs`: `tests/fuzz_test_kem.c` through `KEMFuzzTest`, and random keys and ciphertexts.
- `TestKEMMem.rs`: `tests/test_kem_mem.c` through `KEMMemoryTest`.
- `VectorsKEM.rs`: `tests/test_acvp_vectors.py` and `tests/vectors_kem.c`. All 180 ML-KEM vectors of ACVP-Server.
- `WycheproofVectors.rs`: `tests/test_wycheproof_vectors.py`. The key generation, encapsulation and decapsulation vectors of Wycheproof, valid and invalid.
- Unit tests of `Polynomial`: the NTT product against the schoolbook product, the tables of FIPS 203, every value of the reductions and of the compression, and the encodings.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library.
