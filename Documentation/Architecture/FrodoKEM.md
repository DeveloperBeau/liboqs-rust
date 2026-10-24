# FrodoKEM

## Purpose

`oqs-native-frodokem` ports the twelve FrodoKEM algorithms of liboqs: `FrodoKEM-640-AES`, `FrodoKEM-640-SHAKE`, `FrodoKEM-976-AES`, `FrodoKEM-976-SHAKE`, `FrodoKEM-1344-AES` and `FrodoKEM-1344-SHAKE`, and the ephemeral sets `eFrodoKEM-640-AES` to `eFrodoKEM-1344-SHAKE`. Each gives the bytes of the C algorithm of the same name. liboqs takes its C code from PQCrypto-LWEKE, the reference code of the FrodoKEM team, at commit `a2f9dec8`. The port translates the portable form of that code, which the C oracle builds.

## Parameter sets

| Dimension `n` | Bits `D` of `q = 2^D` | Message bits `B` | Shared secret `L` | Hash | Level |
|---|---|---|---|---|---|
| 640 | 15 | 2 | 16 bytes | SHAKE128 | 1 |
| 976 | 16 | 3 | 24 bytes | SHAKE256 | 3 |
| 1344 | 16 | 4 | 32 bytes | SHAKE256 | 5 |

- Each dimension has an AES set and a SHAKE set. The AES sets make the public matrix `A` with AES-128, and the SHAKE sets with SHAKE128. Every other hash of a set is the hash of its dimension.
- Every set has `n̄ = 8` and a matrix seed of 16 bytes.
- FrodoKEM puts a salt of `2 L` bytes at the end of each ciphertext, and its noise seed has `2 L` bytes. eFrodoKEM has no salt, and its noise seed has `L` bytes. `Parameters` derives both lengths from one flag, so both variants run the same code.

| Sets | Public key | Secret key | Ciphertext of FrodoKEM | Ciphertext of eFrodoKEM |
|---|---|---|---|---|
| 640 | 9616 | 19888 | 9752 | 9720 |
| 976 | 15632 | 31296 | 15792 | 15744 |
| 1344 | 21520 | 43088 | 21696 | 21632 |

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-frodokem` | `Modules/FrodoKEM` | `features` |

| Type | Role |
|---|---|
| `FrodoKEM` | The twelve sets, as the constants `FrodoKEM::frodoKEM640AES` to `FrodoKEM::eFrodoKEM1344SHAKE`, with the key pair, the encapsulation and the decapsulation of `kem.c` and `ekem.c` |
| `Parameters` | The dimension, the bits of the modulus and of the message, the error distribution, the matrix generation, the hash, the lengths of the noise seed and of the salt, and the liboqs facts of a set |
| `MatrixGeneration` | The public matrix `A` of a seed, one row at a time, with AES-128 or SHAKE128 |
| `MatrixArithmetic` | The products `A S + E` and `S' A + E'`, the masks `S' B + E''` and `B' S`, the sums and differences modulo `q`, and the encoding and the decoding of the message |
| `ErrorDistribution` | The noise sampler of `noise.c`, from the table of the cumulative distribution of a set |
| `HashFunction` | SHAKE128 or SHAKE256, the `shake` of the parameter header |
| `Packing` | The packing of `D`-bit values from their high bit, and the little-endian 16-bit form |
| `ConstantTime` | The comparison and the selection of decapsulation, `ct_verify` and `ct_select` |

## Data flow

The key pair:

1. One request of random bytes gives the rejection value `s` of `L` bytes, the noise seed and the 16 bytes `z`.
2. The matrix seed is the 16-byte hash of `z`.
3. The hash of the byte `0x5F` and the noise seed gives `2 n n̄` little-endian 16-bit values. The error distribution turns them into the secret matrix `S`, kept as its transpose, and the error `E`.
4. `B = A S + E`. The public key is the matrix seed and `B` packed with `D` bits for each value.
5. The secret key is `s`, the public key, the secret matrix with two bytes for each value, and the `L`-byte hash of the public key.

The encapsulation:

1. The hash `pkh` of the public key has `L` bytes.
2. One request of random bytes gives the message `mu` of `8 B` bytes and the salt.
3. The hash of `pkh || mu || salt` gives the noise seed and the key `k`.
4. The hash of the byte `0x96` and the noise seed gives the ephemeral secret `S'` and the errors `E'` and `E''`.
5. `B' = S' A + E'`, `V = S' B + E''` and `C = V + Encode(mu)`.
6. The ciphertext is `B'` and `C`, each packed with `D` bits, and the salt. The shared secret is the `L`-byte hash of the ciphertext and `k`.

The decapsulation:

1. `M = C - B' S` with the secret matrix of the secret key, and `mu' = Decode(M)`.
2. The steps 3 to 5 of the encapsulation run again with `pkh` of the secret key, `mu'` and the salt of the ciphertext.
3. The new `B'` is reduced modulo `q`. `ConstantTime` compares `B'` and `C` of the ciphertext with the new ones and selects `k'` when both are equal, and `s` when one differs, with no branch.
4. The shared secret is the `L`-byte hash of the ciphertext and the selected key.

## Random requests

The key pair draws `L` plus the noise seed plus 16 bytes in one request, as `crypto_kem_keypair` does. The encapsulation draws `8 B` plus the salt in one request, as `crypto_kem_enc` does. The decapsulation draws nothing.

| Sets | Key pair | Encapsulation |
|---|---|---|
| FrodoKEM-640 | 64 bytes | 48 bytes |
| FrodoKEM-976 | 88 bytes | 72 bytes |
| FrodoKEM-1344 | 112 bytes | 96 bytes |
| eFrodoKEM-640 | 48 bytes | 16 bytes |
| eFrodoKEM-976 | 64 bytes | 24 bytes |
| eFrodoKEM-1344 | 80 bytes | 32 bytes |

## Memory

The C code keeps its matrices on the stack. The port keeps every matrix on the heap, and the stack holds only small values, so each operation runs on a thread with the default stack. The public matrix is never stored as a whole: `MatrixGeneration` makes one row at a time in buffers of `2 n` bytes.

The peak heap of each operation, with the values that it returns, measured with a counting allocator:

| Dimension | Key pair | Encapsulation | Decapsulation |
|---|---|---|---|
| 640 | 68.9 KiB | 40.6 KiB | 60.9 KiB |
| 976 | 106.9 KiB | 61.7 KiB | 92.4 KiB |
| 1344 | 147.2 KiB | 84.7 KiB | 127.0 KiB |

The AES and the SHAKE sets need the same memory, and the ephemeral sets need up to 96 bytes less.

## Edge cases

- FrodoKEM checks neither key, as the C code does. Any public key and any secret key of the right length give a result.
- A changed ciphertext gives the implicit-rejection secret, the hash of the ciphertext and of `s`. The comparison gathers the differences of the 16-bit values with an or, as `ct_verify` does, and joins the comparisons of `B'` and of `C` with an or.
- Each sum and each product is modulo `2^16`, with explicit wrapping operations, as the C code computes it. Only the results that the C code reduces modulo `q` are reduced: the two masks, the sums and differences, and the new `B'` of decapsulation before the comparison. Packing keeps the low `D` bits of the other values.
- The C code makes the public matrix four rows or eight columns at a time. The port makes it one row at a time. The sums modulo `2^16` do not depend on the order.
- liboqs gives FrodoKEM no seeded forms, because its `keypair_derand` and `encaps_derand` return `OQS_ERROR`. Both seeded methods return `OQSError::seedNotSupported`.
- Every input of a wrong length is `OQSError::invalidLength`. Decapsulation checks the ciphertext first.
- The C code wipes its intermediate buffers with `OQS_MEM_cleanse`. The port keeps the random bytes, the hash inputs and outputs, the keys `k` and `k'`, the secret key and the shared secret in `SecretBytes`, which wipes them. The 16-bit noise matrices are plain vectors, as the polynomials of ML-KEM are.

## Tests

Each test file names the liboqs test that it replicates.

- `KATKEM.rs`: `tests/kat_kem.c`. The `single` digest of each set equals `tests/KATs/kem/kats.json`. The `all` digests take up to a minute for each set in the dev profile, so they are ignored by default. `cargo test --release -p oqs-native-frodokem -- --ignored` runs them.
- `TestKEM.rs`: `tests/test_kem.c` through `KEMCorrectnessTest`, the size of each random request, the layout of the keys, the salt of the ciphertext, the rejection secret for changed bytes of `B'`, of `C` and of the salt, the same bit changed in two values of `B'` and of `C`, keys that the C code accepts, the length errors, the refused seeded forms and the facts of each C file.
- `FuzzTestKEM.rs`: `tests/fuzz_test_kem.c` through `KEMFuzzTest`, the cases 0 to 3 of each set, and random keys and ciphertexts.
- `TestKEMMem.rs`: `tests/test_kem_mem.c` through `KEMMemoryTest`.
- Unit tests: the matrix products, the masks, the sums and differences, the encoding and the decoding, the noise sampler on every 16-bit value, the packing and `ct_verify` against digests of the internal C functions of liboqs on the same inputs. The counts of the noise sampler against the probabilities of the tables, and packing and rounding examples written by hand.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library.

liboqs has no vector test for FrodoKEM, so the crate has no vector file.
