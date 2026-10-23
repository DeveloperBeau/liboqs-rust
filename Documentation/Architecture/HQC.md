# HQC

## Purpose

`oqs-native-hqc` ports the three HQC KEMs of liboqs: `HQC-1`, `HQC-3` and `HQC-5`. HQC is the Hamming Quasi-Cyclic code-based KEM that NIST selected for standardization, in the version of the specification of 2025-08-22. Each set gives the bytes of the C algorithm of the same name, whose C code is the reference code of the HQC team at commit `161cd4f`.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-hqc` | `Modules/HQC` | `features` |

| Type | Role |
|---|---|
| `HQC` | The KEM, with the constants `hqc1`, `hqc3` and `hqc5` |
| `Parameters` | The parameters of `parameters.h` and the liboqs facts of a set |
| `PublicKeyEncryption` | HQC-PKE: key generation, encryption and decryption, `hqc.c` and `parsing.c` |
| `BinaryVector` | A vector of `n` bits as a polynomial modulo `X^n - 1`: the three samplers, the sum, and the product with the reduction of `gf2x.c` |
| `CarrylessMultiplication` | The Karatsuba product of two binary polynomials of `gf2x.c`, with an exact product of two words at the base |
| `ConcatenatedCode` | The Reed-Solomon code outside and the Reed-Muller code inside, `code.c` |
| `ReedSolomon` | The shortened Reed-Solomon code over GF(2^8): systematic encoding, and decoding with the Berlekamp algorithm with masks, `reed_solomon.c` |
| `AdditiveFFT` | The additive FFT of Gao and Mateer that finds the roots of the error locator polynomial, `fft.c` |
| `GaloisField` | GF(2^8) with the field polynomial `0x11D`, `gf.c` |
| `ReedMuller` | The duplicated RM(1,7) code and its decoder by the Hadamard transform, `reed_muller.c` |
| `HashFunctions` | `G`, `H`, `I`, `J` and the expander, each with its domain byte, `symmetric.c` |

Only `HQC` is public.

## Parameter sets

| Set | `n` | `n1` | `n2` | `omega` | `omega_e`, `omega_r` | `k` | `delta` | Public key | Secret key | Ciphertext | Level |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `HQC-1` | 17669 | 46 | 384 | 66 | 75 | 16 | 15 | 2241 | 2321 | 4433 | 1 |
| `HQC-3` | 35851 | 56 | 640 | 100 | 114 | 24 | 16 | 4514 | 4602 | 8978 | 3 |
| `HQC-5` | 57637 | 90 | 640 | 131 | 149 | 32 | 29 | 7237 | 7333 | 14421 | 5 |

The shared secret has 32 bytes. The Barrett multiplier, the rejection threshold and the lengths follow from `n`, `n1`, `n2` and `k`. The unit tests compare them with the values of `parameters.h` and `kem_hqc.h`.

## Random requests

| Operation | Requests in order |
|---|---|
| Key pair | 32 bytes, `seed_kem` |
| Encapsulation | `k` bytes, the message `m`, then 16 bytes, the salt |
| Decapsulation | none |

The known-answer programs give HQC the SHAKE256 generator of `tests/test_helpers.c`, whose output does not depend on how the requests split it. The base case of the parity checks uses the NIST DRBG, whose output does depend on it. So the base case and the request test of `TestKEM.rs` prove the split, and the known-answer test does not.

## Data flow

The expander of a seed is SHAKE256 of the seed and the domain byte 1. `H` is SHA3-256 with the domain byte 1, `I` and `G` are SHA3-512 with the domain bytes 2 and 0, and `J` is SHA3-256 with the domain byte 3.

1. A key pair draws `seed_kem`. Its expander gives the 32-byte seed of the PKE and then the `k` bytes of `sigma`.
2. `I` of the PKE seed gives the decryption seed and the seed of `h`. The expander of the decryption seed gives `y` and then `x`, each of weight `omega` by rejection sampling. The expander of the seed of `h` gives `h`, with the bits at and above `n` cleared.
3. The public key is the seed of `h` and the bytes of `s = x + y h`. The secret key is the public key, the decryption seed, `sigma` and `seed_kem`.
4. An encapsulation draws `m` and the salt. `G` of `H(pk)`, `m` and the salt gives the shared secret in its first 32 bytes and the seed `theta` in its last 32.
5. The expander of `theta` gives `r2`, then `e`, then `r1`, by Algorithm 5 of ePrint 2021/1631. The ciphertext is `u = r1 + r2 h`, then `v = encode(m) + truncate(s r2 + e)`, then the salt.
6. Decapsulation computes `y` again, decodes `v + truncate(y u)` to `m'`, and encrypts `m'` again with the `theta` of `G(H(pk), m', salt)`.
7. The comparison folds the byte differences of the re-encryption and the ciphertext with an or. A difference gives the rejection secret `J(H(pk), sigma, c)`, with a mask and no branch.

The decoder is the one of the C code. The Reed-Muller decoder sums the copies of each codeword, takes the Hadamard transform and keeps the first largest absolute value. The Reed-Solomon decoder computes the syndromes, the error locator with the Berlekamp algorithm with masks, its roots with the additive FFT, the error evaluator, and the error values by the formula of Forney.

## The product

`vect_mul` of the C code multiplies two vectors of `ceil(n / 64)` words exactly, then folds the bits from `n` to `2 n` back onto the bits from 0 and clears the bits of the last word at and above `n`. `BinaryVector::product` does the same.

`CarrylessMultiplication` splits a product as `karatsuba_mul` does, down to 16 words. There the C code multiplies bit by bit with masks. The port multiplies whole words with integer products of bits four places apart, and gets the high word from the product of the bit reversals. The two forms give the same exact product, and neither has a branch on the values. The word product is much faster in the test build, see `Documentation/Learnings/Families.md`.

## Edge cases

- HQC checks no key and no ciphertext. Every input of the right length gives a result. The C decapsulation returns success also for a rejection, so the port returns the rejection secret and never an error.
- The last byte of `s` in a public key and of `u` in a ciphertext has bits above `n`. The C code keeps them. A product with such a bit can reach past `2 n`, where the reduction of the C code drops it and the ring would fold it again. The port keeps the reduction of the C code, and `HostileInputParity.rs` of `Tools/Parity` proves it with the C library.
- A bit of `u` above `n` always makes the re-encryption differ, so it gives the rejection secret.
- The C code copies the salt of the ciphertext into the re-encryption, so the salt always agrees. A changed salt changes `theta`, and then `u` and `v` differ.
- The decoder decodes every word. More than `delta` errors in the Reed-Solomon code give another message, and the re-encryption then gives the rejection secret.
- Decapsulation reads the public key, the decryption seed and `sigma` from the secret key, and not `seed_kem`. `sigma` changes only the rejection secret.
- liboqs gives HQC no seeded forms: `keypair_derand` and `encaps_derand` return `OQS_ERROR`. Both seeded methods return `OQSError::seedNotSupported`.
- Every input of a wrong length is `OQSError::invalidLength`. Decapsulation checks the ciphertext before the secret key, and encapsulation checks the public key before it draws random bytes.

## Tests

Each test file names the liboqs test that it replicates. liboqs has no vector test for HQC.

- `KATKEM.rs`: `tests/kat_kem.c`. The `single` and `all` digests of the three sets equal `tests/KATs/kem/kats.json`.
- `TestKEM.rs`: `tests/test_kem.c` through `KEMCorrectnessTest`, the random requests and the layout of the secret key, the rejection secret `J` of each changed part of a ciphertext and of a secret key, the same bit changed in two bytes, the refused seeded forms and the length errors.
- `FuzzTestKEM.rs`: `tests/fuzz_test_kem.c` through `KEMFuzzTest`, and random keys and ciphertexts, which give results and never errors.
- `TestKEMMem.rs`: `tests/test_kem_mem.c` through `KEMMemoryTest`.
- Unit tests: the tables of GF(2^8) against `gf.h` and every product against the definition, the generator polynomials against their roots, the additive FFT against the value at every field element, the Reed-Solomon code up to `delta` errors and past it, the Reed-Muller code for every byte and up to 95 flipped bits, each sampler against the stream by hand, the rejection threshold and a repeated position, the word product and the split against the definition, and a product with a bit above `n`.
- `Tools/Parity`: the base case and the seeded variations of each set against the C library, and `HostileInputParity.rs` for hostile keys and ciphertexts.
