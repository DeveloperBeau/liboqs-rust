# BIKE

## Purpose

`oqs-native-bike` ports the three BIKE KEMs of liboqs: `BIKE-L1`, `BIKE-L3` and `BIKE-L5`, the bit flipping key encapsulation of round 4 of the NIST process. Each gives the bytes of the C algorithm of the same name. The C code is the additional implementation of the BIKE team in its portable form, the form that the oracle builds, with SHA3-384 and a pseudorandom function on SHAKE256.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-bike` | `Modules/BIKE` | `features` |

| Type | Role |
|---|---|
| `BIKE` | The KEM, with the constants `bikeL1`, `bikeL3` and `bikeL5`, and the functions `L` and `K` |
| `Parameters` | The block length, the weights, the thresholds, the tables of the inversion, the layout of the secret key and the liboqs facts of a set |
| `PolynomialRing` | The ring `GF(2)[x] / (x^r - 1)`: the product, the square, the powers and the inverse |
| `PseudorandomFunction` | The SHAKE256 function of a seed, read in blocks of 136 bytes |
| `Sampler` | The positions of the method of Fisher and Yates, the secret blocks `h0` and `h1`, and the error vector |
| `Decoder` | The Black-Gray-Flip decoder with five iterations |
| `Syndrome` | The syndrome in three copies, and its rotations |
| `ParityCheckCounters` | The bit-sliced counters of the unsatisfied parity checks of each position |

## Parameter sets

| Set | `r` | `d` | `t` | Public key | Secret key | Ciphertext | Version text of liboqs |
|---|---|---|---|---|---|---|---|
| `BIKE-L1` | 12323 | 71 | 134 | 1541 | 5223 | 1573 | `Additional - 01/27/2023` |
| `BIKE-L3` | 24659 | 103 | 199 | 3083 | 10105 | 3115 | `Additional - 01/27/2023` |
| `BIKE-L5` | 40973 | 137 | 264 | 5122 | 16494 | 5154 | `Additional - 01/07/2023` |

The shared secret has 32 bytes. liboqs claims the NIST levels 1, 3 and 5 and IND-CPA security. Its wrapper `src/kem/bike/kem_bike.c` gives both seed lengths as zero. liboqs builds BIKE only on 64-bit little-endian platforms, and not on Windows. The byte formats of the port are those of a little-endian processor.

## Data flow

1. A key pair draws 64 random bytes in one request. The first 32 bytes seed the pseudorandom function, and the last 32 bytes are the rejection seed `sigma`.
2. The sampler draws the `d` positions of `h0` and then the `d` positions of `h1`, all below `r`, from one function. Each position takes 4 bytes, and the last position comes first.
3. The public key is `h = h1 h0^-1`. The inverse is the power `h0^(2^(r - 1) - 2)` by the steps and the tables of the C code.
4. The secret key is the positions of `h0` and `h1` as little-endian 32-bit values, the bytes of `h0`, of `h1` and of `h`, and `sigma`.
5. An encapsulation draws 64 random bytes in one request and uses the first 32 as the message `m`. The error vector `(e0, e1) = H(m)` has `t` positions below `2 r` from the function of `m`. The ciphertext is `c0 = e0 + e1 h` and `c1 = m + L(e0, e1)`, and the shared secret is `K(m, c0, c1)`. `L` and `K` are the first 32 bytes of the SHA3-384 of their inputs.
6. Decapsulation decodes `c0` with `h0`, the public key and the positions of the secret key. It computes `m' = c1 + L(e')` and `H(m')`, and compares `H(m')` with the decoded error `e'` with no branch on the result. A difference gives `K(sigma, c0, c1)`, and else the shared secret is `K(m', c0, c1)`.

## The decoder

1. The syndrome is `c0 h0`. The decoder keeps it in three copies, so that a rotation reads a window of the words.
2. Each iteration starts with the threshold `max((T0 + T1 |s|) / 10^8, minimum)` of the syndrome weight `|s|`, in the integer arithmetic of the C code.
3. For each block, the decoder adds the syndrome rotated by each position of the block to bit-sliced counters, and subtracts the threshold. Each position whose count reaches the threshold flips, and is black. Each other position whose count reaches the threshold minus 3 is gray.
4. The decoder computes the syndrome of `c0 + e0 + e1 h` again after each step.
5. The first iteration then flips the black and then the gray positions whose count reaches `(d + 1) / 2 + 1`. The four other iterations have only the first step.

Every step runs for every input, so the decoder has no branch on a secret value, and it finds the same error vector as the C code for every ciphertext and every secret key.

## Edge cases

- Neither key is checked, as in the C code. Every input of the right length gives a shared secret.
- Decapsulation does not read the block `h1` of the secret key, and reads `sigma` only for a rejection.
- A position of a secret key can have any 32-bit value. A rotation moves the syndrome by at most `64 (2 largestRotationStep - 1) + 63` coefficients, and the copies repeat the syndrome every `r` coefficients, so a position `p + r` within that reach counts as `p`. The C code does the same.
- A key or a ciphertext can have coefficients from `r` up to the end of its last byte. The product multiplies them, adds the coefficients `r` to `2 r - 1` of the exact product to the coefficients below `r`, and drops the coefficients from `2 r` up, as the reduction of the C code does. `K` hashes the ciphertext bytes as they are.
- The threshold is a byte. For `BIKE-L3` a syndrome weight of 21604 or more gives a threshold above 128, so the difference of a counter and the threshold can wrap in its 8 slices, as in the C code.
- The high word of the threshold is the `MUL64HIGH` macro of the C code, which is often one below the exact high word. The shift by 26 hides the difference for every syndrome weight.
- The pseudorandom function loses the rest of a block when a request does not fit in it. The samplers ask for 4 bytes at a time, and 136 is a multiple of 4, so no byte is lost.
- The product computes the exact product by another method than the C code: the method of Karatsuba down to a schoolbook product of 16 words, with an integer multiplication of the five residue classes of the bit positions in place of the table of `gf2x_mul_base_port`. The reduction is the one of the C code.
- Every input of a wrong length is `OQSError::invalidLength`. liboqs gives BIKE no seeded forms, so both seeded methods return `OQSError::seedNotSupported`, and the C library refuses them too.

## Tests

Each test file names the liboqs test that it replicates. liboqs has no vector test for BIKE.

- `KATKEM.rs`: `tests/kat_kem.c`. The `single` and `all` digests of the three sets equal `tests/KATs/kem/kats.json`.
- `TestKEM.rs`: `tests/test_kem.c` through `KEMCorrectnessTest`, the rejection of changed ciphertexts and keys, the ciphertexts with the same bit changed in two bytes, the parts of the secret key that decapsulation does not read, the positions plus `r`, the shared secrets of the C library for hostile ciphertexts and keys, the random requests, the seeded forms and the length errors.
- `FuzzTestKEM.rs`: `tests/fuzz_test_kem.c` through `KEMFuzzTest`, with 12 cases of each set, and random keys and ciphertexts.
- `TestKEMMem.rs`: `tests/test_kem_mem.c` through `KEMMemoryTest`.
- Unit tests with the known answers of the C functions `gf2x_mul_base_port`, `gf2x_mod_mul`, `k_sqr_port`, `gf2x_mod_inv`, `get_prf_output`, `sample_indices_fisher_yates`, `generate_secret_key`, `generate_error_vector`, `dup_port`, `rotate_right_port`, `get_threshold` and `decode` of liboqs 0.16.0, and of the arithmetic against references written by hand. The decoder tests include a ciphertext with 40 more errors, whose decoded error depends on every step of the decoder.
- `aDecodedErrorThatDiffersInTheSameBitOfTwoWordsIsRejected` in `BIKE.rs`: a ciphertext whose decoded error differs from the error of its message in bit 0 of two words, so the comparison must gather the differences with an or.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library.
