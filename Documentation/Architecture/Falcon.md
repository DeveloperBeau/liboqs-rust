# Falcon

## Purpose

`oqs-native-falcon` ports the four Falcon signature schemes of liboqs: `Falcon-512`, `Falcon-1024`, `Falcon-padded-512` and `Falcon-padded-1024`. Each gives the bytes of the C algorithm of the same name. The C code is the clean code of PQClean, commit `1eacfdaf`, with the version text `20211101 with PQClean patches`. The oracle build of liboqs enables this clean code only, not the AVX2 or the AArch64 code.

The C code computes in floating point with an emulation over integers, `fpr.h` and `fpr.c`. The port translates that emulation bit for bit, so each key and each signature is the same as with the C library for the same random bytes.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-falcon` | `Modules/Falcon` | `features` |

| Type | Role |
|---|---|
| `Falcon` | The scheme, with the constants `falcon512`, `falcon1024`, `falconPadded512` and `falconPadded1024` |
| `Parameters` | The degree, the form of the signature and the liboqs facts of a set |
| `FloatingPoint` | The binary64 arithmetic over integers of `fpr.c` |
| `FourierTransform` | The FFT of `fft.c` and the operations on polynomials in the transform |
| `ModularPolynomial` | The NTT modulo `q = 12289` of `vrfy.c`: the public key, the polynomial `G` and the verification |
| `Encoding` | The modular, trimmed and compressed encodings of `codec.c` |
| `HashToPoint` | `hash_to_point_ct` of `common.c` |
| `SignatureNorm` | The norm bound of a signature vector, `is_short` and `is_short_half` of `common.c` |
| `ChaChaRandom` | The ChaCha20 generator of the sampler, `rng.c` |
| `GaussianSampler` | The sampler of `sign.c` with the Bernoulli trial of FACCT |
| `Signer` | `sign_dyn` of `sign.c`: the Gram matrix, the LDL tree and fast Fourier sampling |
| `SecretBasis` | The four secret polynomials `f`, `g`, `F` and `G` |
| `KeyGenerator` | The loop of `keygen` in `keygen.c` |
| `KeyRefusal` | The reason why the key generator refuses a candidate pair |
| `NTRUSolver` | `solve_NTRU` of `keygen.c` |
| `SolverFailure` | The step at which the solver finds no small solution |
| `BigInteger` | The big integers of 31-bit words of the solver, the `zint_*` functions |
| `PrimeModulus` | The arithmetic and the NTT modulo one small prime, the `modp_*` functions |
| `SmallPrime` | The 521 primes of the residue number system of `keygen.c` |

## Data flow

A key pair:

1. A key pair draws a 48-byte seed in one request. SHAKE256 of the seed is the stream of the key generator.
2. The key generator draws `f` and `g` from a discrete Gaussian distribution, each with an odd sum of coefficients. It refuses a pair whose coefficients do not fit the encoding, whose norm or orthogonalized norm is at or above the bound, whose `f` is not invertible modulo `q`, or whose NTRU equation has no small solution. Each refusal draws the next pair from the same stream.
3. The solver goes down to degree 1 with the field norms of `f` and `g`, solves there with the extended GCD of the two resultants, and comes back up with Babai reduction.
4. The secret key is the byte `0x50 + logn`, then `f` and `g` in 6 bits for each coefficient for degree 512 and 5 bits for degree 1024, then `F` in 8 bits. The public key is the byte `logn`, then `h = g / f mod q` in 14 bits for each coefficient.

A signature:

1. The secret key must have the length of the set. Then it must decode, and `G = g F / f mod q` must exist with each coefficient within 127. Both checks come before the first random byte.
2. The signature draws a 40-byte nonce. The point `c0` is HashToPoint of `nonce || message`.
3. The signature draws a 48-byte seed. SHAKE256 of the seed seeds the ChaCha20 generator of each attempt of the signer.
4. The signer samples a point of the lattice of the basis close to `(c0, 0)`. The difference `(s1, s2)` is short. An attempt whose difference is above the norm bound starts again with the next bytes of the stream.
5. A compressed set encodes `s2` in at most 711 bytes for degree 512 and 1421 bytes for degree 1024, and a vector that does not fit is `OQSError::operationFailed`. A padded set takes the next vector until one fits in 625 or 1239 bytes, and pads it with zeros.
6. The signature is the byte `0x30 + logn`, the nonce and the encoded `s2`.

A verification decodes the public key and the signature, computes `s1 = c0 - s2 h mod q` in the NTT, and accepts when the squared norm of `(s1, s2)` is within the bound: 34034726 for degree 512 and 70265242 for degree 1024.

## Edge cases

- A secret key of a wrong length is `OQSError::invalidLength`. A secret key that does not decode, or whose `G` does not exist or does not fit, is `OQSError::operationFailed`, with no random byte drawn.
- A decoder refuses the value `-2^(bits - 1)` of the trimmed encoding, a modular value of `q` or more, a compressed negative zero, a compressed value above 2047 and a padding bit that is not zero.
- A verification of either form accepts a compressed value that fills the signature, or a value of the padded length whose remaining bytes are zero. So a padded set accepts a compressed signature, and a compressed set accepts a padded signature, as the PQClean code in liboqs does.
- A public key of a wrong length, a signature shorter than 41 bytes and a wrong header byte give `false`.
- Falcon has no context string. A non-empty context is `OQSError::contextNotSupported` for a signature and `false` for a verification. The empty context gives the plain signature.
- The emulated floating point gives zero for a result that would be subnormal, as the C code does. No operation makes an infinity or a NaN.
- A secret key that decodes and completes, but is not a key of the scheme, can make the signer run without end. A key with `F = 0` does so in the C library and in the port. No test uses such a key.
- The solver has a failure check at depth 1, `SolverFailure::depthOne`, that no known pair `f` and `g` reaches, in the C code or in the port. Deeper values that no deeper level gives reach it. The unit test of depth 1 gives such values, and the port fails for the same three of them as `solve_NTRU_binary_depth1`.

## Tests

Each test file names the liboqs test that it replicates.

- `KATSig.rs`: `tests/kat_sig.c`. The `single` and `all` digests of all four sets equal `tests/KATs/sig/kats.json`. The `all` digests take about 23 seconds of processor time for the four sets, so the fast suite ignores them, and `cargo test -p oqs-native-falcon --test KATSig -- --ignored` runs them.
- `TestSig.rs`: `tests/test_sig.c` through `SignatureCorrectnessTest`, the facts of each set, the random requests, the formats of the keys and the signatures, and each refused key and signature. The tests of the negative zero and of the padding bit change a signature whose vector stays the same, so they fail if the decoder ignores the rule.
- `FuzzTestSig.rs`: `tests/fuzz_test_sig.c` through `SignatureFuzzTest`, random secret keys with the right header, and random signatures and public keys with the right headers.
- `TestSigMem.rs`: `tests/test_sig_mem.c` through `SignatureMemoryTest`.
- Unit tests: the floating point against the IEEE-754 arithmetic of the processor and against the C code, the FFT and the NTT against the schoolbook product, the encodings, the ChaCha20 block of RFC 8439, and the known answers of the C code for the sampler, HashToPoint, the keys of every degree from 2 to 1024 and the signature vectors of every degree.
- Known answers of the internal C functions, with inputs from `LinearCongruentialSequence` and digests of `OutputDigest`: `zint_co_reduce`, `zint_co_reduce_mod`, `zint_bezout` and `zint_norm_zero`, `FFT`, `iFFT` and `poly_LDL_fft`, `poly_big_to_fp`, `solve_NTRU_intermediate` and `solve_NTRU_binary_depth1`, and `BerExp`. The inputs include values that no key gives: pairs whose reductions negate a or b, a complex `g00`, and deeper values that make the reduction fail.
- `eachCandidateIsRefusedOrAcceptedAsTheCCodeDecides`: the decision of the key generator for each candidate pair of ten streams, against the decisions of the C loop, with every reason of `KeyRefusal`.
- `eachPairIsSolvedOrRefusedAtTheStepOfTheCCode`: the solution, or the step that fails, for sixteen pairs, against the C solver.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library.
