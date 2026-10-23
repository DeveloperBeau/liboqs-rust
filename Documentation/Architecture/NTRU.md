# NTRU

## Purpose

`oqs-native-ntru` ports the six NTRU KEMs of liboqs: `NTRU-HPS-2048-509`, `NTRU-HPS-2048-677`, `NTRU-HPS-4096-821`, `NTRU-HPS-4096-1229`, `NTRU-HRSS-701` and `NTRU-HRSS-1373`, the lattice key encapsulation of round 3 of the NIST process. Each gives the bytes of the C algorithm of the same name. The C code is the clean code of PQClean, from the reference code of the NTRU team, with SHA3-256 for the shared secret. The oracle builds this form. liboqs has an AVX2 form of four sets as well, and the port does not follow it.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-ntru` | `Modules/NTRU` | `features` |

| Type | Role |
|---|---|
| `NTRU` | The KEM, with the constants `ntruHPS2048509`, `ntruHPS2048677`, `ntruHPS4096821`, `ntruHPS40961229`, `ntruHRSS701` and `ntruHRSS1373` |
| `Parameters` | The constants of `params.h` of a set, the lengths that follow from them and the liboqs facts of the set |
| `Variant` | NTRU-HPS or NTRU-HRSS |
| `MultiplicationMethod` | The method of the product of a set: Toom-Cook with Karatsuba, or Karatsuba alone |
| `PolynomialMultiplication` | The product modulo `x^n - 1` with 16-bit coefficients that wrap, `poly_Rq_mul` |
| `PolynomialRing` | The reductions modulo 3 and `Phi_n`, the products modulo 3 and modulo `q`, and the lift of a message |
| `PolynomialInversion` | The inverses modulo 2, 3 and `q` |
| `SortingNetwork` | The constant-time sort of 32-bit signed values |
| `Sampler` | The polynomials of random bytes: independent coefficients, a fixed type, and a nonnegative correlation |
| `Packing` | The byte forms of the polynomials modulo 3 and modulo `q` |
| `PublicKeyEncryption` | The deterministic encryption of `owcpa.c`: the key pair, the encryption, the decryption and its three checks |

## Parameter sets

| Set | `n` | `q` | Public key | Secret key | Ciphertext | Random bytes of a key pair | Random bytes of an encapsulation | Level |
|---|---|---|---|---|---|---|---|---|
| `NTRU-HPS-2048-509` | 509 | 2048 | 699 | 935 | 699 | 2413 and 32 | 2413 | 1 |
| `NTRU-HPS-2048-677` | 677 | 2048 | 930 | 1234 | 930 | 3211 and 32 | 3211 | 3 |
| `NTRU-HPS-4096-821` | 821 | 4096 | 1230 | 1590 | 1230 | 3895 and 32 | 3895 | 5 |
| `NTRU-HPS-4096-1229` | 1229 | 4096 | 1842 | 2366 | 1842 | 5833 and 32 | 5833 | 5 |
| `NTRU-HRSS-701` | 701 | 8192 | 1138 | 1450 | 1138 | 1400 and 32 | 1400 | 3 |
| `NTRU-HRSS-1373` | 1373 | 16384 | 2401 | 2983 | 2401 | 2744 and 32 | 2744 | 5 |

The shared secret has 32 bytes. liboqs claims IND-CCA security for each set, and gives every set the version text `https://github.com/jschanck/ntru/tree/6d96ed37 reference implementation`. Its wrappers `src/kem/ntru/kem_ntru_<set>.c` give both seed lengths as zero.

## Data flow

1. A key pair draws the bytes of `f` and `g` in one request, and then the 32 bytes of the rejection key in a second request. The first `n - 1` bytes give `f`, and the rest give `g`.
2. NTRU-HPS samples `f` with independent coefficients, each byte modulo 3, and `g` of a fixed type: each coefficient below `n - 1` takes 30 bits of the bytes as a key, the first `q / 16 - 1` keys get the mark 1 and the next `q / 16 - 1` the mark 2, and a sort of the keys moves the marks to random places. NTRU-HRSS samples `f` and `g` with independent coefficients and negates the even coefficients when the correlation `<x f, f>` is negative. Every sample has the last coefficient 0.
3. The public key is `h = 3 g / f` modulo `q` and `Phi_n`, with `g` times `x - 1` for NTRU-HRSS. The key pair computes the inverse of `3 g f` modulo `q`, the inverse modulo 2 lifted by four Newton steps. The public key packs `h` in its sum-zero form: the `n - 1` first coefficients with `logq` bits each.
4. The secret key is `f` and `f^-1` modulo 3, packed five coefficients to the byte, `h^-1` modulo `q`, and the rejection key.
5. An encapsulation draws the bytes of `r` and `m` in one request. NTRU-HPS samples `r` with independent coefficients and `m` of the fixed type, and NTRU-HRSS samples both with independent coefficients. The shared secret is the SHA3-256 of the packed `r` and `m`. The ciphertext is `c = r h + Lift(m)`. The lift of NTRU-HPS is `m` itself, and the lift of NTRU-HRSS is `(x - 1)` times `m / (x - 1)` modulo 3 and `Phi_n`.
6. Decapsulation computes `m` from `c f` modulo 3 and `f^-1`, and `r = (c - Lift(m)) h^-1` modulo `q` and `Phi_n`. It checks the unused bits of the last ciphertext byte, the values of `r` and, for NTRU-HPS, the type of `m`, and joins the three results with an or. When every check passes, `c` is the encryption of `(r, m)`, so decapsulation needs no second encryption. A failed check gives the SHA3-256 of the rejection key and the ciphertext, and else the shared secret is the SHA3-256 of the packed `r` and `m`. A mask selects the result, with no branch.

## The product

The C code multiplies with 16-bit coefficients that wrap, and keeps each coefficient modulo `2^16` until it packs a polynomial or needs its value modulo `q`. The port does the same, with wrapping operations.

- The five sets up to `q = 8192` use Toom-Cook in four parts with two layers of Karatsuba below, `toom4_k2x2_mul`. The interpolation divides by 2, 4 and 8, so the result is exact modulo `2^13` only. The port keeps every step, so each 16-bit coefficient equals the coefficient of the C code, also in the three high bits.
- `NTRU-HRSS-1373` has `q = 16384`, and uses four layers of Karatsuba, `k2x4_mul`, whose result is the exact product modulo `2^16`.

## Edge cases

- Neither key is checked, as in the C code. Every input of the right length gives a shared secret.
- The key pair does not check that `f` has an inverse modulo 3. A key pair of the constant random bytes 0x00 or 0xFF has `f = 0`, as in the C code, and its keys do not decapsulate. The fuzz test states what they give, and runs its seeded cases from 2 up.
- The check of the unused bits sees a change only for the sets whose ciphertext leaves bits of the last byte unused: 508 times 11, 676 times 11 and 700 times 13 bits. The bits of `NTRU-HPS-4096-821`, `NTRU-HPS-4096-1229` and `NTRU-HRSS-1373` fill every byte.
- The check of `r` reads each coefficient below `n - 1` modulo `q`, with two tests that it joins with an or: the bits from 2 up of `r + 1`, which are 0 only for -1, 0, 1 and 2, and the bit 2 of `r + 2`, which is 1 for 2 and 0 for -1, 0 and 1. It also reads the last coefficient. The reduction modulo `Phi_n` makes that coefficient 0, so this part of the check never fails in a decapsulation.
- The check of `m` tests the balance, as many coefficients 1 as -1, and that `m` has `q / 16 - 1` coefficients -1. It joins the two tests with an or. The packing keeps `c(1) = 0`, so the message change `c + x^j - x^k` keeps the balance. A change that breaks the balance needs `c + d + k Phi_n` with `k n + d(1) = 0` modulo `q`. It decrypts to `m + d` and the same `r` for a key with `f(1) = 0`, and the rejection tests use such a key.
- NTRU-HRSS has no check of `m`, as in the C code. The zero secret key decrypts the zero ciphertext to `r = 0` and `m = 0`, which NTRU-HRSS accepts and NTRU-HPS refuses.
- A byte of a packed polynomial modulo 3 can have any value up to 255. The unpacking takes the five low digits of the byte in base 3, as the C code does, so the values from 243 up give the digits of their value minus 243.
- Every input of a wrong length is `OQSError::invalidLength`, the ciphertext first. liboqs gives NTRU no seeded forms, so both seeded methods return `OQSError::seedNotSupported`, and the C library refuses them too.

## Tests

Each test file names the liboqs test that it replicates. liboqs has no vector test for NTRU.

- `KATKEM.rs`: `tests/kat_kem.c`. The `single` digest of each set equals `tests/KATs/kem/kats.json`. The `all` digests take up to 5 seconds of processor time for each set in the dev profile, so they are ignored by default. `cargo test --release -p oqs-native-ntru -- --ignored` runs them, and so does `parity known-answers`.
- `TestKEM.rs`: `tests/test_kem.c` through `KEMCorrectnessTest`, the random requests, the keys, the shared secret, the rejection of changed ciphertexts, each check alone, two failed checks together, two equal failures of each test of the check of `r`, the two tests of the check of `m` alone and with the same difference, the roles of the parts of the secret key, the zero key, the seeded forms and the length errors. The changed ciphertexts come from the public key and the random bytes of an encapsulation, with arithmetic written in the test: `c + delta x^j h` changes `r` by `delta x^j`, and for NTRU-HPS `c + x^j - x^k` changes `m` by `x^j - x^k`.
- `FuzzTestKEM.rs`: `tests/fuzz_test_kem.c` through `KEMFuzzTest::runCases`, with the cases 2 to 13 of each set, the key pairs of the constant bytes, and random keys and ciphertexts.
- `TestKEMMem.rs`: `tests/test_kem_mem.c` through `KEMMemoryTest`.
- Unit tests with the known answers of the C functions `poly_Rq_mul`, `poly_S3_inv`, `poly_R2_inv`, `poly_Rq_inv`, `poly_lift`, `poly_Rq_to_S3`, `poly_S3_mul`, `poly_Sq_mul`, `poly_S3_tobytes`, `poly_S3_frombytes`, `poly_Sq_tobytes`, `poly_Rq_sum_zero_frombytes`, `sample_fg`, `sample_rm`, `crypto_sort_int32`, `owcpa_keypair` and `owcpa_dec` of liboqs 0.16.0, and of the arithmetic against references written by hand. The answers come from a C program that called these functions of the oracle library with the same inputs. The program is not part of the repository.
- `Tools/Parity`: the base case and the seeded variations of each set against the C library, and the hostile keys and ciphertexts of `HostileInputParity.rs`.
