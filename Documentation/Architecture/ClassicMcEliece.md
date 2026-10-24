# Classic McEliece

## Purpose

`oqs-native-classic-mceliece` ports the ten Classic McEliece KEMs of liboqs, from `Classic-McEliece-348864` to `Classic-McEliece-8192128f`. Classic McEliece is the code-based KEM of round 4 of the NIST process, in the version SUPERCOP-20221025. Each set gives the bytes of the C algorithm of the same name, whose C code is the code of the Classic McEliece team in PQClean, in the `clean` form that the oracle builds.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-classic-mceliece` | `Modules/ClassicMcEliece` | `features` |

The sorts `int32_sort.h` and `uint64_sort.h` of the C code are `SortingNetwork::sort` and `SortingNetwork::sortWords` of the shared crate `oqs-native-sorting-network`, see [Primitives.md](Primitives.md).

| Type | Role |
|---|---|
| `ClassicMcEliece` | The KEM, with the ten constants such as `classicMcEliece348864` and `classicMcEliece348864f`, `operations.c` |
| `Parameters` | The parameters of `params.h`, the field polynomial of GF((2^m)^t), the layout of the secret key and the liboqs facts of a set |
| `GaloisField` | GF(2^12) and GF(2^13): the products, squares, inverses and quotients of `gf.c`, the evaluation of `root.c`, and `bitrev` and `load_gf` of `util.c` |
| `GoppaPolynomial` | The product `GF_mul` in GF((2^m)^t) and the minimal polynomial `genpoly_gen` of `sk_gen.c` |
| `ControlBits` | The control bits of the Benes network of a permutation, `controlbits.c` |
| `BenesNetwork` | The Benes network and the support of the Goppa code, `benes.c` and `transpose.c` |
| `ParityCheckMatrix` | The public key: the matrix of the Goppa code in systematic or semi-systematic form, `pk_gen.c` |
| `Encryption` | The error vector and its syndrome, `encrypt.c` |
| `Decryption` | The double syndrome, the Berlekamp-Massey algorithm, the error vector and its checks, `decrypt.c`, `synd.c` and `bm.c` |

Only `ClassicMcEliece` is public. The code of the two forms of each base set is the same code, and the `f` sets differ only in a flag of `Parameters`, which turns on the pivot search of the key generation.

## Parameter sets

| Sets | `m` | `n` | `t` | Field polynomial of GF((2^m)^t) | Public key | Secret key | Ciphertext | Level |
|---|---|---|---|---|---|---|---|---|
| `348864`, `348864f` | 12 | 3488 | 64 | `y^64 + y^3 + y + z` | 261120 | 6492 | 96 | 1 |
| `460896`, `460896f` | 13 | 4608 | 96 | `y^96 + y^10 + y^9 + y^6 + 1` | 524160 | 13608 | 156 | 3 |
| `6688128`, `6688128f` | 13 | 6688 | 128 | `y^128 + y^7 + y^2 + y + 1` | 1044992 | 13932 | 208 | 5 |
| `6960119`, `6960119f` | 13 | 6960 | 119 | `y^119 + y^8 + 1` | 1047319 | 13948 | 194 | 5 |
| `8192128`, `8192128f` | 13 | 8192 | 128 | `y^128 + y^7 + y^2 + y + 1` | 1357824 | 14120 | 208 | 5 |

GF(2^12) reduces by `x^12 + x^3 + 1` and GF(2^13) by `x^13 + x^4 + x^3 + x + 1`, and `z` is the element `x` of GF(2^12). The shared secret has 32 bytes. The wrappers `kem_classic_mceliece_<set>.c` of liboqs give every set the version text `SUPERCOP-20221025` and IND-CCA security, and give both seed lengths as zero. The unit tests compare the lengths and the sizes of `params.h` with the C headers.

## Random requests

| Operation | Requests in order |
|---|---|
| Key pair | 32 bytes, the seed |
| Encapsulation | `4 t` bytes for each attempt of the error vector, until an attempt is valid. The 8192128 sets draw `2 t` bytes for each attempt |
| Decapsulation | none |

## Data flow

1. A key pair draws the seed. Each attempt expands the byte 64 and the seed with SHAKE256 into `n / 8 + 4 * 2^m + 2 t + 32` bytes: the rejection value `s`, the `2^m` 32-bit order values, the `t` coefficients of an element of GF((2^m)^t), and the seed of the next attempt.
2. The Goppa polynomial `g` is the minimal polynomial of the element. When the powers of the element are not independent, the attempt fails, and the next attempt takes the next seed with no new request.
3. A sorting network sorts the order values with their indices, and `pi` lists the indices in the order of the values. Two equal values fail the attempt. The support is `L_i = bitrev(pi[i])` for `i` below `n`.
4. The parity-check matrix has the `m` bit rows of `L_i^j / g(L_i)` for each `j` below `t`. The Gaussian elimination brings it into the systematic form `(I | T)`, and fails the attempt when the first `m t` columns are not independent. The `f` sets first search the pivots of the window of the last 32 rows from column `m t - 32`, move those columns into place in the matrix and in `pi`, and fail only when the window has a rank below 32. The public key is `T`, row by row.
5. The secret key is the seed of the attempt that succeeded, the 64-bit pivots, the coefficients of `g`, the control bits of the Benes network of `pi`, and `s`. The pivots are `0xFFFFFFFF` for the sets without the pivot search.
6. An encapsulation draws the bytes of an attempt. They give `2 t` candidates of `m` bits, of which the first `t` below `n` are the positions, or `t` positions for the 8192128 sets. Fewer than `t` valid candidates or a repeated position fail the attempt. The ciphertext is the syndrome `(I | T) e` of the error vector, of `m t` bits, and the shared secret is `SHAKE256(1 || e || c)`, 32 bytes.
7. A decapsulation reads `g`, and the support from the control bits. It computes the double syndrome of the word `(c, 0)`, the error locator by the Berlekamp-Massey algorithm, and the error vector of the roots of the locator in the support. It accepts the error vector when its weight is `t` and its double syndrome equals the double syndrome of the received word. The C code folds the weight difference and each 16-bit difference of the double syndromes with an or. The shared secret is `SHAKE256(1 || e || c)` for an accepted vector and `SHAKE256(0 || s || c)` for a refused one, chosen with a mask and no branch.

## Edge cases

- liboqs gives Classic McEliece no seeded forms, so both seeded methods return `OQSError::seedNotSupported`, and the C library refuses them too.
- No key is checked. The decapsulation reads neither the seed nor the pivots of the secret key, and reads `s` only for a refused error vector. A secret key with any bytes gives a support of distinct elements, because every setting of a Benes network is a permutation.
- The 6960119 sets have `m t = 1547`, which is not a multiple of 8, so a ciphertext and each row of a public key have padding bits. A public key with a padding bit is `OQSError::operationFailed` after the random requests of the error vector, and a ciphertext with a padding bit is `OQSError::operationFailed`, where the C code returns -1. The other sets have no padding.
- Zero bytes and bytes of 0xFF never give a valid error vector, so an encapsulation with such a source never ends, as in the C code. The fuzz test starts at case 2.
- The pivot search of 6960119f starts its window at column 1515, inside byte 189. The C code writes the first byte of the moved window as `(tmp[0] << tail) | mat[i][block_idx] << (8 - tail) >> (8 - tail)`. The byte is promoted to `int`, so the first five bits of the window become the or of the old and the moved bits. The port does the same. A key reaches it only when a pivot of the window falls outside the diagonal in its first five columns, about once in `2^27` keys, so a unit test runs the C function copied into a test program on a chosen matrix.
- With `w` errors below `t`, the locator of the decoder is `x^(t - w)` times the locator of the errors, so the decoded vector also has the place whose support element is 0, when the support holds 0. The rejection tests use this to break one check at a time.
- `uint64_sort` swaps two values when the top bit of their difference is set, so it orders only values that differ by less than `2^63`. The key generation sorts only values below `2^63`. `SortingNetwork::sortWords` keeps the exchange and the order of the comparisons of the C code, so it gives the same result for every input.
- The port computes some steps in another form that gives the same bytes. The elimination works on 64-bit words and skips the words below the word of the pivot, which are zero in both rows. The C code checks the control bits and computes them again on a mismatch, and the recursion is exact for every permutation, so the port computes them once. A decapsulation computes the factors `1 / g(L_i)^2` once for both double syndromes, and masks each term with the bit of the word in place of the product of the C code, because the term is always a reduced element.
- Every input of a wrong length is `OQSError::invalidLength`. The ciphertext is checked before the secret key, and a public key of a wrong length draws no random bytes.

## Tests

Each test file names the liboqs test that it replicates. liboqs has no vector test for Classic McEliece.

- `KATKEM.rs`: `tests/kat_kem.c`. The `single` digests of the ten sets equal `tests/KATs/kem/kats.json` in the default run. The `all` run has 10 counts, each with a key pair, and its tests are ignored in the dev profile. `parity known-answers --all` proves them in a release build.
- `TestKEM.rs`: `tests/test_kem.c` through `KEMCorrectnessTest`. The four decisions of the decoder with keys of the identity network: an accepted vector of weight `t`, the weight check alone, the syndrome check alone, and the weight and one syndrome value that differ in the same bits, which an exclusive or of the fold would cancel. Changed ciphertexts, the parts of the secret key that the decapsulation reads, the layout of the secret key, the next seed after a failed attempt of the key pair with the attempt counts of liboqs, the random requests and the retries of the error vector, the padding checks of the 6960119 sets, also with the same padding bit in two rows, the length errors and the seeded forms.
- `FuzzTestKEM.rs`: `tests/fuzz_test_kem.c` through `KEMFuzzTest` from case 2, with one case of each set, and random secret keys, ciphertexts and public keys.
- `TestKEMMem.rs`: `tests/test_kem_mem.c` through `KEMMemoryTest`.
- Unit tests with the known answers of the C functions `gf_mul`, `gf_inv`, `gf_frac`, `GF_mul`, `genpoly_gen`, `crypto_int32_min`, `controlbitsfrompermutation`, `apply_benes`, `support_gen`, `pk_gen` with its failing order values and with a repeated value that keeps the order of a key, `encrypt`, `synd`, `bm` and `decrypt` of liboqs 0.16.0, and of `mov_columns` of 6960119f copied into a test program. The C programs and the tests take their inputs from SplitMix64, as `FuzzRandom::seeded` of `Modules/AlgorithmTests` makes them, and compare the `OutputDigest` of each output. The arithmetic is also checked against references written by hand: the schoolbook products of the fields and the identity sent through the layers of the control bits. The tests of the sorts are in `Modules/SortingNetwork`.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library, and the hostile keys and ciphertexts of `HostileInputParity.rs`.
