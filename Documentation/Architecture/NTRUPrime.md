# NTRU Prime

## Purpose

`oqs-native-ntru-prime` ports the NTRU Prime KEM of liboqs, `sntrup761`: Streamlined NTRU Prime, the lattice key encapsulation of round 3 of the NIST process. It gives the bytes of the C algorithm of the same name. The C code is `sntrup761.c` of OpenSSH, revision 1.9, from the code of the NTRU Prime team in SUPERCOP, with SHA-512 for its hashes.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-ntru-prime` | `Modules/NTRUPrime` | `features` |

| Type | Role |
|---|---|
| `NTRUPrime` | The KEM, with the constant `sntrup761` |
| `Parameters` | The constants `p`, `q` and `w`, the lengths that follow from them and the liboqs facts of the set |
| `ModularReduction` | The centered residues modulo 3 and modulo `q`, the reciprocal modulo `q`, and the masks of the C helpers |
| `PolynomialRing` | The rings `R3` and `Rq` modulo `x^p - x - 1`: the products, the reciprocals and the rounding |
| `RadixEncoding` | The mixed-radix encoding of a list of values with their ranges, `Encode` and `Decode` |
| `Encoding` | The byte forms of a small polynomial, a polynomial modulo `q` and a rounded polynomial |
| `SortingNetwork` | The constant-time sort of 32-bit unsigned values |
| `Sampler` | The small and the short polynomials of random 32-bit words |
| `HashFunctions` | `Hash_prefix`, the confirmation and the session key |
| `PublicKeyEncryption` | `KeyGen`, `Encrypt` and `Decrypt` with their byte forms |

## Parameter set

| Set | `p` | `q` | `w` | Public key | Secret key | Ciphertext | Version text of liboqs |
|---|---|---|---|---|---|---|---|
| `sntrup761` | 761 | 4591 | 286 | 1158 | 1763 | 1039 | `v1.9.2026.01.20 via https://github.com/openssh/openssh-portable/blob/master/sntrup761.c` |

The shared secret has 32 bytes. liboqs claims the NIST level 2 and IND-CCA security. Its wrapper `src/kem/ntruprime/kem_ntruprime_sntrup761.c` gives both seed lengths as zero.

## Data flow

1. A key pair draws `p` random 32-bit words for a small `g`, in one request of 3044 bytes. Each word gives the coefficient `floor(3 v / 2^30) - 1` of its low 30 bits `v`. The key pair draws `g` again until `g` has an inverse in `R3`.
2. It then draws `p` words for the short `f`, in one more request of 3044 bytes. The first `w` words get the mark 0 or 2 in their low two bits, and the others the mark 1. A sort of the words moves the marks to random places, and each mark minus 1 is a coefficient, so `f` has `w` coefficients 1 or -1.
3. The public key is `h = g / (3 f)` in `Rq`, in the mixed-radix encoding with the range `q` for each coefficient. The secret key is `f` and `1 / g` in `R3`, four coefficients plus 1 to the byte, then the public key, the rejection value `rho` of 191 random bytes in a third request, and the hash `Hash_prefix(4, pk)` of the public key.
4. An encapsulation draws `p` words for the short `r` in one request of 3044 bytes. The ciphertext is the rounded encryption `Round(h r)`, each coefficient a multiple of 3 encoded as its third with the range `(q + 2) / 3`, and the confirmation `Hash_prefix(2, Hash_prefix(3, r) || Hash_prefix(4, pk))` of the encoded `r`. The shared secret is the session key `Hash_prefix(1, Hash_prefix(3, r) || c)`. `Hash_prefix(b, x)` is the first 32 bytes of the SHA-512 of the byte `b` and `x`.
5. Decapsulation computes `e = 3 f c` in `R3` and `r = e / g`. An `r` that does not have the weight `w` becomes the short polynomial with `w` leading coefficients 1. It then encrypts `r` again with the public key and the hash of the public key in the secret key, and gathers the byte differences of the two ciphertexts with an or. A difference puts `rho` in place of the encoded `r` and the prefix 0 in place of 1, with a mask and no branch, so a changed ciphertext gives `Hash_prefix(0, Hash_prefix(3, rho) || c)`.

## Edge cases

- Neither key is checked, as in the C code. Every input of the right length gives a shared secret.
- The C code reads the random words in the byte order of the processor. The port reads them as little-endian words, the order of the processors of the oracle.
- The retry of `g` is the only branch on a secret value, as in the C code, which declassifies the result of `R3_recip` before it branches. Each of the 100 counts of the known-answer run takes one candidate, so a unit test feeds a first candidate of zeros, which has no inverse.
- A byte of an encoded small polynomial has four pairs of bits, and the pair 3 decodes to 2. A hostile secret key can have the coefficient 2 in `f` or `1 / g`, and the products take it as the C code does. The last byte holds one coefficient in its low two bits, and its high bits are not read.
- `Decode` reduces each value modulo its range, also for bytes that no encoding gives, so a hostile public key or ciphertext decodes to values below their ranges, as in the C code.
- The fixed polynomial that replaces an `r` of another weight is short, so the encryption again always runs on a short `r`, and the comparison decides.
- The comparison reads all 1039 bytes of the ciphertext, the rounded part and the confirmation. The mask is the C expression of the folded 16-bit difference, `bitmod_01(d - 1, 8) - 1`.
- Every input of a wrong length is `OQSError::invalidLength`, the ciphertext first. liboqs gives sntrup761 no seeded forms, so both seeded methods return `OQSError::seedNotSupported`, and the C library refuses them too.

## Tests

Each test file names the liboqs test that it replicates. liboqs has no vector test for sntrup761.

- `KATKEM.rs`: `tests/kat_kem.c`. The `single` digest equals `tests/KATs/kem/kats.json`. The `all` digest takes 3 seconds of processor time in the dev profile, so it is ignored by default. `cargo test --release -p oqs-native-ntru-prime -- --ignored` runs it, and so does `parity known-answers`.
- `TestKEM.rs`: `tests/test_kem.c` through `KEMCorrectnessTest`, the random requests, the layout of the secret key, the confirmation and the session key from hashes written in the test, the rejection of changed bytes of the rounded part and of the confirmation, the same bit changed in two bytes, the roles of the parts of the secret key, the zero key, the seeded forms and the length errors.
- `FuzzTestKEM.rs`: `tests/fuzz_test_kem.c` through `KEMFuzzTest`, with 12 cases, the constant bytes of the cases 0 and 1 among them, and random keys and ciphertexts.
- `TestKEMMem.rs`: `tests/test_kem_mem.c` through `KEMMemoryTest`.
- Unit tests with the known answers of the C functions `R3_recip`, `Rq_recip3`, `Rq_mult_small`, `R3_mult`, `Round`, `Rq_encode`, `Rq_decode`, `Rounded_encode`, `Rounded_decode`, `Small_encode`, `Small_decode`, `Short_fromlist`, the formula of `Small_random`, `ZDecrypt`, and `crypto_kem_sntrup761_keypair`, `_enc` and `_dec` with a seeded random source, of liboqs 0.16.0. The answers come from a C program that included `sntrup761.c` to call its static functions with the same inputs. The program is not part of the repository. Other unit tests check the arithmetic, the encodings and the sort against references written by hand.
- `Tools/Parity`: the base case and the seeded variations against the C library, and the hostile keys and ciphertexts of `HostileInputParity.rs`.
