# CROSS

## Purpose

`oqs-native-cross` ports the eighteen CROSS signature schemes of liboqs, from `cross-rsdp-128-balanced` to `cross-rsdpg-256-small`. Each gives the bytes of the C algorithm of the same name. The C code is the clean code of the CROSS team, version 2.2 of the specification, from commit `179d61b8` of CROSS-lib-oqs, with the version text `2.2 + PQClean and OQS patches`. The oracle build of liboqs enables this clean code only, not the AVX2 code.

A signature proves the knowledge of a restricted vector e whose syndrome `s = e H^T` is the public key, over t rounds of a zero-knowledge protocol that SHAKE makes non-interactive. The C code of the 18 sets has four forms: RSDP or RSDP(G), each with trees for the balanced and the small sets or without trees for the fast sets. The port builds the 18 sets from one table and follows the four forms step by step.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-cross` | `Modules/CROSS` | `features` |

| Type | Role |
|---|---|
| `CROSS` | The scheme, with the constants `crossRSDP128Balanced` to `crossRSDPG256Small`, and the `Signing` interface |
| `Parameters` | The table of the 18 sets: the code, the trade-off, t, w, the room for the nodes of the trees and the random bits of the two challenges, with the derived lengths and the layout of a signature |
| `CodeParameters` | The six codes of the two problems at the three levels: n, k, m and the random bits of the samplers of the keys and of the vectors of a round |
| `Problem` | RSDP or RSDP(G), with the reductions of `fp_arith.h` and `restr_arith.h` |
| `Tradeoff` | Balanced, fast or small, and whether the set has trees |
| `TreeLayout` | The shape of the trees of t leaves, the `TREE_*` parameters of `parameters.h` |
| `HashFunction` | SHAKE128 or SHAKE256 with the domain separator of `csprng_hash.h` |
| `BitReader` | The window of 64 bits through which the samplers read their random bytes |
| `Sampler` | The rejection samplers of `csprng_hash.h` and the second challenge of fixed weight |
| `Packing` | The bit packing of `pack_unpack.c` and its padding checks |
| `FieldArithmetic` | The vectors and the syndromes over F_p |
| `RestrictedArithmetic` | The restricted vectors and the elements of the subgroup G |
| `PublicMatrices` | V^T and W of a public seed, `expand_pk` |
| `KeyMaterial` | The matrices and the secret vector of a secret seed, `expand_sk`, and the public key |
| `SeedTree` | The seeds of the rounds, the seed path and the rebuild of the seeds, `seedtree.c` |
| `MerkleTree` | The commitments of the rounds, the Merkle proof and the recomputed root, `merkle.c` |
| `Signer` | `CROSS_sign` |
| `Verifier` | `CROSS_verify` |

## Parameter sets

RSDP works in F_127 with the restricted group of the powers of 2, of order 7. RSDP(G) works in F_509 with the restricted group of the powers of 16, of order 127, and its restricted vectors lie in a subgroup G with m coordinates. The NIST level is 1 for lambda 128, 3 for lambda 192 and 5 for lambda 256.

| Set | lambda | n | k | m | t | w | Nodes | Public key | Secret key | Signature |
|---|---|---|---|---|---|---|---|---|---|---|
| `cross-rsdp-128-balanced` | 128 | 127 | 76 | | 256 | 215 | 108 | 77 | 32 | 13152 |
| `cross-rsdp-128-fast` | 128 | 127 | 76 | | 157 | 82 | 82 | 77 | 32 | 18432 |
| `cross-rsdp-128-small` | 128 | 127 | 76 | | 520 | 488 | 129 | 77 | 32 | 12432 |
| `cross-rsdp-192-balanced` | 192 | 187 | 111 | | 384 | 321 | 165 | 115 | 48 | 29853 |
| `cross-rsdp-192-fast` | 192 | 187 | 111 | | 239 | 125 | 125 | 115 | 48 | 41406 |
| `cross-rsdp-192-small` | 192 | 187 | 111 | | 580 | 527 | 184 | 115 | 48 | 28391 |
| `cross-rsdp-256-balanced` | 256 | 251 | 150 | | 512 | 427 | 220 | 153 | 64 | 53527 |
| `cross-rsdp-256-fast` | 256 | 251 | 150 | | 321 | 167 | 167 | 153 | 64 | 74590 |
| `cross-rsdp-256-small` | 256 | 251 | 150 | | 832 | 762 | 251 | 153 | 64 | 50818 |
| `cross-rsdpg-128-balanced` | 128 | 55 | 36 | 25 | 256 | 220 | 101 | 54 | 32 | 9120 |
| `cross-rsdpg-128-fast` | 128 | 55 | 36 | 25 | 147 | 76 | 76 | 54 | 32 | 11980 |
| `cross-rsdpg-128-small` | 128 | 55 | 36 | 25 | 512 | 484 | 117 | 54 | 32 | 8960 |
| `cross-rsdpg-192-balanced` | 192 | 79 | 48 | 40 | 268 | 196 | 138 | 83 | 48 | 22464 |
| `cross-rsdpg-192-fast` | 192 | 79 | 48 | 40 | 224 | 119 | 119 | 83 | 48 | 26772 |
| `cross-rsdpg-192-small` | 192 | 79 | 48 | 40 | 512 | 463 | 165 | 83 | 48 | 20452 |
| `cross-rsdpg-256-balanced` | 256 | 106 | 69 | 48 | 356 | 258 | 185 | 106 | 64 | 40100 |
| `cross-rsdpg-256-fast` | 256 | 106 | 69 | 48 | 300 | 153 | 153 | 106 | 64 | 48102 |
| `cross-rsdpg-256-small` | 256 | 106 | 69 | 48 | 642 | 575 | 220 | 106 | 64 | 36454 |

The column `Nodes` is `TREE_NODES_TO_STORE`: the room of a signature for the seeds of the seed path and for the digests of the Merkle proof. The descriptions hold the facts of `sig_cross_<set>.c`: the version text, the claim EUF-CMA without SUF-CMA, and no context support.

## Data flow

The hash function of a set is SHAKE128 for lambda 128 and SHAKE256 above it. Each expansion and each hash absorbs its input and then a domain separator of 16 bits, low byte first. A hash is the first 2 lambda / 8 bytes of the output. Most domain separators depend on t: `3 t + 1` for the secret seed, `3 t + 2` for the matrices, `3 t + 3` for the secret vector, `3 t - 1` and `3 t` for the two challenges, `i + 2 t - 1` for the seed of round i, and `2^15 + i + 2 t - 1` for its commitments. The seed tree expands node j with the separator j, and a fast set expands the root seed with 0 and its 4 quarter seeds with 1 to 4. Every other hash, the Merkle tree among them, uses `2^15`.

A key pair:

1. The key pair draws a seed of 2 lambda / 8 bytes in one request. The seed is the secret key.
2. SHAKE of the seed gives the seed of e and then the seed of the matrices, each of 2 lambda / 8 bytes.
3. SHAKE of the seed of the matrices gives W for RSDP(G) and then V^T, each by rejection from its own buffer of random bits.
4. SHAKE of the seed of e gives e for RSDP. For RSDP(G) it gives the information word e_G, and e is `e_G [W I]`.
5. The public key is the seed of the matrices and the packed syndrome `s = e H^T` with `H = [V I]`.

A signature:

1. The secret key must have 2 lambda / 8 bytes. Every byte string of that length is a secret key.
2. The signature draws a root seed of lambda / 8 bytes and then a salt of 2 lambda / 8 bytes, in two requests.
3. The balanced and the small sets expand the root seed into the seed tree, whose leaves are the seeds of the rounds. The fast sets expand it into 4 seeds and each of those into a quarter of the round seeds.
4. SHAKE of the seed of round i and the salt gives the restricted vector e' (e'_G for RSDP(G)) and then the mask u'. The commitment syndrome is `(g^(e - e') * u') H^T`. The first commitment hashes the packed syndrome, the packed vector `v = e - e'` (the word `v_G = e_G - e'_G` for RSDP(G)) and the salt. The second commitment hashes the seed and the salt.
5. The digest of the commitments hashes the Merkle root of the first commitments and the hash of the second commitments. The digest of the first challenge hashes the hash of the message, that digest and the salt. SHAKE expands it to t field elements from 1 to p - 1.
6. The responses `y = u' + c g^e'` and the digest of the first challenge give the digest of the second challenge. SHAKE expands it to t bits of weight w by the shuffle of Fisher and Yates.
7. The signature holds the salt, the two digests, the seed path, the Merkle proof, and for each round with the bit zero its second commitment and its response y with v or v_G. A round with the bit one reveals its seed through the seed path.

A verification checks the lengths of the public key and the signature. It recomputes y for each round with the bit one, and the first commitment for each round with the bit zero from y, v and the public syndrome. It accepts when both digests come out as in the signature, each published vector lies in the restricted group, and each padding check passes.

## Edge cases

- A secret key of a wrong length is `OQSError::invalidLength`, before any random byte is drawn. CROSS has no context string: a context that is not empty is `OQSError::contextNotSupported`, and a verification under it is false. The empty context gives the plain signature.
- A signature or a public key of a wrong length is not valid. liboqs verifies the signature first and then refuses a length other than its own, so the C code reads the whole length of a shorter signature. The oracle gives the C code a copy with zeros after it, see [Oracle.md](Oracle.md).
- The arithmetic keeps the forms of the C code. The reduction in F_127 folds the bits above 7 and keeps 127 as a second form of zero, and the exponents fold modulo 7 or 127 in the same way. F_509 reduces fully with the multiplication of Hacker's Delight. Each vector is normalized where the C code normalizes it.
- The samplers squeeze a fixed number of random bits, the `BITS_*_CT_RNG` of the set. When they run out, the window gives zeros and the samplers accept them, as in the C code. No known seed reaches this, and the unit tests of `Sampler` feed such buffers.
- The unpacking of a 3-bit vector of RSDP accepts any padding, because the mask of `generic_unpack_3_bit` is `0xFF << (n * 3) & 0x7`, which is zero. The verification still refuses a changed padding bit of such a vector, because the first commitment hashes the bytes of the signature and not the unpacked values. The 7-bit and 9-bit checks refuse each padding bit, so a set padding bit of y or of the public key is refused although the values stay the same.
- The bytes of the seed path and of the Merkle proof after their last node must be zero. The fast sets fill both, so their check always passes.
- The group check refuses an exponent of z, the second form of zero, in a published vector. A changed exponent also changes the first commitment of its round, so a changed signature cannot reach the group check alone. z gives the same arithmetic as 0, so a signer that leaves out the normalization of its published vectors makes a signature that only the group check refuses. `Signer::keepingTheSecondFormOfZero` makes that signer, and only the tests can call it.
- `TREE_NODES_TO_STORE` comes from a script of the CROSS team that liboqs does not ship. It is a bound, not the exact maximum: 108 for t = 256 and w = 215, where the longest seed path has 105 seeds. A unit test proves for each set with trees that the longest path and proof of any challenge fit, so the port never reads or writes past the room.
- `xof_shake_update` takes the length of the message as an `unsigned int`, so the C code hashes a message of 2^32 bytes or more without the bytes past its length modulo 2^32. The port does the same. No test signs such a message.

## Tests

Each test file names the liboqs test that it replicates. liboqs has no vector test for CROSS, so the family has no `VectorsSig.rs`.

- `KATSig.rs`: `tests/kat_sig.c`. The `single` and `all` digests of the 18 sets equal `tests/KATs/sig/kats.json`. The `all` digests take about 24 seconds of processor time in a test build, so the fast suite ignores them, and `cargo test -p oqs-native-cross --test KATSig -- --ignored` runs them. The release run of `parity known-answers` covers them.
- `TestSig.rs`: `tests/test_sig.c` through `SignatureCorrectnessTest` for each set, the facts of each set, the random requests, the seed as the secret key, the length errors before any random byte, the verification of wrong lengths, the binding to the message and to the key, changed bits and the missing context.
- `FuzzTestSig.rs`: `tests/fuzz_test_sig.c` through `SignatureFuzzTest`, random seeds that sign, and random signatures, second challenges and public keys that are refused.
- `TestSigMem.rs`: `tests/test_sig_mem.c` through `SignatureMemoryTest`.
- Unit tests: the arithmetic of both problems against its definition, the tree layout of each set against the `TREE_*` parameters of the C headers, the samplers at their boundaries and with a used-up buffer, and the known answers of the C functions `pack_*`, `unpack_*`, `expand_digest_to_fixed_weight`, `tree_root`, `tree_proof`, `recompute_root`, `gen_seed_tree`, `seed_leaves`, `seed_path` and `rebuild_tree`, and of their `NO_TREES` forms, for each set. The padding checks give the flags of the static functions `generic_unpack_3_bit`, `generic_unpack_7_bit` and `generic_unpack_9_bit` for every count from 1 to 16. The tests of `Verifier` change each field of a signature and each padding bit alone, and sign with a signer that keeps the second form of zero in its published vectors, which only the group check refuses.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library.
