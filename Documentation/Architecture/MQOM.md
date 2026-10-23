# MQOM

## Purpose

`oqs-native-mqom` ports the twelve MQOM signature schemes of liboqs, from `mqom2_cat1_gf16_fast_r3` to `mqom2_cat5_gf16_short_r5`. Each gives the bytes of the C algorithm of the same name. liboqs builds every set from the code of the MQOM team in `src/sig/mqom/mqom_mqom_common`, with the parameter header of the set in `src/sig/mqom/mqom_mqom2_<set>_default` and the build flags of the default implementation in `src/sig/mqom/CMakeLists.txt`. MQOM is a candidate of round 2 of the NIST call for additional signatures. A signature proves the knowledge of a solution x over GF(16) of a public system of quadratic equations, without showing x.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-mqom` | `Modules/MQOM` | `features` |

| Type or module | Role |
|---|---|
| `MQOM` | MQOM 2.1, with the twelve constants and the `Signing` interface |
| `Parameters` | The parameters of the header and the build flags of a set, the lengths that follow from them, and the liboqs facts of the set |
| `InternalAlgorithms` | The key pair of a seed, the signature with a given salt and root seed, and the verification, as `keygen.c` and `sign.c` |
| `ExtensionField` | GF(2^8) and GF(2^16), the lift of GF(16) into them, and the encoding of their elements, as `fields_ref.h` |
| `BitPlanes` | Up to 64 elements of the extension field in bit planes, the bitsliced fields of `fields_bitsliced_branchconst.h` |
| `XOF` | SHAKE128 or SHAKE256, as `xof.h` chooses it |
| `SeedCipher` | AES-128 or Rijndael-256 keyed with a tweaked salt, `TweakSalt`, and the derived seed of `LinOrtho` |
| `PseudorandomGenerator` | `PRG` of `prg.c` |
| `GGMTree` | The correlated seed tree of `ggm_tree.c`: the expansion, the sibling path of a hidden leaf and the partial expansion |
| `EquationSystem` | The equations of a public key, `ExpandEquations` of `expand_mq.c` |
| `LineCommitment`, `LineTerms` | The batched line commitment of `blc_default.c`: the commitment, the opening and the evaluations |
| `PIOP` | The polynomial proof of `piop_bitslice.c` |

## Parameter sets

| Set | λ | Field | n | τ | N | w | Rounds | NIST level | Public key | Secret key | Signature |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `mqom2_cat1_gf16_fast_r3` | 128 | GF(2^8) | 56 | 17 | 256 | 9 | 3 | 1 | 60 | 88 | 3484 |
| `mqom2_cat1_gf16_fast_r5` | 128 | GF(2^8) | 56 | 17 | 256 | 9 | 5 | 1 | 60 | 88 | 3280 |
| `mqom2_cat1_gf16_short_r3` | 128 | GF(2^16) | 56 | 12 | 2048 | 8 | 3 | 1 | 60 | 88 | 3060 |
| `mqom2_cat1_gf16_short_r5` | 128 | GF(2^16) | 56 | 12 | 2048 | 8 | 5 | 1 | 60 | 88 | 2916 |
| `mqom2_cat3_gf16_fast_r3` | 192 | GF(2^8) | 84 | 27 | 256 | 3 | 3 | 3 | 90 | 132 | 8224 |
| `mqom2_cat3_gf16_fast_r5` | 192 | GF(2^8) | 84 | 27 | 256 | 3 | 5 | 3 | 90 | 132 | 7738 |
| `mqom2_cat3_gf16_short_r3` | 192 | GF(2^16) | 84 | 18 | 2048 | 12 | 3 | 3 | 90 | 132 | 6820 |
| `mqom2_cat3_gf16_short_r5` | 192 | GF(2^16) | 84 | 18 | 2048 | 12 | 5 | 3 | 90 | 132 | 6496 |
| `mqom2_cat5_gf16_fast_r3` | 256 | GF(2^8) | 116 | 36 | 256 | 4 | 3 | 5 | 122 | 180 | 14708 |
| `mqom2_cat5_gf16_fast_r5` | 256 | GF(2^8) | 116 | 36 | 256 | 4 | 5 | 5 | 122 | 180 | 13772 |
| `mqom2_cat5_gf16_short_r3` | 256 | GF(2^16) | 116 | 25 | 2048 | 6 | 3 | 5 | 122 | 180 | 12664 |
| `mqom2_cat5_gf16_short_r5` | 256 | GF(2^16) | 116 | 25 | 2048 | 6 | 5 | 5 | 122 | 180 | 12014 |

n is the number of variables over GF(16) and also the number m of equations. τ is the number of repetitions of the proof, N the number of leaves of each seed tree, and w the number of bits of the proof of work. A seed and the salt have λ / 8 bytes, and a digest has 2 λ / 8 bytes. `Parameters` holds one row of this table for each set and computes every length from it.

- The base field GF(16) is `F2[z] / (z^4 + z + 1)`. The fast sets prove over GF(2^8) = `F2[x] / (x^8 + x^4 + x^3 + x + 1)`, and the short sets over GF(2^16) = `GF(2^8)[Y] / (Y^2 + Y + 32)`, as a little-endian 16-bit value whose low byte is the constant coefficient. The lift of GF(16) sends the bits of an element to 0x01, 0xE0, 0x5D and 0xB0, the powers of z = 0xE0.
- An extension element holds µ = 2 or 4 elements of GF(16), so the m equations over GF(16) are m / µ equations over the extension field. The masks and the values alpha have η elements: m / µ for three rounds, and λ divided by the bits of the field for five rounds.
- The XOF is SHAKE128 for λ = 128 and SHAKE256 for λ = 192 and 256. Each use starts with a domain byte, from 0x00 for the key pair to 0x08 for the batching matrix.
- The seed cipher is AES-128 for λ = 128, through the AES API of liboqs as `enc_liboqs.h` calls it. For λ = 192 it is Rijndael-256 with the key and the block padded with eight zero bytes and the output cut to 24 bytes, and for λ = 256 it is Rijndael-256, as `enc_local.h` encrypts them with the bitsliced code of `rijndael_ct64.c`. `Rijndael256` of `Modules/AES` gives that cipher, see [Primitives.md](Primitives.md).

The descriptions hold the facts of `sig_mqom_mqom2_<set>.c`: the version text `2.1`, the claim EUF-CMA without SUF-CMA, and no context support.

## Data flow

1. A key pair draws its seed of 2 λ / 8 bytes in one request. The XOF of the byte 0x00 and the seed gives x, n / 2 bytes, and then the equation seed of 2 λ / 8 bytes.
2. Equation i has the seed of the XOF of the byte 0x01, the equation seed and i as two little-endian bytes. The PRG of that seed with the zero salt gives the lower triangular matrix A_i row by row, with j + 1 elements in row j, and then the vector b_i. The image is `y_i = x^T A_i x + b_i^T x` over the extension field, with x lifted from GF(16). The public key is the equation seed and y, and the secret key is the public key and x.
3. A signature checks the length of the secret key. Then it draws the root seed and then the salt, λ / 8 bytes each, in two requests, as `crypto_sign_signature` does. The message hash is the XOF of the byte 0x02 and the message.
4. The derived seed of a seed under a key is its encryption plus `LinOrtho` of the seed, `(high + low) || low` of its two halves. `TweakSalt(salt, selector, e, j)` makes the key: byte 0 of the salt takes the selector plus 4 e, and the bytes 1 and 2 take the 16-bit index j. The selector is 0 for the leaf commitments, 2 for the levels of a tree and 3 for the blocks of the PRG. Block b of the PRG output of a seed is its derived seed under the selector 3 and the index b, and the last block is cut.
5. The root seeds of the τ trees are the PRG output of the root seed with the zero salt. In tree e, node 2 is root seed e and node 3 is root seed e plus delta, the first λ / 8 bytes of x. The children of node k are node 2k, its derived seed under the selector 2 and its level, and node 2k + 1, the sum of node 2k and node k. The N leaves therefore sum to delta.
6. The line commitment of `BLC_Commit_default`: leaf i of tree e expands to a share of x and u, the seed and its PRG output. Its commitment is its derived seed under the tweak of selector 0 and then under the same tweak with bit 0 of byte 0 flipped. The shares fold along the Gray code, so `x0 = Σ ω_i share_i` and `u0 = Σ ω_i u_i`, with ω_i the Gray code of i as an element of the extension field, and `u1 = Σ u_i`. The partial delta of tree e is x plus the sum of the shares, without its first seed, which is zero. com1 is the XOF of the byte 0x07, the XOF of the byte 0x06 and the N leaf commitments of each tree, and the τ partial deltas.
7. The proof of `ComputePAlpha_bitslice`: for each equation, `P_z(r) = P_x(r)^T A_i P_x(r) + r b_i^T P_x(r) - r^2 y_i` with `P_x(r) = x0 + r x`. Its degree two term is zero for the x of the key, so `P_z(r) = z0 + r z1`. The three-round sets give `alpha0 = z0 + u0` and `alpha1 = z1 + u1`. The five-round sets first multiply z0 and z1 with the batching matrix Gamma, η rows of m / µ elements from the XOF of the byte 0x08 and com1. com2 is the XOF of the byte 0x03, the τ alpha0 and the τ alpha1.
8. The challenge hash is the XOF of the byte 0x04, the public key, com1, com2 and the message hash. `SampleChallenge` tries the nonces 0, 1, 2 and so on, as four little-endian bytes. The XOF of the byte 0x05, the hash and the nonce gives 2 τ + 2 bytes: τ little-endian 16-bit values cut to log2 N bits, the hidden leaves, and one value whose w low bits must be zero. The first nonce that meets this proof of work stands. The C code tries four nonces at a time and takes the first of them that meets it, which is the same nonce.
9. The signature is the salt, com1, com2, the τ alpha1, the opening and the nonce. The opening of `BLC_Open_default` is the τ sibling paths of the hidden leaves, the τ commitments of the hidden leaves and the τ partial deltas.
10. A verification checks the lengths of the signature and the public key. It computes the challenge hash, refuses a nonce that fails the proof of work, and rebuilds every leaf but the hidden one of each tree from its path, as `GGMTree_PartiallyExpand` does. `BLC_Eval_default` folds the shares with the hidden share zero and the opened commitment, and refuses an opening whose com1 differs. The evaluation at the point r of the hidden leaf is `x0' + r (sum + delta)`, the line of x at r. `RecomputePAlpha_bitslice` computes `alpha0 = P_z(r) + u(r) + r alpha1` from these evaluations, with the product with Gamma first for five rounds. The signature is valid when com2 of the recomputed alpha0 and of alpha1 equals com2.

The C code hashes four inputs at once and encrypts two, four or eight seeds at once under several keys. Each of these forms gives the bytes of the plain function for each input, so the port computes each hash alone and encrypts the seeds of one key together. The bitsliced fields of the C code compute the τ repetitions in the lanes of words. `BitPlanes` does the same in 64-bit planes, with x in lane τ. A product with a secret value uses masks. A product with an element of the public equations branches on the bits of that element, which the C code does only with `FIELDS_BITSLICE_PUBLIC_JUMP`. The branch depends only on the public key, and the product is the same.

## Edge cases

- Every input of a wrong length is `OQSError::invalidLength`. The length of the secret key is checked before the random requests.
- MQOM signs without a context string. A context of one byte or more is `OQSError::contextNotSupported`, before any random request, and a verification under it is false. The empty context is the plain form, as the NULL context of the C code.
- The secret key is read with no check, as in the C code. Any bytes of the right length sign, also an x that solves none of the equations of the public key in the key. `MalformedKeyParity.rs` in `Tools/Parity` shows that the C library gives the same signatures.
- A signature or a public key of a wrong length is not valid, as `crypto_sign_verify` refuses every signature length but one. The C API takes no length of the public key, so a public key of a wrong length has no C counterpart. Any bytes of the right length decode, so the verification of hostile bytes ends at one of its checks, the proof of work, com1 or com2, and it never panics.
- The proof of work refuses a nonce whose challenge has a w-bit value that is not zero, before the opening is read. A unit test signs with a nonce that fails the proof of work, and the verification refuses that signature although its opening and its slopes prove the hidden leaves.
- `SampleChallenge` of the C code loops over the nonces with no end, and a 32-bit nonce wraps. The port tries every 32-bit nonce once, and when none meets the proof of work the signature is `OQSError::operationFailed`. Each nonce fails with the probability `1 - 2^-w`, with w at most 12, so no input is known to reach the end, and the C code would loop forever there. A unit test gives the search a range of one nonce that fails and sees the failure.
- The signature parts lie at fixed places, as `Verify_default` reads them. The nonce is at the place `MQOM2_SIG_SIZE - 4`.
- `BLC_Eval_default` sets the share of the hidden leaf to zero, and the port leaves it out of the folds. The share of a leaf adds `(ω_i + r) share_i` to the evaluation at r, which is zero at the point of the hidden leaf, so any share there gives the same evaluation. A test cannot see a change of that share, and a mutant of it is equivalent.
- liboqs marks the default implementation as one with a large stack. The port keeps its trees, leaf commitments, shares and equations on the heap, so it signs on a thread with the default stack.
- The default build does not define `BLC_KEEP_ALL_TREES_IN_MEMORY`, so `BLC_Open_default` expands each tree again from its root seed. `LineCommitment` keeps the trees and the leaf commitments of the signature, which give the same opening.

## Tests

Each test file names the liboqs test that it replicates.

- `KATSig.rs`: `tests/kat_sig.c`. The `single` digest of each set equals `tests/KATs/sig/kats.json`. The `all` digests make 100 key pairs and signatures for each set, which take about 35 seconds for `mqom2_cat5_gf16_short_r5` alone in the dev profile, so they are ignored by default. `cargo test --release -p oqs-native-mqom --test KATSig -- --ignored` runs them, and so does `parity known-answers`.
- `TestSig.rs`: `tests/test_sig.c` through `SignatureCorrectnessTest`, the random requests, the place of the salt, the refused context and its order with the random requests, the length errors, a change in each part of a signature and of a public key, messages of several lengths, and a secret x that solves no equation.
- `FuzzTestSig.rs`: `tests/fuzz_test_sig.c` through `SignatureFuzzTest`, random secret keys that sign, and random signatures and public keys that are not valid, also with a zero nonce.
- `TestSigMem.rs`: `tests/test_sig_mem.c` through `SignatureMemoryTest`.
- liboqs has no vector test for MQOM, so the crate has no `VectorsSig.rs`.
- Unit tests of `Parameters`: the lengths of `sig_mqom.h`, η, the number of equations and `PRG_BLC_SIZE` of the parameter headers, and the facts of each set.
- Unit tests of `ExtensionField` and `BitPlanes`: every product of GF(2^8) against its definition, the lift as a map of fields, the tower field against the field rules, each lane of the planes against the field, and the products of `field_ext_mult` and `field_ext_base_constant_vect_mult` of the C code.
- Unit tests of `XOF` and `SeedCipher`: the SHAKE function of each level, the padded form of Rijndael-256, the derived seed against the definition of `LinOrtho`, and each byte of the tweak.
- Unit tests of `PseudorandomGenerator`, `GGMTree`, `EquationSystem`, `LineCommitment`, `PIOP` and `InternalAlgorithms`: the digests of the C functions of the MQOM code on seeded inputs, for each set. A C program built the code of each set with the flags of `CMakeLists.txt`, linked it with `liboqs.a`, and printed `OutputDigest` of the outputs for inputs from `LinearCongruentialSequence`. The functions are `PRG`, `GGMTree_Expand`, `GGMTree_Open`, `GGMTree_PartiallyExpand`, `ExpandEquations`, `BLC_Commit_default`, `BLC_Open_default`, `BLC_Eval_default`, `ComputePAlpha_bitslice`, `RecomputePAlpha_bitslice`, `KeyGen`, `SampleChallenge`, `Sign` and `Verify_default`.
- Unit tests of each check of the verification: a nonce that fails the proof of work, another nonce that meets it and hides other leaves, a changed path, opened commitment and partial delta, and a changed alpha1, each with the earlier checks passing.
- Unit tests of the nonce search of `MQOM`: a range of one nonce that fails gives `OQSError::operationFailed`, the range up to the nonce of a signature gives that signature, and a signature of a set with w = 3 takes the nonce 0, so the search starts at 0.
- `Tools/Parity`: the base case and 1000 seeded variations of each set against the C library. `MalformedKeyParity.rs` signs secret keys of random bytes and secret keys with a random x on both sides, and `HostileSignatureParity.rs` gives both sides public keys and signatures of any bytes.
