# XMSS

## Purpose

`oqs-native-xmss` ports the stateful hash-based signatures of liboqs of RFC 8391 and NIST SP 800-208: the 21 sets of XMSS and the 16 sets of XMSS^MT. Each gives the bytes of the C algorithm of the same name. The C code is the XMSS code of liboqs in `src/sig_stfl/xmss`, by SandboxAQ after the reference code of Andreas Hülsing and Joost Rijneveld, with the BDS traversal of `xmss_core_fast.c`.

A stateful scheme uses one one-time key for each signature. The secret key holds the index of the next one-time key and the BDS states that keep the next authentication path ready, and each signature advances it.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-xmss` | `Modules/XMSS` | `features` |

| Type | Role |
|---|---|
| `XMSS` | XMSS with one tree, with a constant for each of the 21 sets, such as `XMSS::sha2Height10Bits256`, the list `XMSS::schemes` of the 21 sets in the order of liboqs, and the `StatefulSigning` interface |
| `XMSSMT` | XMSS^MT with a hypertree of layers, with a constant for each of the 16 sets, such as `XMSSMT::sha2Height20Layers2`, the list `XMSSMT::schemes` of the 16 sets in the order of liboqs, and the `StatefulSigning` interface |
| `Scheme` | One liboqs set: its facts and the wrappers of `sig_stfl_xmss_xmssmt.c`, `sig_stfl_xmss_functions.c`, `sig_stfl_xmssmt_functions.c` and `xmss.c` |
| `Variant` | XMSS or XMSS^MT, each with its own table of object identifiers |
| `Parameters` | The parameters of an object identifier, as `xmss_parse_oid`, `xmssmt_parse_oid` and `xmss_xmssmt_initialize_params` of `params.c` give them |
| `CoreHash` | The hash function of a set, `core_hash` of `core_hash.c` |
| `HashState` | A `CoreHash` while it absorbs its input in parts |
| `KeyedHash` | The keyed functions of `hash.c` for one public seed: F, H, H_msg, PRF and PRF_keygen |
| `HashAddress` | The address ADRS of `hash_address.c` |
| `WOTS` | The WOTS+ one-time signatures of `wots.c` |
| `MerkleTree` | The leaf, the L-tree, the root and the verification of `xmss_commons.c` |
| `BDSState` | The BDS state of one tree, its traversal and its serialization, of `xmss_core_fast.c` |
| `CoreAlgorithms` | The key pair and the signature of XMSS and of XMSS^MT, of `xmss_core_fast.c` |
| `SigningFailure` | The ways a signature of the C code ends without a signature |
| `BigEndian` | `ull_to_bytes` and `bytes_to_ull` of `utils.c` |

## Parameter sets

Every set has the Winternitz parameter w = 16 and the BDS parameter k = 0. The lengths include the 4 bytes of the object identifier in front of each key, as liboqs counts them.

| Set | Identifier | Hash | n | h | d | Public key | Secret key | Signature |
|---|---|---|---|---|---|---|---|---|
| `XMSS-SHA2_10_256` | 0x01 | SHA-256 | 32 | 10 | 1 | 68 | 1377 | 2500 |
| `XMSS-SHA2_16_256` | 0x02 | SHA-256 | 32 | 16 | 1 | 68 | 2097 | 2692 |
| `XMSS-SHA2_20_256` | 0x03 | SHA-256 | 32 | 20 | 1 | 68 | 2577 | 2820 |
| `XMSS-SHAKE_10_256` | 0x07 | SHAKE128 | 32 | 10 | 1 | 68 | 1377 | 2500 |
| `XMSS-SHAKE_16_256` | 0x08 | SHAKE128 | 32 | 16 | 1 | 68 | 2097 | 2692 |
| `XMSS-SHAKE_20_256` | 0x09 | SHAKE128 | 32 | 20 | 1 | 68 | 2577 | 2820 |
| `XMSS-SHA2_10_512` | 0x04 | SHA-512 | 64 | 10 | 1 | 132 | 2657 | 9092 |
| `XMSS-SHA2_16_512` | 0x05 | SHA-512 | 64 | 16 | 1 | 132 | 4049 | 9476 |
| `XMSS-SHA2_20_512` | 0x06 | SHA-512 | 64 | 20 | 1 | 132 | 4977 | 9732 |
| `XMSS-SHAKE_10_512` | 0x0a | SHAKE256 | 64 | 10 | 1 | 132 | 2657 | 9092 |
| `XMSS-SHAKE_16_512` | 0x0b | SHAKE256 | 64 | 16 | 1 | 132 | 4049 | 9476 |
| `XMSS-SHAKE_20_512` | 0x0c | SHAKE256 | 64 | 20 | 1 | 132 | 4977 | 9732 |
| `XMSS-SHA2_10_192` | 0x0d | SHA-256, first 24 bytes | 24 | 10 | 1 | 52 | 1057 | 1492 |
| `XMSS-SHA2_16_192` | 0x0e | SHA-256, first 24 bytes | 24 | 16 | 1 | 52 | 1609 | 1636 |
| `XMSS-SHA2_20_192` | 0x0f | SHA-256, first 24 bytes | 24 | 20 | 1 | 52 | 1977 | 1732 |
| `XMSS-SHAKE256_10_192` | 0x13 | SHAKE256 | 24 | 10 | 1 | 52 | 1057 | 1492 |
| `XMSS-SHAKE256_16_192` | 0x14 | SHAKE256 | 24 | 16 | 1 | 52 | 1609 | 1636 |
| `XMSS-SHAKE256_20_192` | 0x15 | SHAKE256 | 24 | 20 | 1 | 52 | 1977 | 1732 |
| `XMSS-SHAKE256_10_256` | 0x10 | SHAKE256 | 32 | 10 | 1 | 68 | 1377 | 2500 |
| `XMSS-SHAKE256_16_256` | 0x11 | SHAKE256 | 32 | 16 | 1 | 68 | 2097 | 2692 |
| `XMSS-SHAKE256_20_256` | 0x12 | SHAKE256 | 32 | 20 | 1 | 68 | 2577 | 2820 |
| `XMSSMT-SHA2_20/2_256` | 0x01 | SHA-256 | 32 | 20 | 2 | 68 | 6002 | 4963 |
| `XMSSMT-SHA2_20/4_256` | 0x02 | SHA-256 | 32 | 20 | 4 | 68 | 10942 | 9251 |
| `XMSSMT-SHA2_40/2_256` | 0x03 | SHA-256 | 32 | 40 | 2 | 68 | 9604 | 5605 |
| `XMSSMT-SHA2_40/4_256` | 0x04 | SHA-256 | 32 | 40 | 4 | 68 | 15256 | 9893 |
| `XMSSMT-SHA2_40/8_256` | 0x05 | SHA-256 | 32 | 40 | 8 | 68 | 24520 | 18469 |
| `XMSSMT-SHA2_60/3_256` | 0x06 | SHA-256 | 32 | 60 | 3 | 68 | 16633 | 8392 |
| `XMSSMT-SHA2_60/6_256` | 0x07 | SHA-256 | 32 | 60 | 6 | 68 | 24511 | 14824 |
| `XMSSMT-SHA2_60/12_256` | 0x08 | SHA-256 | 32 | 60 | 12 | 68 | 38099 | 27688 |
| `XMSSMT-SHAKE_20/2_256` | 0x11 | SHAKE128 | 32 | 20 | 2 | 68 | 6002 | 4963 |
| `XMSSMT-SHAKE_20/4_256` | 0x12 | SHAKE128 | 32 | 20 | 4 | 68 | 10942 | 9251 |
| `XMSSMT-SHAKE_40/2_256` | 0x13 | SHAKE128 | 32 | 40 | 2 | 68 | 9604 | 5605 |
| `XMSSMT-SHAKE_40/4_256` | 0x14 | SHAKE128 | 32 | 40 | 4 | 68 | 15256 | 9893 |
| `XMSSMT-SHAKE_40/8_256` | 0x15 | SHAKE128 | 32 | 40 | 8 | 68 | 24520 | 18469 |
| `XMSSMT-SHAKE_60/3_256` | 0x16 | SHAKE128 | 32 | 60 | 3 | 68 | 16633 | 8392 |
| `XMSSMT-SHAKE_60/6_256` | 0x17 | SHAKE128 | 32 | 60 | 6 | 68 | 24511 | 14824 |
| `XMSSMT-SHAKE_60/12_256` | 0x18 | SHAKE128 | 32 | 60 | 12 | 68 | 38099 | 27688 |

The descriptions hold the facts of `sig_stfl_xmss_xmssmt.c` and `sig_stfl_xmss.h`: the object identifier, the version text `https://datatracker.ietf.org/doc/html/rfc8391`, the claim EUF-CMA without SUF-CMA, and the three lengths. The build of each set fixes its `CoreHash` with the `HASH` value of `CMakeLists.txt`. The n = 24 sets pad each hash input with 4 bytes, and the other sets with n bytes.

## Keys

A public key is the object identifier, the root of the top tree and PUB_SEED.

A secret key is the serialized key of liboqs, byte for byte:

1. The object identifier, 4 bytes.
2. The index of the next one-time key: 4 bytes for XMSS, and the bytes of the full height for XMSS^MT, ceil(h / 8).
3. SK_SEED, SK_PRF, the root and PUB_SEED, n bytes each.
4. 2 d - 1 BDS states: the current tree of each layer, then the next tree of each layer below the top. A state has a stack of h / d + 1 nodes, the stack offset in 4 bytes, the stack levels, the authentication path, h / 2d kept nodes, a treehash instance for each height and the next leaf in 4 bytes. A treehash instance has its height, its next index in 4 bytes, its stack usage, its completion and its node.
5. For XMSS^MT, d - 1 WOTS+ signatures: the signature of the root of the current tree of each layer by the layer above.

## Data flow

1. A key pair starts from a zeroed secret key, as the key object of liboqs does. It draws 2 n random bytes for SK_SEED and SK_PRF, then n bytes for PUB_SEED, in two requests. Each layer computes the root of its first tree with `treehash_init`, which also sets the authentication path of leaf 0 and the nodes of the treehash instances. The layer above signs that root with its first WOTS+ key. The states of the next trees stay empty.
2. A signature checks the length of the secret key and reads the parameters from its object identifier. It works on a copy of the key. The index gives R = PRF(SK_PRF, toByte(index, 32)) and the digest H_msg(R, root, index, M). The lowest layer signs the digest with the WOTS+ key of the index, and each layer above adds the WOTS+ signature that the key keeps and its authentication path.
3. Then the states advance. XMSS moves the authentication path to the next leaf with `bds_round` and spends h / 2 updates on the treehash instances. XMSS^MT adds a leaf to the next tree of the lowest layer, advances the current trees of the layers whose trees go on, and gives the updates that are left to the next trees above. A tree that ends swaps places with its next tree, and the layer above signs the root of the new tree into the key.
4. The signature is written into the copy, which replaces the key, and `releaseSignature` saves the advanced key before the signature is released.
5. A verification checks the length of the signature and of the public key, and the object identifier of the set in the public key. From the digest, each layer gives the WOTS+ public key of its signature, the leaf of its L-tree and the root of its authentication path, and the root of the top layer must equal the root of the public key.
6. The remaining count is 2^h - 1 minus the index, and the total count is 2^h - 1, from the identifier of the secret key.

Each array of a BDS state is a place in the secret key. The port keeps the offsets of the places and computes each access with the unsigned 32-bit arithmetic of the C code, so a state reads and writes the bytes that the C code reads and writes.

`KeyedHash` computes the state of the hash after toByte(3, padding) and PUB_SEED once. Each key and bitmask of F and H is a PRF of the public seed with that prefix, so a step of a chain costs four SHA-256 compressions instead of six for n = 32. The bytes are the same.

## Edge cases

- A secret key of another length is `OQSError::invalidLength` for a signature and for the counts. A key whose object identifier is not a set of the variant is `OQSError::operationFailed`, and the key stays as it is, as in the C library.
- The object identifier of another set of the variant gives that set's parameters, and the set that signs keeps its hash function, as in the C code. A key of XMSS-SHA2_10_256 in the buffer of XMSS-SHA2_16_256 signs with height 10 and gives a signature of 2500 bytes. When the identifier gives another n, or a longer key or a longer signature than the set, the C code reads or writes outside its buffers. The port refuses another n or a longer signature before it signs, and a longer key at its first access past the buffer, each with `OQSError::operationFailed`. The counts still read the index of such a key.
- At the last index, 2^h - 1, the C code wipes the key after its identifier and then signs with the wiped seeds, root and path. That last signature is not valid. The index becomes 2^h, so the remaining count wraps to 2^64 - 1, except for the sets of height 40, whose 5 index bytes keep 2^40 as 0.
- Past the last index, the signature is `OQSError::keyExhausted`, and the key in memory is zero after its identifier, as the C code leaves it. That wiped key has index 0, so it signs again with zero seeds, as in the C library.
- `bds_treehash_update` returns the count of updates as a `char`. When three trees of an XMSS^MT set of tree height 5 end at once, the count goes below zero, and the signed `char` of x86-64 makes it a large unsigned count, which the layers above then spend. The port copies that conversion. The keys of key generations keep the count between -9 and 10, where the conversion changes nothing. A target with an unsigned `char`, such as AArch64 Linux, gets 255 minus the updates used, and the signatures of the tests stay the same with it.
- In the layer loop of a signature, the C code passes the tree index of a layer through `uint32_t` before `set_tree_addr`, and its other calls keep 64 bits. The port does the same. The cast changes the advanced key once the tree index of the lowest layer passes 32 bits: from the index 2^37 of the 40/8 and 60/12 sets, 2^42 of the 60/6 sets and 2^52 of the 60/3 sets.
- A forged state can send the C code outside the key, as with a stack offset of 2^32 - 1, a stack usage without nodes on the stack, overlapping copies or a shift by the width of a value. The port refuses such a signature with `OQSError::operationFailed` and keeps the key. A forged state whose places stay in the key signs as in the C code.
- A forged XMSS^MT state with an unfinished treehash instance, at an index where the count of updates goes below zero, makes the C code spend a count near 2^32 on that instance. The port does the same, so such a key takes a very long time to sign.
- A refused save is `OQSError::persistenceFailed`. No signature comes back, and the key in memory has advanced, as the C library advances it before it calls the store.
- A signature or a public key of another length, or a public key with the identifier of another set, is not valid. A verification never panics.

## Tests

Each test file names the liboqs test that it replicates.

- `KATSigStfl.rs`: `tests/kat_sig_stfl.c` through `StatefulKnownAnswerTest`. Each of the 37 sets signs the message of its response file with the key of the file, and the digest equals `tests/KATs/sig_stfl/kats.json`.
- `TestSigStfl.rs`: `tests/test_sig_stfl.c` through `StatefulSignatureCorrectnessTest`, with the response file of each set. The program makes three key pairs of a set, so the default suite runs it on the 24 sets whose key pairs build no tree above height 5: the 18 sets whose key pairs the program reads from the response file, and the XMSS^MT sets of 4, 8 and 12 layers. An ignored test runs it on every set. Then the tests of the family. The key pairs of the NIST generator seeded with the bytes 0 to 47 against the response files, or against the C digests for the sets whose response file liboqs made with other random bytes. The random requests. Sequences of signatures against the chained digests of the C library, with the key after each signature and the counts. The last index, the indices past it, an index that the state does not follow, the identifier of another set, the updates below zero, and the index 2^52 + 5 of XMSSMT-SHA2_60/3_256 for the 32-bit tree index. Each rejection path with its error, with a case of its own for each rule that refuses an identifier. A refused save for each variant, forged states and the checks of the verification.
- `FuzzTestSigStfl.rs`: `tests/fuzz_test_sig_stfl_xmss.c` through `StatefulSignatureFuzzTest` on every set, with seeded cases on the values of the response file. The C program fuzzes XMSS-SHA2_10_256 and XMSSMT-SHA2_20/2_256. Hostile secret keys that keep the identifier of the set and forge the index and the BDS states give a signature or a defined error.
- Unit tests: the tables of `params.c` against the lengths of `sig_stfl_xmss.h`, the core hashes against FIPS 180-4 and FIPS 202, the addresses, the byte order, and `KeyedHash`, `WOTS` and `MerkleTree` against the internal functions of the C library, such as `oqs_sig_stfl_xmss_sha256_h10_inner_thash_h`, for each core hash. The BDS state: its layout, the low bytes of its counters, the count of updates as a signed `char`, the order of the treehash updates, the places outside the key, the copies and the swaps.
- The tests of height 10 key pairs, of the whole life of an XMSS key, of the end of the first tree of the second layer of XMSS^MT and of the correctness program on every set are ignored in the test build, with the reason, and run with `--release`.
- `Tools/Parity`: the coverage tests compare each description with the C library. `RegisteredParity` checks the sets of the suite sample, whose largest tree has a height of 10 or less, through `StatefulParity`, and `parity run` checks every set in release builds, the sets of trees of height 20 or more with `--large-trees`. `parity known-answers` runs the response files on the C library and on the port.
