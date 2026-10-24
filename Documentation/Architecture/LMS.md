# LMS

## Purpose

`oqs-native-lms` ports the 33 LMS sets of liboqs, the hash-based stateful signatures of RFC 8554 and NIST SP 800-208. A set of one level is one LMS tree, and a set of two levels is an HSS key whose top tree signs the trees below it. Each set gives the bytes of the C algorithm of the same name, whose code is the hash-sigs code of Cisco with the seed method of ACVP and the liboqs patches.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native-lms` | `Modules/LMS` | `features` |

| Type | Role |
|---|---|
| `LMS` | The 33 sets as constants from `lmsSHA256H5W1` to `lmsSHA256H20W8H20W8`, the `StatefulSigning` interface, the key pair and the load of a working key |
| `LMSWorkingKey` | The working key of hash-sigs: a secret key loaded once, with the trees of its levels, that signs many messages |
| `Parameters` | The table of the 33 sets: the types of their levels and the facts of `sig_stfl_lms.c` and `sig_stfl_lms.h` |
| `ParameterSet` | The levels of a key: the signature length, the highest count, the compressed form of the private key and the object identifier |
| `LevelType`, `TreeType`, `OneTimeSignatureType` | The LMS and LM-OTS parameter sets of RFC 8554, Tables 1 and 2, with their typecodes |
| `PrivateKey` | The private key of hash-sigs, 64 bytes, and the checks of `hss_get_parameter_set` |
| `AuxiliaryData` | The 10916 bytes of aux data of a key pair: the saved nodes of the top tree and their HMAC |
| `SeedDerivation` | The secret values of a tree, RFC 8554, Appendix A |
| `OneTimeSignature` | LM-OTS: the public key, the signature and the public key candidate of a signature |
| `MerkleTree` | One tree of a key: the hashes of its nodes, its public key, its children and its LMS signatures |
| `TreeBuilder` | The treehash stack that builds the nodes of a tree or of a subtree one leaf at a time |
| `TreeState` | One tree of a working key at its next leaf, with the subtrees of its authentication paths |
| `SignatureVerification` | The verification of an HSS signature, as `hss_verify_inc.c` and `lm_verify.c` decide it |

## Parameter sets

Every set uses SHA-256 with n = 32. The public key has 60 bytes, the private key of hash-sigs 64 bytes, and the serialized secret key 10980 bytes: the private key and 10916 bytes of aux data. The descriptions hold the facts of `sig_stfl_lms.c`: the version text `https://datatracker.ietf.org/doc/html/rfc8554`, the claim EUF-CMA without SUF-CMA, and the lengths of `sig_stfl_lms.h`. The object identifier is the level count, then the byte `(tree typecode << 4) + one-time typecode` of each level, top level first, as `OQS_LMS_ID_*` defines it.

| Set | Levels, top first | Object identifier | Signature | Total count |
|---|---|---|---|---|
| `LMS_SHA256_H5_W1` | H5 W1 | `0x0151` | 8688 | 31 |
| `LMS_SHA256_H5_W2` | H5 W2 | `0x0152` | 4464 | 31 |
| `LMS_SHA256_H5_W4` | H5 W4 | `0x0153` | 2352 | 31 |
| `LMS_SHA256_H5_W8` | H5 W8 | `0x0154` | 1296 | 31 |
| `LMS_SHA256_H10_W1` | H10 W1 | `0x0161` | 8848 | 1023 |
| `LMS_SHA256_H10_W2` | H10 W2 | `0x0162` | 4624 | 1023 |
| `LMS_SHA256_H10_W4` | H10 W4 | `0x0163` | 2512 | 1023 |
| `LMS_SHA256_H10_W8` | H10 W8 | `0x0164` | 1456 | 1023 |
| `LMS_SHA256_H15_W1` | H15 W1 | `0x0171` | 9008 | 2^15 - 1 |
| `LMS_SHA256_H15_W2` | H15 W2 | `0x0172` | 4784 | 2^15 - 1 |
| `LMS_SHA256_H15_W4` | H15 W4 | `0x0173` | 2672 | 2^15 - 1 |
| `LMS_SHA256_H15_W8` | H15 W8 | `0x0174` | 1616 | 2^15 - 1 |
| `LMS_SHA256_H20_W1` | H20 W1 | `0x0181` | 9168 | 2^20 - 1 |
| `LMS_SHA256_H20_W2` | H20 W2 | `0x0182` | 4944 | 2^20 - 1 |
| `LMS_SHA256_H20_W4` | H20 W4 | `0x0183` | 2832 | 2^20 - 1 |
| `LMS_SHA256_H20_W8` | H20 W8 | `0x0184` | 1776 | 2^20 - 1 |
| `LMS_SHA256_H25_W1` | H25 W1 | `0x0191` | 9328 | 2^25 - 1 |
| `LMS_SHA256_H25_W2` | H25 W2 | `0x0192` | 5104 | 2^25 - 1 |
| `LMS_SHA256_H25_W4` | H25 W4 | `0x0193` | 2992 | 2^25 - 1 |
| `LMS_SHA256_H25_W8` | H25 W8 | `0x0194` | 1936 | 2^25 - 1 |
| `LMS_SHA256_H5_W8_H5_W8` | H5 W8, H5 W8 | `0x025454` | 2644 | 1023 |
| `LMS_SHA256_H10_W4_H5_W8` | H10 W4, H5 W8 | `0x026354` | 3860 | 2^15 - 1 |
| `LMS_SHA256_H10_W8_H5_W8` | H10 W8, H5 W8 | `0x026454` | 2804 | 2^15 - 1 |
| `LMS_SHA256_H10_W2_H10_W2` | H10 W2, H10 W2 | `0x026262` | 9300 | 2^20 - 1 |
| `LMS_SHA256_H10_W4_H10_W4` | H10 W4, H10 W4 | `0x026363` | 5076 | 2^20 - 1 |
| `LMS_SHA256_H10_W8_H10_W8` | H10 W8, H10 W8 | `0x026464` | 2964 | 2^20 - 1 |
| `LMS_SHA256_H15_W8_H5_W8` | H15 W8, H5 W8 | `0x027454` | 2964 | 2^20 - 1 |
| `LMS_SHA256_H15_W8_H10_W8` | H15 W8, H10 W8 | `0x027464` | 3124 | 2^25 - 1 |
| `LMS_SHA256_H15_W8_H15_W8` | H15 W8, H15 W8 | `0x027474` | 3284 | 2^30 - 1 |
| `LMS_SHA256_H20_W8_H5_W8` | H20 W8, H5 W8 | `0x028454` | 3124 | 2^25 - 1 |
| `LMS_SHA256_H20_W8_H10_W8` | H20 W8, H10 W8 | `0x028464` | 3284 | 2^30 - 1 |
| `LMS_SHA256_H20_W8_H15_W8` | H20 W8, H15 W8 | `0x028474` | 3444 | 2^35 - 1 |
| `LMS_SHA256_H20_W8_H20_W8` | H20 W8, H20 W8 | `0x028484` | 3604 | 2^40 - 1 |

A key of total height H makes `2^H` signatures. liboqs reports `2^H - 1` as the total count, because hash-sigs stores the highest sequence number, and the remaining count is that total less the count of the key.

## Data flow

1. A key pair draws 48 random bytes in one request: the seed and the identifier I of the top tree, as `hss_generate_private_key` draws `PRIVATE_KEY_SEED_LEN` bytes through `LMS_randombytes`. No other operation draws random bytes.
2. The private key is the count 0 in 8 bytes, the parameter set in 8 bytes, the seed and I. The parameter set has one byte for each level, then `0xFF`.
3. The private element j of the one-time key of leaf q is `H(I || u32str(q) || u16str(j) || u8str(0xFF) || SEED)`, RFC 8554, Appendix A. The same derivation with j = `0xFFFE` and `0xFFFF` gives the seed and I of the child tree under leaf q, and with j = `0xFFFD` the randomizer C of the signature of leaf q.
4. A leaf is the hash of the one-time public key of RFC 8554, Algorithm 1: the hash of I, q, `D_PBLC` and the end of each Winternitz chain. `TreeBuilder` hashes the leaves of the top tree in order with the treehash stack, which gives the root and the nodes of the aux data.
5. The public key is the level count, the two typecodes of the top tree, I and the root. The secret key is the private key, then the aux data: a marker whose bit d is set for each saved depth d, the `2^d` nodes of each saved depth, and the HMAC-SHA256 of both under the SHA-256 of 20 zero bytes, `D_DAUX` and the seed, then zeros. A top tree of height 5 saves the depths 1 and 3, of height 10 or 20 the depths 2, 4, 6 and 8, and of height 15 or 25 the depths 1, 3, 5 and 7.
6. A signature loads the key as `oqs_sig_stfl_lms_sign` does, with `LMSWorkingKey`. The count splits into one leaf index for each level, the bottom level in the low bits. The tree of each level below the top is the child of the leaf of its parent. The load builds each tree of the key in full, about one key generation for each level.
7. The signature is the level count less one, the signed public key of each level below the top, and the LMS signature of the message by the bottom tree. An LMS signature is q, the one-time signature with the randomizer of leaf q, the tree typecode and the authentication path. The signed public key of a level is the LMS signature of its public key by its parent, then the public key.
8. Before the signature comes back, the count of the private key moves to the next signature, or the whole private key becomes `0xFF` after the last signature, as `hss_advance_count` writes it. The aux data stays as it was. The advanced key goes to the store through `releaseSignature`, and the key in memory advances even when the store fails, as in the C library.
9. A working key keeps the trees after a signature. `TreeState` keeps the top part of each tree, the subtree of height `min(h, 10)` of the current leaf and the next subtree in full, and builds the subtree after them one leaf for each signature. Each level below the top builds its next tree one leaf for each signature, so a change of tree costs no new load.
10. A verification is an exact port of `hss_validate_signature_init` and `hss_validate_signature_finalize`. It reads the level count and the parameter sets from the public key and the signature, checks each signed public key with `lm_validate_signature`, and checks the bottom signature against the message hash `H(I || u32str(q) || D_MESG || C || message)`.

## Edge cases

- A secret key shorter than the 64 bytes of the private key is `OQSError::invalidLength`. A longer key is valid. Its bytes after the private key are aux data, which liboqs never reads, and which each signature keeps unchanged.
- A key after its last signature, filled with `0xFF`, and a key whose count is above the highest count are `OQSError::keyExhausted`. A parameter set with an unknown typecode, with no level, or with a byte other than `0xFF` after its end is `OQSError::operationFailed`. The C library gives `OQS_ERROR` for each of them, because the serialized key does not load.
- hash-sigs reads the parameter set from the key, not from the name of the scheme. So a key of `LMS_SHA256_H5_W8` signs under the name `LMS_SHA256_H5_W1` with its own signature of 1296 bytes, and its counts are the counts of its own set, as in the C library. A key of up to eight levels signs the same way. A key whose signature is longer than the signature of the scheme is `OQSError::operationFailed`, because the C code would write past its signature buffer.
- The C verification reads the public key from a buffer of 60 bytes. A shorter key reads with zeros after it, as the oracle gives it to the C code, so the raw LMS public key of 56 bytes of the response files of `LMS_SHA256_H5_W1` and `LMS_SHA256_H10_W1` verifies. A longer key is not valid. The liboqs patch of `hss_verify_inc.c` tells the two forms apart by the first words of the key and of the signature.
- The verification of any LMS set accepts a valid signature of another LMS set with its public key, because the key and the signature carry their parameter sets.
- A signature shorter than 12 bytes is not valid. The C code reads these bytes before it checks the length, and every such signature fails a later check.
- The C working key of liboqs 0.16.0 has two defects that liboqs never meets, because it loads the key again for each signature. A working key of one level gives signatures that do not verify from its fifth signature on, because the loop that moves its subtrees skips the top tree. A working key of two levels stops with `hss_error_private_key_expired` at the end of its bottom tree, because `(i-1) == 0` marks the end of the bottom tree as the end of the key. `LMSWorkingKey` gives the signature of a fresh load at each count, which is the signature of `OQS_SIG_STFL_sign`. The working key of the oracle verifies each signature and loads again where the defect shows, so the parity harness compares the same signatures, as `Documentation/Learnings/COracle.md` describes.
- A C secret key object that signs again after its last signature reports success with an empty signature, because `oqs_sig_stfl_lms_sign` returns 0 when the key does not load. The serialized key of that object does not load either, so the oracle and the port refuse it.

## Tests

Each test file names the liboqs test that it replicates.

- `KATSigStfl.rs`: `tests/kat_sig_stfl.c`. The digests of the 18 sets with a response file equal `tests/KATs/sig_stfl/kats.json`. The files of `LMS_SHA256_H5_W8_H5_W8` and `LMS_SHA256_H10_W4_H5_W8` are the test cases 1 and 2 of RFC 8554, Appendix F.
- `TestSigStfl.rs`: `tests/test_sig_stfl.c` through `StatefulSignatureCorrectnessTest` on each set of trees of height 5, and in an ignored test on each set of trees of height 10, without a response file as liboqs runs it. Then the tests of the family: the key pairs and the first signatures of eight sets, the advanced key after each signature, the request of 48 bytes, the counts and the end of a key, a failed save, each rejection path with its error, a key of another set, both public key forms, the verdicts on changes of each part of a signature, and the working key against the C library and against fresh loads. The known answers come from the C library of the oracle with the NIST known-answer generator.
- `FuzzTestSigStfl.rs`: `tests/fuzz_test_sig_stfl_lms.c` through `StatefulSignatureFuzzTest` on each of the 18 sets with a response file, and forged secret keys with the parameter set of a scheme, which sign with their saved key or give a defined error.
- Unit tests of `SeedDerivation`, `OneTimeSignature` and `MerkleTree`: the values of `hss_seed_derive`, the one-time public keys and signatures of each type, the digits and the checksums, and the internal nodes, against the exported functions of the C oracle.
- Unit tests of `TreeState`: each authentication path against the nodes of the definition, with subtrees of height 2, 3 and 5 and from starts in the middle of a subtree.
- Unit tests of `PrivateKey` and `AuxiliaryData`: the verdicts of `hss_get_parameter_set` and the aux levels of `hss_optimal_aux_level` of the C oracle, and the HMAC against RFC 4231.
- Unit tests of `LMSWorkingKey`: keys of three levels across the ends of bottom and middle trees against fresh loads, whose signatures equal the C library at the same counts, the last signature, and a key whose signature does not fit.
- `Tools/Parity`: `AlgorithmCoverage.rs` compares the description of each set with the C library, and `parity known-answers` runs the response files on both sides in release builds.
