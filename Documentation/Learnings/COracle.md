# The C oracle

## The C library has one global random source

- Trap: two tests that call the C library at the same time share its random source, so each one reads bytes that the other one seeded.
- Finding: `OQS_randombytes` reads one process-wide generator, and the test harness runs tests on several threads.
- Rule: every C call goes through a `COracle`, which holds one lock for its whole life. A full parity run uses several processes to use several processors.

## A second oracle on the same thread waits forever

- Trap: a test that holds an oracle and calls a function that makes another oracle hangs.
- Finding: `unknownNamesAreFailuresAndNotPanics` hung, because it held an oracle and then called `OracleMechanism::named`, which locks again.
- Rule: `COracle::new` panics at once when the thread already holds an oracle. A test drops its oracle before it calls an adapter.

## The C algorithms need a large stack

- Trap: a check of some algorithms on a spawned thread overflows the stack.
- Finding: the first `known-answers` run stopped with a stack overflow. Some C schemes keep several megabytes on the stack, and a spawned thread has 2 MiB.
- Rule: each check runs on a `LargeStack` thread with 256 MiB of stack.

## The NIST KAT generator is not a stream

- Trap: a port that asks for the same bytes in other requests gives other output.
- Finding: the NIST DRBG updates its state after each request. `eachKEMDefectIsReportedAtItsStep` splits the 64-byte request of an ML-KEM key pair in two. The public key stays the same, because it comes from the first 32 bytes, and the secret key changes.
- Rule: a port asks for its random bytes in the same requests as the C code. The parity checks compare both keys of each key pair.

## The LMS code counts from the highest sequence number

- Trap: a port that reports 32 signatures for an LMS tree of height 5 differs from the C library.
- Finding: `statefulSigningAdvancesTheSecretKeyThatTheCLibraryPersists` showed that liboqs reports 31. The hash-sigs code stores the highest sequence number, `2^h - 1`, as the total.
- Rule: the port of a stateful scheme takes its counts from the C library, not from the size of the tree.

## The last signature of an LMS key writes over the private key

- Trap: a port that stops an LMS key at its total count, or that keeps the private key after the last signature, differs from the C library.
- Finding: a new key of `LMS_SHA256_H5_W1` reports 31 signatures left of a total of 31, and it signs 32 times, with the sequence numbers 0 to 31. The 32nd signature verifies, and `hss_advance_count` writes `0xFF` over the whole private key. After it, every count and every signature of the key fails, because the parameter set of the key is gone. `aWorkingKeySignsEachSignatureOfTheWholeKeyAsTheCLibraryDoes` compares all 32 signatures and the refused 33rd.
- Rule: the LMS port signs the last sequence number and writes over the private key as the C library does. The parity run signs at most the remaining count, so it never reaches the last signature, and the port needs its own test of it against the C library.

## The C library signs past the end of an XMSS key

- Trap: a port that refuses to sign once the remaining count is 0, or that refuses every signature after the end of the key, differs from the C library.
- Finding: a key of `XMSS-SHA2_10_256` made 1023 signatures that verify, and then its remaining count was 0. The next signature, at index 1023, succeeded, but `xmss_core_sign` first wrote zeros over the secret key and then signed with the zero seeds, so the signature does not verify, and the remaining count became 18446744073709551615. The signature after that failed and left the key all zeros but its object identifier, so the remaining count was 1023 and the next signature succeeded again with the zero key. A small C program linked with the oracle library found it.
- Rule: the parity run signs at most the remaining count, so it never reaches these signatures. Whether a port copies them is a decision for the owner, and a port that copies them needs its own test against the C library.

## A working key of liboqs does not sign on

- Trap: a working key of hash-sigs that the oracle loads once and signs on with gives other signatures than `OQS_SIG_STFL_sign`, and they do not verify.
- Finding: the signatures count from 0. A working key of `LMS_SHA256_H5_W1` that signed on gave the signatures of the C library up to the end of its first subtree, and from there signatures that did not verify: from signature 4, the fifth, with the memory target of liboqs, 0, and from signature 16 with a target of 64 MiB. A working key of `LMS_SHA256_H5_W8_H5_W8` failed with `hss_error_private_key_expired` at signature 32, the first after its first bottom tree. The cause is the loop at the end of `hss_generate_signature`, in `src/sig_stfl/lms/external/hss_sign.c` of liboqs 0.16.0. Line 597, `for (i = w->levels-1; i>=1; i--, merkle_levels_below += tree->level)`, moves the subtrees of each tree from the bottom level up, but never those of tree 0, the top tree. A key of one level has only tree 0, so its subtrees never move. Line 602, `if ((i-1) == 0)`, takes the end of the bottom tree of a key of two levels for the end of the key, and line 606 sets `w->status = hss_error_private_key_expired`. `OQS_SIG_STFL_sign` loads a new working key for each signature, so it never meets the defect. `aWorkingKeySignsEachSignatureOfTheWholeKeyAsTheCLibraryDoes` failed at signature 16 when the shim did not load again, and `aTwoLevelWorkingKeySignsAcrossItsBottomTreesAsTheCLibraryDoes` failed at signature 32.
- Rule: the shim verifies each signature of a working key. When a signature fails or does not verify, it sets the private key back, loads the working key again and signs again. A signature that verifies has the one authentication path of its leaf, so it is the signature of `OQS_SIG_STFL_sign`, and the contract tests prove the two paths byte-identical.

## An LMS signature of the C library costs a key generation

- Trap: a parity run that signs the variations of a large LMS tree with `OQS_SIG_STFL_sign` takes days.
- Finding: `oqs_sig_stfl_lms_sign` loads the working key from the private key for each signature, without the aux data of the serialized key. `OQS_SIG_STFL_sigs_total`, and so `OQS_SIG_STFL_sigs_remaining`, loads it too. One signature of `LMS_SHA256_H15_W8` took 84 seconds, about its key generation of 87 seconds. Its working key, loaded with the aux data, took 0.6 seconds to load and 7 milliseconds for each of 1000 signatures, with three more loads at subtree boundaries. A working key of a tree of height 20 has larger subtrees than the aux data reaches, so its load takes about one key generation, 237 seconds for `LMS_SHA256_H20_W1`. It then signed 1000 times without a new load, in half a millisecond each. The next entry holds the table of the times.
- Rule: the C side of the parity harness signs LMS with an `OracleWorkingKey`. It loads once with the aux data and a memory target of 64 MiB, loads again only where the defect of the working key shows, and counts with the `max_count` of the working key. XMSS needs no working key, because its secret key holds the state of the tree traversal, and one signature takes a few milliseconds.

## The key generation of a large stateful tree takes hours

- Trap: a check that generates a key of a large tree, in the C library or in a port, takes from minutes to a day, and a gate over every stateful set does not end.
- Finding: the table holds the C times of one key pair and one signature, in seconds of processor time on a shared machine, from a small C program linked with the oracle library. `OQS_SIG_STFL_sign` of LMS loads a new working key for each signature. The working key of the oracle loads once, with the aux data and a memory target of 64 MiB, and the last column is the time of each of 1000 signatures with it, its new loads included. XMSS and XMSS^MT sign fast without a working key. A value with "about" is an estimate from the measured trees, because the run takes many hours or a day. A tree with twice the leaves takes twice the time. A key pair of XMSS^MT builds one tree of each layer, so a key pair of `XMSSMT-SHA2_40/2_256` costs two key pairs of `XMSS-SHA2_20_256`.

| Set | Key pair | Signature with `OQS_SIG_STFL_sign` | Load of the working key | Signature with the working key |
|---|---|---|---|---|
| `LMS_SHA256_H5_W8` | 0.08 | 0.09 | 0.04 | 0.005, of 31 signatures |
| `LMS_SHA256_H10_W8` | 2.4 | 2.4 | 2.6 | 0.003 |
| `LMS_SHA256_H15_W8` | 87 | 84 | 0.6 | 0.007 |
| `LMS_SHA256_H20_W1` | 241 | about 240 | 237 | 0.0005 |
| `LMS_SHA256_H20_W8` | 2751 | about 2750 | about 2750 | not measured |
| `LMS_SHA256_H25_W8` | about 88000 | about 88000 | about 88000 | not measured |
| `LMS_SHA256_H5_W8_H5_W8` | 0.08 | 0.19 | 0.10 | 0.010 |
| `LMS_SHA256_H10_W8_H10_W8` | 2.9 | 6.2 | 2.6 | 0.007 |
| `XMSS-SHA2_10_256` | 1.9 | 0.002 | | |
| `XMSS-SHA2_16_256` | 120 | 0.003 | | |
| `XMSS-SHA2_20_256` | 1929 | 0.002 | | |
| `XMSSMT-SHA2_20/2_256` | 3.7 | 0.004 | | |
| `XMSSMT-SHA2_20/4_256` | 0.3 | 0.008 | | |
| `XMSSMT-SHA2_40/4_256` | 7.6 | 0.011 | | |
| `XMSSMT-SHA2_40/8_256` | 0.5 | 0.008 | | |
| `XMSSMT-SHA2_60/6_256` | 11 | 0.012 | | |
| `XMSSMT-SHA2_60/12_256` | 0.7 | 0.011 | | |
| `XMSSMT-SHA2_40/2_256` | about 3900 | about 0.005 | | |
| `XMSSMT-SHA2_60/3_256` | about 5800 | about 0.008 | | |

- Rule: `SuiteSample` keeps the default test suite to the stateful sets whose largest tree has a height of 10 or less, and `parity run` skips a set of a tree of height 20 or more unless `--large-trees` includes it. A parity run of a large tree costs one key generation on the C side, and for an LMS tree of height 20 or more a second one, the first load of the working key. The Rust side adds the key generation of the port, and for LMS one load of its `LMSWorkingKey`, which costs about one more.

## The serialized LMS key is longer than the key length of liboqs

- Trap: a port or a test that takes the secret key length of an LMS scheme as the length of its serialized key differs from the C library.
- Finding: liboqs gives every LMS scheme a secret key length of 64 bytes, the private key of hash-sigs: the count, the parameter set, the seed and the value `I`. `OQS_SIG_STFL_SECRET_KEY_serialize` gives 10980 bytes, the private key and 10916 bytes of aux data, which the base case of `StatefulParity` compares. `oqs_deserialize_lms_key` reads any length from 64 bytes up and takes the bytes after the private key as aux data, so a private key of 64 bytes alone also signs.
- Rule: the LMS port serializes its key with the aux data, byte for byte as the C library, and reads every length that the C library reads.

## liboqs accepts a raw LMS public key

- Trap: a harness that checks the length of a public key rejects the public key of an LMS response file, which the C program accepts.
- Finding: the response files of `LMS_SHA256_H5_W1` and `LMS_SHA256_H10_W1` hold a raw LMS public key of 56 bytes and a raw LMS signature, not the HSS form of 60 bytes with the level count. `kat_sig_stfl` reads the key into a buffer of 60 bytes, and the patched hash-sigs code tells the two forms apart by their first words. The signature reads with four zeros in front, the level count of one.
- Rule: the oracle gives a shorter stateful public key to the C code with zeros after it, and the LMS port reads both forms as the C code does.

## A C key object signs after its last signature

- Trap: a test that signs with a C secret key object after its last signature expects an error.
- Finding: a probe got `OQS_SUCCESS` and a signature of zero bytes for the 33rd signature of one key object of `LMS_SHA256_H5_W8`. `oqs_sig_stfl_lms_sign` returns 0 when `hss_load_private_key` fails on the private key of `0xFF` bytes that the last signature leaves. The serialized key of that state does not deserialize, so the oracle, which deserializes the key for each call, returns `OQS_ERROR`.
- Rule: the oracle and the port refuse a used key. A test of a long-lived C key object checks the length of each signature, not only the status.

## The internal C functions give known answers for the arithmetic

- Trap: a unit test of an internal function, such as a matrix product of FrodoKEM, needs a known answer that does not come from the Rust code, and the specification gives none for most inputs.
- Finding: the FrodoKEM code of liboqs exports its internal functions, such as `oqs_kem_frodokem_640_aes_mul_add_as_plus_e`, as global symbols of `liboqs.a`. A small C program linked with the oracle library printed a digest of each function on seeded inputs, and the Rust functions gave each digest.
- Rule: when liboqs exports an internal function, take the known answers of its unit test from it. The test names the C function. `LinearCongruentialSequence` of `Modules/AlgorithmTests` makes its inputs and `OutputDigest` its digest, so the C program and every family share one contract. `nm` on `liboqs.a` of the oracle build lists the exported names.

## A fetch through a linked oracle folder builds the C library again

- Trap: `cargo xtask fetch-oracle` in a worktree whose `target/oracle` links to the oracle folder of another clone builds the whole C library again, although no source changed.
- Finding: a fetch took 2 minutes 35 seconds on 4 processors. The tool gave CMake the relative folders `target/oracle/<version>/source` and `target/oracle/<version>/build`, so the CMake cache recorded the path through the link of the worktree that ran the last fetch. A fetch from another worktree changed that path, and CMake configured and compiled every file again. The new build also rewrote the `liboqs.a` that the tests of the other worktrees link.
- Rule: a tool that gives a path to a program that records it gives the path with every link resolved. `OracleBuild` takes the folders from `FileReading::resolvedPath`.

## An empty Rust slice is not a null pointer

- Trap: an oracle that passes `as_ptr()` of an empty context gives the C library a pointer that is not null, and liboqs reads the pointer as well as the length.
- Finding: the parity check of `Falcon-512` failed with "Rust succeeds and C fails" for the empty context. The liboqs wrapper of a scheme without context support signs only when `ctx_str == NULL && ctx_str_len == 0`, and the pointer of an empty Rust slice is a dangling address that is not null. `anEmptyContextIsTheNullContextOfTheCLibrary` failed before the fix.
- Rule: the oracle passes the null pointer for an empty context, as `tests/test_sig.c` does. An empty input reaches the C library as the null pointer wherever the C code compares a pointer with `NULL`.

## The CROSS verification reads the whole signature before its length check

- Trap: the parity check of a short signature makes the C library read past its input.
- Finding: the liboqs wrapper of CROSS calls `CROSS_verify` and refuses a length other than its own only after it, and `CROSS_verify` reads the whole `CROSS_sig_t`. The parity check of a signature one byte short read one byte past its copy. `aShortSignatureReachesTheCVerificationWithItsWholeLength` stopped with a memory fault for an empty signature, whose pointer points to no memory.
- Rule: the oracle gives the C verification a copy of a shorter signature with zeros after it, up to the signature length of the scheme. The C code still receives the length of the signature.

## A primitive of one family has no public API in liboqs

- Trap: the parity test of a shared primitive calls the C primitive through the public API of liboqs, and liboqs has no public API for Rijndael-256.
- Finding: MQOM encrypts its seeds of the levels 3 and 5 with Rijndael-256, and only `src/sig/mqom/mqom_mqom_common/rijndael_ct64.c` holds it. The headers in `build/include` have no Rijndael. `nm` on `liboqs.a` lists `rijndael256_ct64_setkey_enc` and `rijndael256_ct64_enc` as global symbols of each MQOM set, with the namespace of the set, such as `oqs_sig_private_mqom2_cat5_gf16_fast_r3_default_`.
- Rule: the shim declares the context of the family header and the functions of one set, and wraps them in a plain function. The contract test checks a standard vector through the wrapper, so a wrong context or a wrong loop of the shim fails there first. `oracleRijndael256ECB` is the template.
