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

## A working key of liboqs does not sign on

- Trap: a working key of hash-sigs that the oracle loads once and signs on with gives other signatures than `OQS_SIG_STFL_sign`, and they do not verify.
- Finding: the signatures count from 0. A working key of `LMS_SHA256_H5_W1` that signed on gave the signatures of the C library up to the end of its first subtree, and from there signatures that did not verify: from signature 4, the fifth, with the memory target of liboqs, 0, and from signature 16 with a target of 64 MiB. A working key of `LMS_SHA256_H5_W8_H5_W8` failed with `hss_error_private_key_expired` at signature 32, the first after its first bottom tree. The cause is the loop at the end of `hss_generate_signature`, in `src/sig_stfl/lms/external/hss_sign.c` of liboqs 0.16.0. Line 597, `for (i = w->levels-1; i>=1; i--, merkle_levels_below += tree->level)`, moves the subtrees of each tree from the bottom level up, but never those of tree 0, the top tree. A key of one level has only tree 0, so its subtrees never move. Line 602, `if ((i-1) == 0)`, takes the end of the bottom tree of a key of two levels for the end of the key, and line 606 sets `w->status = hss_error_private_key_expired`. `OQS_SIG_STFL_sign` loads a new working key for each signature, so it never meets the defect. `aWorkingKeySignsEachSignatureOfTheWholeKeyAsTheCLibraryDoes` failed at signature 16 when the shim did not load again, and `aTwoLevelWorkingKeySignsAcrossItsBottomTreesAsTheCLibraryDoes` failed at signature 32.
- Rule: the shim verifies each signature of a working key. When a signature fails or does not verify, it sets the private key back, loads the working key again and signs again. A signature that verifies has the one authentication path of its leaf, so it is the signature of `OQS_SIG_STFL_sign`, and the contract tests prove the two paths byte-identical.

## liboqs accepts a raw LMS public key

- Trap: a harness that checks the length of a public key rejects the public key of an LMS response file, which the C program accepts.
- Finding: the response files of `LMS_SHA256_H5_W1` and `LMS_SHA256_H10_W1` hold a raw LMS public key of 56 bytes and a raw LMS signature, not the HSS form of 60 bytes with the level count. `kat_sig_stfl` reads the key into a buffer of 60 bytes, and the patched hash-sigs code tells the two forms apart by their first words. The signature reads with four zeros in front, the level count of one.
- Rule: the oracle gives a shorter stateful public key to the C code with zeros after it, and the LMS port reads both forms as the C code does.

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
