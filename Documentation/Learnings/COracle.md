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

## liboqs accepts a raw LMS public key

- Trap: a harness that checks the length of a public key rejects the public key of an LMS response file, which the C program accepts.
- Finding: the response files of `LMS_SHA256_H5_W1` and `LMS_SHA256_H10_W1` hold a raw LMS public key of 56 bytes and a raw LMS signature, not the HSS form of 60 bytes with the level count. `kat_sig_stfl` reads the key into a buffer of 60 bytes, and the patched hash-sigs code tells the two forms apart by their first words. The signature reads with four zeros in front, the level count of one.
- Rule: the oracle gives a shorter stateful public key to the C code with zeros after it, and the LMS port reads both forms as the C code does.
