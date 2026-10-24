# Algorithm families

## A liboqs fact can differ between the parameter sets of a family

- Trap: a port that writes one version text for a family differs from the C library for one parameter set.
- Finding: `eachRegisteredMechanismHasTheFactsOfTheCMechanism` failed for `Kyber512`. liboqs names commit `74cad307` of the reference code as its version, and commit `28413dfb` for `Kyber768` and `Kyber1024`.
- Rule: each parameter set takes each of its facts from the C file of that set, `kem_<name>.c` or `sig_<name>.c`, and the coverage test compares the whole description.

## Two families with the same arithmetic can draw their random bytes differently

- Trap: a key pair that draws its 64 bytes in one request gives other keys than the C code, which draws them in two.
- Finding: ML-KEM draws `d || z` in one request of 64 bytes. Kyber draws `d` and later `z` in two requests of 32 bytes, so the NIST DRBG gives other bytes for `z`.
- Rule: the port of a family copies the order and the sizes of the random requests of its C code, and the known-answer test of each set proves them.

## A debug test build is slow for cryptography

- Trap: the test suite of a family takes ten times longer than it needs to.
- Finding: the ML-KEM tests took 10 seconds at the optimization level 0 and 1.3 seconds at level 1.
- Rule: the workspace builds `dev` with `opt-level = 1`. The overflow checks and the debug assertions stay on, so an overflow that the C code does not have still fails a test.

## A rejection test that changes one byte cannot see an exclusive or

- Trap: the comparison of the re-encryption with the ciphertext folds the byte differences with an or. A fold with an exclusive or passes every test that changes one byte.
- Finding: mutation testing replaced the or with `^` in the decapsulation of ML-KEM and of Kyber, and every test still passed. When two bytes differ by the same value, the exclusive or gives zero, and the mechanism accepts the changed ciphertext.
- Rule: the rejection tests of a family also change the same bit in two bytes, so that the two differences cancel under an exclusive or. `aCiphertextWithTheSameBitChangedInTwoBytesIsRejected` is the template.

## The two changes of a rejection test go in the unit of the comparison

- Trap: the two-byte rejection test of ML-KEM changes the same bit in two bytes. FrodoKEM compares 16-bit values, not bytes. With 15-bit packing, the same bit of two bytes can be two different bits of two values, and then an exclusive or does not cancel the two differences.
- Finding: with the fold of `ct_verify` changed to an exclusive or, every test that changes one byte of a FrodoKEM ciphertext still passed. `aCiphertextWithTheSameBitChangedInTwoValuesIsRejected` failed. It flips the low bit of the values 0 and 8 of `B'` and of `C`.
- Rule: the two changes of the rejection test change the same bit of two values of the unit that the comparison folds. In a packed matrix, the low bits of the values 0 and 8 are the same bit of two bytes for any width.

## A reduction that only one parameter set can see

- Trap: the C code of FrodoKEM reduces some results modulo `q = 2^D` and keeps 16 bits in others. For `D = 16` each reduction is the identity, so no test of such a set sees a missing reduction.
- Finding: with the reduction of `B'` before the comparison of decapsulation removed, every test of FrodoKEM-976 and FrodoKEM-1344 passed. The tests of FrodoKEM-640, with `D = 15`, failed.
- Rule: the port reduces exactly where the C code reduces. A test of each reduction runs a set whose modulus is below `2^16`.

## The known answers of a large family are slow in the dev profile

- Trap: the `all` run of `kat_kem` has 100 counts. For the twelve FrodoKEM sets it takes about 220 seconds of processor time in the dev profile, and the parity test of the registry grows with each slow family too.
- Finding: one count of FrodoKEM-640-AES took 0.04 seconds and one count of FrodoKEM-1344-SHAKE 0.55 seconds in the dev profile. The SHAKE sets are slower than the AES sets because the Keccak permutation is slow at the first optimization level. A release build ran the twelve `all` runs in 26 seconds on two threads. `RegisteredParity.rs` went from under a second to about 12 seconds.
- Rule: the default suite runs the `single` digest of each set. Each `all` digest is ignored with the reason in its attribute, and a release run with `--ignored` proves it. The fuzz test of a slow family runs few cases, and the parity program runs the seeded variations in a release build.

## The known-answer generator of HQC cannot see how the requests split the bytes

- Trap: an HQC port that draws the message and the salt of an encapsulation in one request passes every known-answer digest of liboqs.
- Finding: the known-answer programs give HQC the SHAKE256 generator of `tests/test_helpers.c`, whose output is one stream. A merge of the two requests passed `KATKEM.rs` and failed only `aKeyPairDrawsOneRequestAndAnEncapsulationTwoAsTheCCode`, which records the requests, and the snapshot line of `HQC-1`, which uses the NIST DRBG.
- Rule: a family whose known answers come from a stream generator also proves the sizes of its requests with a recording random source and with the snapshot base case.

## The reduction of the C code is not the reduction of the ring

- Trap: an HQC product that is exact in the ring `F2[X]/(X^n - 1)` gives other bytes than the C library for some hostile public keys.
- Finding: the C code keeps the bits above `n` of the last byte of `s` and of `u`, and `vect_mul` folds the product bits from `n` to `2 n` once and drops the bits past `2 n`. With a public key of only ones, 10 of 1500 encapsulations of `HQC-1` differed from the C library for a product that reduces its factors modulo `X^n - 1` before it multiplies them. None differed with the reduction of the C code.
- Rule: a port keeps the arithmetic of the C code for every input, not only the mathematical result for valid inputs. The parity checks use valid keys, so a test with chosen hostile inputs, such as `HostileInputParity.rs`, proves the edge.

## A rejection loop on a stream never meets its own boundary

- Trap: the bound of a rejection loop can be wrong by one while every end-to-end test passes.
- Finding: an HQC candidate equal to the rejection threshold comes once in `2^24` candidates. With `>` in place of `>=`, the known-answer, correctness, fuzz and memory tests all passed. Only `rejectionSkipsTheThresholdAndRepeatedPositions`, which feeds chosen candidates, failed.
- Rule: a rejection loop takes its candidates from a function, so that a unit test can feed the values at the boundary.

## A bit by bit polynomial product is slow in a test build

- Trap: a port that copies the bit by bit schoolbook product of the HQC C code makes the test suite slow.
- Finding: the six known-answer digests of HQC took 25 seconds on one thread with the bit by bit product at the base of the Karatsuba split, and 3.7 seconds with a product of whole words. Both give the same exact product, so the bytes are the same.
- Rule: the base of a binary polynomial product multiplies whole words, with a test against the definition. The output depends only on the exact product, so the form of the product is free.

## A decoder test of correctable words cannot see the decoding beyond the capacity

- Trap: the decoders of HQC give a defined output for every word, and the decapsulation of an honest ciphertext with a decryption failure depends on it. A test that decodes only words with at most `delta` errors cannot see a change of that output.
- Finding: five mutants of the Berlekamp algorithm of `ReedSolomon::errorLocator` and two of `ReedMuller::peakPosition` passed every test of the first mutation run. They change the tracking of the degree and the choice between peaks, and every correctable word of the tests still decoded. `decodingOfEveryWeightGivesTheMessageOfTheCFunction`, `decodingOfManyErrorsAndTiesGivesTheBytesOfTheCFunction` and `decodingOfAnyWordGivesTheMessageOfTheCFunction` compare words of every weight, ties and noise with `reed_solomon_decode`, `reed_muller_decode` and `code_decode`, and kill all seven.
- Rule: a decoder test also compares words that the code cannot correct with the C function, from no error to every symbol wrong. For a decoder that picks a peak, the words include ties.
