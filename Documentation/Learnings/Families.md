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

## A position of an invalid key can count as another position

- Trap: a test that expects an out-of-range position of a secret key to break the decoding fails, because the decapsulation accepts the ciphertext.
- Finding: `aChangedSecretKeyGivesTheSecretOfSigma` first set a position of `h0` of a BIKE-L1 key to `r`. A rotation by `r` coefficients reads the copies of the syndrome at their start, so the position counted as position 0, and one wrong position of 71 did not stop the decoder. The C code rotates in the same way.
- Rule: a test of an invalid input takes its expected result from the C library or from the rule of the C code, not from the idea that an invalid input fails.

## A test with a decodable ciphertext cannot see most steps of a decoder

- Trap: the known answers of valid ciphertexts, and of simple hostile ones, pass with a decoder that skips a step.
- Finding: a BIKE decoder without the gray step, or with a delta of 2 in place of 3, passed every known-answer test and the decoder tests for a ciphertext of ones and for a key with positions out of range. The later iterations repair a missing step for a decodable ciphertext, and the simple hostile inputs give the same output with or without the step. A valid ciphertext with 40 more errors gives an output that changes with each step.
- Rule: the tests of a decoder include an input beyond its reach, with the answer of the C code. Run each step of the decoder once as deliberately wrong code against the tests.

## A test of a rare path must prove that its input takes the path

- Trap: a test passes for wrong code, because its input never takes the path that the test is about.
- Finding: the reduction of BIKE drops the coefficients of a product from `2 r` up. The first test of that rule used factors whose exact product had no coefficient at `2 r` or above. The test of the mask of the error vector used one seed whose error vector had no position in the last word of `e0`, so the sampler passed without the mask.
- Rule: a test of a rare path asserts that its input reaches the path, for example that the exact product has a coefficient from `2 r` up, or that a count of the cases over many seeds is above zero.

## A loop that the release build unrolls stays a loop in the test build

- Trap: the tests of a family are slow, although the release build is fast.
- Finding: the carry-less product of BIKE first looped over the five classes of the bit positions. A product of two BIKE-L5 polynomials took 4.7 ms in the test build, and 1.6 ms with the 25 integer products written out. The `all` known-answer run of BIKE-L5 fell from about 20 seconds to 7 seconds.
- Rule: write the innermost arithmetic of a family out in full, and measure it in the test build as well as in the release build.

## A test of a word that is not zero must reach its top bit

- Trap: the comparison of decapsulation of BIKE gathers the differences of two error vectors in one 64-bit word and tests the word with `(x | -x) >> 63`. The mutant `(x ^ -x) >> 63` gives the same answer for every value but `2^63`, so every test passed with it.
- Finding: a ciphertext whose decoded error differs from the rebuilt error only in the coefficients 63 and 127 gathers the difference `2^63` alone. The C code compares bytes and rejects it, and the mutant accepted it.
- Rule: a rejection test of a comparison that gathers into a word also puts the whole difference in the top bit of the word. `aDecodedErrorThatDiffersOnlyInTheTopBitOfTwoWordsIsRejected` is the template.

## The tests of a signature family spend their time in SHAKE

- Trap: the correctness test of a lattice signature takes minutes in the `dev` profile, although the code of the family is fast.
- Finding: `SignatureCorrectnessTest` took 93 seconds on one thread for the three ML-DSA sets at the optimization level 1. A probe found the time in SHA-3: the SHAKE128 sampling of one matrix polynomial took 27 microseconds, and one NTT 2 microseconds. At the level 3, SHAKE was seven to nine times faster, and the NTT changed little.
- Rule: the `dev` profile builds `oqs-native-sha3` with `opt-level = 3` and every other crate with level 1. The override changes only the optimization, so the overflow checks and the debug assertions stay on. The same test now takes 18.5 seconds on one thread.

## A refused case that breaks two rules cannot see the loss of one

- Trap: a decoder test whose malformed inputs each break two rules still passes when the check of one rule is gone.
- Finding: the hint decoding of ML-DSA refuses a count above omega, a count that falls, places of a row that do not rise and a byte after the last place that is not zero. Two deliberate defects passed the first test: a bound of omega + 1 and no check of a falling count. Each refused case of those rules also had places that did not rise, so the other check refused it.
- Rule: each refused case of a decoder breaks one rule only, and an accepted case sits at the edge of each rule. `hintUnpackingRefusesEachMalformedEncodingOfMLDSANative` is the template.

## An invalid sign vector of Wycheproof has no signature

- Trap: a test that compares the optional signature of the port with the optional signature of a vector counts a refusal as a match.
- Finding: the first `WycheproofVectors.rs` of ML-DSA compared `signature.ok()` with the signature of the vector. For tcId 5 of `mldsa_44_sign_noseed_test.json`, the port refused a context of 256 bytes, the invalid vector has an empty signature, and `None == None` counted as accepted.
- Rule: a vector test accepts only a success whose output equals the output of the vector, as `is_ok_and` does in the Wycheproof tests of ML-KEM. A refusal never matches.

## The vector tests of liboqs use hash functions that the hash API of liboqs does not have

- Trap: a port of the pre-hash vector tests cannot hash the message of every vector with the hash API of liboqs.
- Finding: `calc_hash` of `tests/test_acvp_vectors.py` hashes the message of a pre-hash vector with Python `hashlib`, with twelve hash functions. The hash API of liboqs has eight of them. SHA-224, SHA-512/224, SHA-512/256 and SHA3-224 are missing, and the C code of SLH-DSA has its own copies.
- Rule: a test that needs a hash function that the hash API of liboqs lacks takes it from the shared crate of its hash family, written from the standard, with known answers from the standard and from `hashlib`. The pre-hash parameter sets of SLH-DSA name the same four functions.

## A retry loop hides a wrong refusal

- Trap: a key generator that refuses a candidate and draws the next one gives keys that pass every known-answer test when a refusal rule is wrong at its boundary, because no stream of the tests has a candidate at the boundary.
- Finding: the coefficient range of the Falcon key generator with `-limit..limit` in place of `-limit + 1..limit`, and its norm bound with `<=` in place of `<`, passed the known answers of the keys of every degree, the decisions of ten streams of the C loop and the `all` digests of `KATSig.rs`. The C loop refuses a coefficient of `-limit` and a norm of exactly the bound.
- Rule: each refusal of a retry loop is a function with a test of both sides of its boundary, such as `theNormOfThePairIsBelowTheBoundUpTo16822`. The loop reports the reason of each refusal, and a test compares the sequence of reasons with the decisions of the C loop, such as `eachCandidateIsRefusedOrAcceptedAsTheCCodeDecides`.

## Two forms of a scheme can accept the signatures of each other

- Trap: a verification that refuses every signature whose length is not the length of its set refuses signatures that the C code accepts.
- Finding: `do_verify` of both forms of Falcon accepts a compressed value that fills the signature, and a value of the padded length whose remaining bytes are zero. So `Falcon-512` accepts a padded signature of 666 bytes, and `Falcon-padded-512` accepts a compressed signature of any length. `bothFormsOfADegreeShareTheirKeysAndVerifyTheSignaturesOfTheOther` proves it.
- Rule: take each length rule of a verification from the C code, not from the description lengths, and test the lengths on both sides of each rule.

## A hostile key can make a signer run forever

- Trap: a fuzz test of signing with hostile keys hangs when a key passes every check of the C code and reaches a loop that never ends.
- Finding: a `Falcon-512` secret key with `F = 0` decodes, and its `G` is 0, so it passes the checks of `do_sign`. The C library did not return in 120 seconds, and the port did not return in 300 seconds. In the fuzz tests, every random secret key fails the checks, because it has a forbidden value or a `G` out of range.
- Rule: the fuzz tests of a scheme with a retry loop use hostile inputs that the checks refuse, and the architecture page of the family names the inputs that reach the loop. A guard that the C code does not have is a decision for the owner.

## A search limit needs an input at the limit and one past it

- Trap: the echelon form of MAYO searches for the pivot of a column in at most 33 rows. A port with 32 or 34 rows passes the tests of a random matrix and of a matrix whose first entry is far past the limit.
- Finding: with the bound changed from 32 to 31 or to 33, every test of the crate passed, also the known-answer signatures of the 100 counts of each set and a crafted matrix whose first column is zero in its first 40 rows. The pivot of a random column is in one of the first rows, and row 40 is past both bounds. Two matrices whose first entry of the first column is at row 32, the last row of the search, and at row 33 caught the two changes, each at its own case.
- Rule: a test of a search limit puts the input exactly at the limit and one place past it, with the answer of the C code for both. `pivotAtSearchEnd` and `pivotPastSearch` in `EchelonForm.rs` are the template. See also the rejection loop of HQC above.

## A random change cannot see a comparison that skips one element

- Trap: the verification of MAYO compares the m elements of the value of the public map with the m elements of the target. A comparison of m - 1 elements passes every test that changes a signature, a message or a key.
- Finding: with the last element left out of the comparison, every test of the crate passed. Each changed input gives a value that differs from the target in nearly every element, so the other elements still refuse it. A solver that solves the linear system for a right-hand side with one element changed gives a signature whose value differs from the target in that element alone. With it, the comparisons without the first, the middle or the last element each failed.
- Rule: the test of a comparison of two vectors gives an input that differs in one element only, at the first, a middle and the last place, and asserts that the difference is at that place alone. `aSignatureWhoseValueDiffersFromTheTargetInOneElementIsRefused` is the template.

## The static functions of the C code give known answers too

- Trap: a unit test of a step of a family, such as the matrix of the linear system of MAYO, needs a known answer, and liboqs does not export the C function, because it is `static`.
- Finding: `nm` on `liboqs.a` lists `sample_solution`, `m_upper` and the public functions of MAYO, but not `compute_A`, `compute_rhs`, `EF` or `m_calculate_PS_SPS`. A C program that includes `mayo.c` and `arithmetic.c` calls them. Built with `MAYO_BUILD_TYPE_REF` in place of `MAYO_BUILD_TYPE_OPT`, the copy has the names `pqmayo_MAYO_1_ref_*`, which do not clash with the copy in `liboqs.a`. Its `mayo_expand_sk` and `sample_solution` gave the same digests as the exported functions of `liboqs.a`.
- Rule: when a C function is static, build its source file into the known-answer program with the flags of the oracle build of each set, from the `CMakeLists.txt` of the family, and with another namespace. Check one answer against an exported function of `liboqs.a`, so the program is known to build the same code.
