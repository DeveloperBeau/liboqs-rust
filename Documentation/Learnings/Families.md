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
- Finding: `SignatureCorrectnessTest` took 93 seconds on one thread for the three ML-DSA sets at the optimization level 1. A probe found the time in SHA-3: the SHAKE128 sampling of one matrix polynomial took 27 microseconds, and one NTT 2 microseconds. At the level 3, SHAKE was seven to nine times faster, and the NTT changed little. A signature of SLH-DSA-SHAKE-128s, which calls the permutation about two million times, took 13 seconds at the level 1, 1.3 seconds with `oqs-native-sha3` at the level 3, and 1.0 seconds in a release build.
- Rule: the `dev` profile builds `oqs-native-sha3` with `opt-level = 3` and every other crate with level 1. The override changes only the optimization, so the overflow checks and the debug assertions stay on. The same test now takes 18.5 seconds on one thread. Measure a new family in both profiles before you plan its tests.

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

## A bound of the signing loop that no input reaches

- Trap: the number of attempts of the rejection loop of an ML-DSA signature can change, and every test passes.
- Finding: the first mutation run replaced `-` with `+` or `/`, and `/` with `*`, in `(2^16 - 1 - l) / l`, and no test failed. A signature needs a few attempts, and no input makes thousands of attempts fail. With `/` the loop of ML-DSA-44 stopped after 4095 attempts in place of 16382.
- Rule: a bound of a loop that the tests cannot reach is a constant of `Parameters`, with a test against the value of the C code. `eachConstantIsTheConstantOfFIPS204AndOfTheHeaderOfMLDSANative` is the template.

## A seed search finds the bound of a rejection sampler

- Trap: the uniform sampler of ML-DSA keeps a candidate equal to q when `<` becomes `<=`, and every test passes.
- Finding: a 23-bit candidate is q once in 2^23 candidates, and no stream of the tests held one. A C program searched the seeds of `LinearCongruentialSequence` and found 13544 and 37803 in about a second. Their streams hold q as the 199th and as the 16th candidate. `uniformSamplingSkipsACandidateOfQAndGivesThePolynomialOfTheCFunction` compares the polynomials of the two seeds with `poly_uniform` of mldsa-native.
- Rule: when the value at the bound of a rejection sampler comes once in a few million candidates, search for seeds whose stream holds it, and assert in the test that the stream holds it. For a rarer value, the loop takes its candidates from a function, as the rule of the HQC rejection loop says.

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

## A failure that no key reaches can be reachable at its own level

- Trap: a failure check that the documentation calls unreachable has no test, and the mutant that disables the check survives.
- Finding: `SolverFailure::depthOne` said that no known input reaches it, and `||` replaced with `&&` in its check survived the first mutation run of `oqs-native-falcon`. `solve_NTRU_binary_depth1` with deeper values that no deeper level of a key gives fails for 3 of 15 seeds, and the port fails for the same three. `depthOneGivesTheValuesOfSolveNTRUBinaryDepth1AndFailsWhereItFails` and `intermediateLevelsGiveTheValuesOfSolveNTRUIntermediateAndFailWhereItFails` give such values to each level.
- Rule: before the documentation calls a failure path unreachable, run its C function on hostile inputs of its own level. A path that such inputs reach gets a known-answer test at that level.

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

## A copy of a whole buffer agrees with a copy of its part only while the rest is zero

- Trap: `sample_solution` of MAYO copies the k o unknowns of the randomizer into the solution, and the randomizer has one more element, which the signature sets to zero. The port copied the whole randomizer. Every test passed, because every randomizer of the tests ended with a zero.
- Finding: the mutation run missed a mutant that clears the last column of the matrix only in the first row before the product `A r`. Its change reaches the product only through the last element of the randomizer. A known-answer case of `sample_solution` with the element 9 kills the mutant. The same case also failed on the copy of the whole randomizer, before the port copied only the unknowns.
- Rule: copy the same range as the C code. Give the known-answer test of an internal function a value that is not zero in each element that the function reads, also in an element that its caller keeps at zero. `randomizerTail` in `EchelonForm.rs` is the template. See also "An input that the caller never gives hides a mutant" in `MutationTesting.md`.

## A Toom-Cook product is exact only in its low bits

- Trap: a unit test that compares the NTRU product with the exact cyclic product fails for five of the six sets, and a port that computes the exact product gives other 16-bit coefficients than the C code.
- Finding: `poly_Rq_mul` of the sets up to `q = 8192` is Toom-Cook in four parts, whose interpolation divides by 2, 4 and 8. The product of `x^(n - 1)` and `x` gave 32769 at the coefficient 0 in the C code and in the port, which is 1 only modulo `2^13`. `NTRU-HRSS-1373` uses four layers of Karatsuba, whose product is exact modulo `2^16`.
- Rule: the port keeps every step of the product of the C code, so each 16-bit coefficient equals the C coefficient. A test of the arithmetic compares the exact product only in the bits that the method keeps, and the known answers of the C function in all 16 bits.

## The constant bytes of a fuzz case can give a key that the C code cannot use

- Trap: the fuzz cases 0 and 1 of `KEMFuzzTest` fail for NTRU-HPS, because the shared secrets differ.
- Finding: the bytes 0x00 and 0xFF are both 0 modulo 3, so the key pair samples `f = 0`, which has no inverse. The C code checks no key and gives the same keys, which do not decapsulate. sntrup761 makes a usable key of the same bytes.
- Rule: a mechanism whose C code cannot use the key of the constant bytes runs the seeded cases with `KEMFuzzTest::runCases` from 2 up, and a separate test states what the constant bytes give, as `constantRandomBytesGiveTheKeyFZeroAsInTheCCode` does.

## Each test of an or-fold needs its own pair of equal failures

- Trap: `owcpa_check_r` gathers two tests of each coefficient of `r` with an or: the bits from 2 up of `r + 1`, and the bit 2 of `r + 2`. A rejection test with two coefficients 3 cannot see an exclusive or in the first test, because 3 also fails the second.
- Finding: with `^=` in place of `|=` in the first test, every test of the crate passed, the pair of coefficients 3 among them. The value -2 fails only the first test, and a pair of coefficients -2 then failed the unit test of the check and `aBlindingPolynomialOutsideTheTernaryValuesIsRejected`.
- Rule: when a fold gathers several tests of each unit, the rejection tests change two units with a value that fails only one test, for each test. The value 2 fails only the second test of NTRU, and -2 only the first.

## A sum-zero ciphertext keeps the balance of the message

- Trap: the balance test of `owcpa_check_m` of NTRU-HPS, as many coefficients 1 as -1, cannot fail alone in a rejection test that changes the message of a ciphertext.
- Finding: the packing holds only the first `n - 1` coefficients of `c`, and the last is minus their sum, so `c + x^j - x^k` keeps the balance and `c + x^j` changes `r` too. With the balance test removed, or with the two tests of the check joined with an exclusive or, every rejection test passed. For a key with `f(1) = 0`, `c + d + k Phi_n` with `k n + d(1) = 0` modulo `q` decrypts to `m + d` and the same `r`, because `f Phi_n = f(1) Phi_n`. `anUnbalancedMessageIsRejectedByNTRUHPS` searches such a key, and both defects then failed it.
- Rule: a test of a check that a random key cannot fail alone searches the key that can, says why in the test, and a run against the deliberately wrong check proves that the input takes the path.

## The ranges of a mixed-radix code leave thresholds of the decoder unused

- Trap: the decoder of sntrup761 reads one or two bytes for each pair of ranges and rounds the merged range, and the two lists of ranges of sntrup761 never reach the thresholds of the C code. A mutant at a threshold passes every test of the keys and the ciphertexts.
- Finding: two mutants of `RadixEncoding::decode` survived: `>` replaced with `>=` at the product `256 * 16383`, and `(m + 255) >> 8` replaced with `(m - 255) >> 8` in a pair of two bytes. At no level of the recursion do the ranges 4591 and 1531 give a product of `256 * 16383`, or a product of two bytes whose first rounding is 1 or 2 modulo 256. A list of two values at the first threshold did not show its mutant either, because the mutant reads the same three bytes and gives the same values for a valid encoding.
- Rule: a test of a mixed-radix decoder takes the bytes of the C encoder for ranges at each threshold, and puts another pair after the pair at the threshold, so that a wrong number of bytes moves the next pair. `decodingReadsTheBytesOfEncodeAtEachThresholdOfTheRanges` is the template.

## liboqs has no known answers of `kat_sig` for some families

- Trap: a port that plans the `kats.json` digests of each set as its known-answer test finds none for SLH-DSA.
- Finding: `combine_message_signature` of `tests/kat_sig.c` has no signed-message form for SLH-DSA, so the program fails, `tests/KATs/sig/kats.json` has no entry, and `tests/test_kat.py` skips every SLH-DSA scheme, because the ACVP vectors test it instead.
- Rule: read the skips of the upstream test scripts before you plan the tests of a family. Replicate the skip in `KATSig.rs`, and take the known answers from the source that liboqs uses instead.

## An upstream vector script can skip vectors by mistake

- Trap: a Rust test that copies the vector loop of `tests/test_acvp_vectors.py` also copies its gaps.
- Finding: `slh_test_sig_name` replaces `-` with `_` in the hash name, so `SHA2-512/224` and `SHA2-512/256` keep their slash and match no liboqs name. liboqs never runs those 48 signature vectors and 26 verification vectors. `VectorsSig.rs` maps them to `SHA2_512_224` and `SHA2_512_256`, and they pass.
- Rule: map every vector of a file to its scheme, assert the count of each kind of vector, and write each upstream skip in the documentation of the test.

## A hedged signature can draw its randomness before it fails

- Trap: a port that checks the context before it draws its random bytes leaves the random source in another state than the C code.
- Finding: each SLH-DSA wrapper calls `OQS_randombytes(addrnd, n)` before `slh_sign` refuses a context of more than 255 bytes.
- Rule: copy the place of each random request relative to each check of the C code, and test the requests of the failed operation, as `aContextOfMoreThan255BytesIsRefusedAfterTheRandomRequest` does.

## The C library sets the time budget of the test suite

- Trap: the parity tests of the suite, which check every registered algorithm, take an hour once a slow family is registered.
- Finding: the C library signs a small set of SLH-DSA in 0.55 to 1.6 seconds in a release build. `RegisteredParity.rs` runs 11 cases of each scheme, `SnapshotParity.rs` the base case of each, and `runOverTheRegistryReportsItsSize` ran `parity run` over the whole registry with a limit of 120 seconds.
- Rule: `SuiteSample` of `oqs-native-algorithm-tests` holds the algorithms of the default suite, and every test of every algorithm is behind `#[ignore]` with the reason. A slow family adds its rule to `SuiteSample`, and `parity run` stays the full gate.

## A padding check of the C code can accept every input

- Trap: a port that checks the padding bits of each unpacked vector, as the comments of the C code say it does, gives another result than the C function for the restricted vectors of RSDP.
- Finding: `generic_unpack_3_bit` of the CROSS code computes its mask as `0xFF << (n * 3) & 0x7`. The shift binds before the and, so the mask is zero and the check passes for any padding. `unpack_fz_vec` of the oracle library returned 1 for seeded bytes with set padding bits, and the port with a mask of the real padding bits failed that known answer and two other tests. A changed padding bit is still refused, because the first commitment of a round hashes the bytes of the signature. A port that packed the unpacked values again would hash other bytes and accept the change: `aPaddingBitOfARestrictedVectorChangesTheCommitment` failed for that defect.
- Rule: port each check as the C code computes it, and take its known answer from the C function. When a check of the C code accepts every input, find the step that still refuses the input, and test that step with an input that breaks no other rule.

## An upstream bound must hold for every input before a port relies on it

- Trap: a port that keeps a fixed room for a variable number of items, as the C code does, panics where the C code would write past the room.
- Finding: the room of a CROSS signature for its seed path and its Merkle proof is `TREE_NODES_TO_STORE`, from a script of the CROSS team that liboqs does not ship. It is a bound and not the exact maximum: 108 for t = 256 and w = 215, where the longest seed path has 105 seeds. `theStoredNodeCountHoldsTheLongestPathAndProofOfAnyChallenge` computes the longest path and proof of each set over every challenge, by dynamic programming over the tree, and checks it against the room.
- Rule: when a port relies on a bound of the upstream code, a test proves the bound for every input, not only for the inputs of the known answers.

## A check of a value that a commitment binds cannot fail alone in a changed signature

- Trap: the group check of the CROSS verification can be lost, and every test that changes a signature still passes.
- Finding: the mutation run replaced `&=` with `|=` in the group check of `Verifier::isValidSignature`, and no test failed. A changed exponent of a published vector also changes the first commitment of its round, so the digest of the commitments refuses the signature as well. The second form z of a zero exponent gives the same arithmetic as 0, so a signer that leaves out `fz_dz_norm_n` or `fz_dz_norm_m` makes a signature that breaks the group check alone. `CROSS_verify` of liboqs refused such signatures of a copy of the C signer, and the same verification without the group check accepted them.
- Rule: when a verification checks a value that a commitment or a digest also binds, a test signs with a signer that breaks only that rule, from a constructor that only the tests have, such as `Signer::keepingTheSecondFormOfZero`. A copy of the C signer with the same step left out gives the digest of the signature, and the C verification without the check accepts it, so the input is known to reach the check.

## A changed entry of a quadratic map counts only where its variables are not zero

- Trap: a test that changes an entry of a public key and expects the verification to refuse the signature passes or fails with the point of the signature, not with the code.
- Finding: the first `aSignatureIsValidOnlyWithItsMessageItsKeyAndTheLengthsOfTheSet` of UOV changed the first byte of P1, the entry of the first variable squared. The first element of the point of the OV-Is signature was zero, which happens for one signature in 16 in GF(16), so the changed key still accepted the signature. An assertion of the precondition showed it.
- Rule: a test that changes an entry (i, j) of a public map picks i and j from the variables of the point that are not zero, or asserts that they are not zero.

## The loop of a C signature can fail after its last attempt succeeds

- Trap: a port of a rejection loop that returns the first success signs where the C code fails.
- Finding: `ov_sign` of UOV counts an attempt before it runs it, and returns -1 when the count reaches 256 after the loop. So a success of the attempt with the counter 255 is a failure. No test input reaches the last attempt, because an attempt fails only when its linear system is singular, which a random system is about once in 255 in GF(256) and once in 15 in GF(16).
- Rule: copy the count and the bound of a loop of the C code, and test the loop with an attempt function that succeeds at the first counter, at the last two counters and never, as `theFirstSuccessGivesItsResultExceptAtTheLastAttempt` does.

## A generator that keeps the rest of its block is one stream

- Trap: a port that makes P1 and P2 of UOV with two calls of AES in counter mode, each from the counter of the next whole block, gives other bytes for P2 when P1 does not end on a block boundary.
- Finding: `prng_gen_publicinputs` keeps the unused bytes of its last 16-byte block for its next call. P1 of OV-Ip has 103224 bytes, half a block past a boundary. A C program called the generator in pieces of 7, 100, 16 and 33 bytes and in one call of 156 bytes, and both gave the same digest.
- Rule: make the output of one generator of the C code as one stream, and prove it against the C generator called in pieces that do not end on a block boundary.

## Products that load and store the bytes of each entry are slow in a test build

- Trap: the key pair of a family with large matrices of vectors takes most of a second in the dev profile, also when each product is fast in a release build.
- Finding: the first UOV port added each product to the bytes of the secret key, with a load and a store of eight bytes for each word of each product. A key pair of OV-V took 0.68 seconds of processor time in the dev profile. With the sums of a row of S in words, and the powers of each entry of P1 computed once for every element of a row of O, it took 0.1 to 0.18 seconds.
- Rule: keep the sums of a target row in words, and compute the work that a factor shares with many products once. Measure the key pair in the test build as well as in the release build.

## A higher optimization level of AES does not make the UOV verifications fast

- Trap: a test of the UOV sets with a compressed public key spends its time in the expansion of P1 and P2, and an override of the optimization level of AES looks like the fix.
- Finding: the 102 verifications of `SignatureCorrectnessTest` for OV-V-pkc expand 2.4 MB with AES each. They took 2.5 seconds of processor time in the dev profile, and 2.1 seconds with `opt-level = 3` for `oqs-native-aes`. The bitsliced AES is straight-line code, which the first level already compiles well.
- Rule: measure an override of the optimization level before you add it. The workspace keeps AES at the level of the dev profile.
