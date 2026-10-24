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
