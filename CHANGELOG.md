# Changelog

The version of each crate equals the version of liboqs that it ports. Each entry lists what changed in this port, not in liboqs.

## 0.16.0

The first release: a native Rust port of every algorithm of liboqs 0.16.0, with no C in any shipped crate.

### Algorithms

- **Key encapsulation:** ML-KEM, Kyber, FrodoKEM, eFrodoKEM, HQC, BIKE, NTRU, NTRU Prime (sntrup761) and Classic McEliece.
- **Signatures:** ML-DSA, Falcon, MAYO, SLH-DSA (the 12 pure and 144 pre-hash schemes), CROSS, UOV, SNOVA and MQOM.
- **Stateful signatures:** XMSS, XMSS^MT and LMS.
- 332 algorithms in all. `Registry` finds each one by its liboqs name, and `oqs-native` re-exports the families, the capability interfaces and the data types.

### Behavior

- Every algorithm gives the bytes of the C library for the same random bytes: keys, ciphertexts, shared secrets, signatures, the advanced secret keys of the stateful schemes and the verdicts on changed inputs.
- Each operation takes its random source as an argument. `SystemRandom` reads the random source of a Unix system, and the NIST DRBG of the known-answer tests is in `oqs-native-kat-random`.
- The crates build without the standard library, with `core` and `alloc`.
- Zero third-party dependencies in the shipped crates, and one audited `unsafe` function, the wipe of `SecretBytes`.

### Evidence

- The known-answer digests of liboqs, the ACVP vectors of SLH-DSA and the response files of the stateful schemes pass.
- The replicated test programs of liboqs pass: the KEM, signature and stateful signature programs, the fuzz programs with hostile inputs, and the memory tests.
- The base case and 1000 seeded variations of 328 of the 332 algorithms are identical to the C library: 309 in the parity gate, and the 19 stateful sets with a tree of height 20 in the `Large trees` workflow. The four LMS sets of height 25 take from about 7 hours to about four days each, and `Documentation/Registers/LargeTrees.md` records their runs.
- Each family has a recorded mutation run in `Documentation/Registers/MutationResults.md`, with the test that kills each mutant or the proof that it is equivalent.

### Known issues

See `Documentation/KnownIssues.md`.
