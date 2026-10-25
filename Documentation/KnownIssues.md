# Known issues and open decisions of 0.16.0

The port gives the bytes of liboqs 0.16.0 for the same random bytes. This page lists what the release does not cover, where the port follows the C library on purpose in a way a user may not expect, the gaps of the tests, the findings in the upstream code, and the decisions that are still open. Each entry names the page that holds its detail.

## What the release does not cover

- **Large stateful trees.** The default `parity run` and the gate skip the 23 stateful sets with a tree of height 20 or 25, because a key pair takes from minutes to days on each side. The 19 sets of height 20 gave the base case and 1000 variations identical to the C library in the `Large trees` workflow. The four LMS sets of height 25 need a machine without the six-hour limit of a hosted job. `Documentation/Registers/LargeTrees.md` records the result of each set.
- **Secret intermediates.** `SecretBytes` wipes the secret keys and shared secrets that the API returns, through the one audited `unsafe` function of the port. The expanded keys and the buffers inside an operation are not wiped, where some C families wipe theirs (`mayo_secure_clear`, the zeroize calls of mldsa-native). `Documentation/Registers/UnsafeCode.md` describes the wipe.
- **Timing.** The port follows the constant-time structure of each C implementation that it translates. No tool has measured the timing of the Rust code. MQOM branches on the bits of public equation elements where the C code uses masks, so its timing depends on the public key only.
- **Operating system randomness.** `SystemRandom` reads the random source of a Unix system. Other systems need a `RandomGenerating` source of their own.
- **Speed.** The port has only the portable code of each family, with no assembly and no vector instructions. The XMSS sets of SHAKE and of 192 bits are 9 to 25 percent slower than the portable C library, because the shared SHA-3 crate runs a looped permutation.

## Behavior that follows the C library

- **Falcon:** a hostile secret key that decodes but is not a real key, such as one with F = 0, makes signing loop for ever, in the C library and in the port. A compressed signature of any length is accepted when its value decodes exactly, as in the C code.
- **MQOM:** the C function `SampleChallenge` loops over the nonces with no end. The port tries each 32-bit nonce once and then fails with `operationFailed`. No known input reaches that point.
- **Classic McEliece and NTRU:** the constant fuzz inputs of all 0x00 or all 0xFF bytes give an encapsulation that never ends (Classic McEliece) or a key that cannot decapsulate (NTRU), in the C code too. The fuzz tests start at case 2.
- **CROSS:** the message length enters the hash as a 32-bit value, as in the C code.
- **XMSS:** the count of updates passes through a signed char, as on x86-64. On a target where `char` is unsigned, such as AArch64 Linux, the C library gives another count for a forged state. Signing past the end of a key does not copy the C behavior, and the tests check it on their own.
- **LMS:** an exhausted key gives `keyExhausted` and a malformed key `operationFailed`, where the C library returns `OQS_ERROR` for both. The secret key has the 10980 bytes of the serialized key and its aux data, where the C description says 64 bytes. The 32nd signature of a set of height 5, which writes 0xFF over the private key, is tested on its own.

## Gaps of the tests

- **Open Falcon mutants.** 11 mutants of the Falcon mutation run are neither killed nor proved equivalent: ten degrade the two-word approximation of `BigInteger::bezout`, and one swaps the NTT product and the plain product in `NTRUSolver`. Searches found no input that tells them apart. `Documentation/Registers/MutationResults.md`, section "Latest result for Falcon", gives the evidence.
- **Equivalent mutants.** Each family records its equivalent mutants with a proof. Some families rewrote such lines into forms that tests check, others keep the form of the C code. `Documentation/Learnings/MutationTesting.md` holds the rules.
- **Known-answer scheme.** BIKE, Classic McEliece, LMS and XMSS take some of their unit test inputs and digests from programs of their own, not from the shared sequence and digest of `Documentation/Learnings/COracle.md`.
- **Tests without a C answer.** The bound of the WOTS+ chain of XMSS is checked as a property, because the C function is static. The signature of eight LMS levels signs through a test scheme with room for it, because no liboqs set has that room.

## Findings in the upstream code

- `tests/test_acvp_vectors.py` of liboqs skips the SLH-DSA pre-hash vectors of SHA2-512/224 and SHA2-512/256, because its name mapping keeps their slash. The port passes them.
- The XMSS response files of the six 192-bit sets and of the three `XMSS-SHAKE256_*_256` sets hold seeds that the NIST generator does not give.
- A long-lived working key of hash-sigs gives signatures that stop verifying from the fifth signature of a one-level key. liboqs never reaches it, because it loads the key for each signature. The parity oracle reloads the key where the C working key goes wrong.

## Open decisions

These choices stand as the release has them, and a later release may change them.

- One rule for an endless loop of the C code on hostile input: keep it, as Falcon does, or stop it with an error, as MQOM does.
- One rule for an equivalent mutant: rewrite the line into a form that tests check, or keep the form of the C code with a proof.
- The wiping of secret intermediates with the audited wipe function.
- A working-key form of `StatefulSigning` in the domain crate, in place of the `LMSWorkingKey` that the parity harness uses.
- The public API of SLH-DSA: one constant per pure set, `preHashed` for the pre-hash forms, and `SLHDSA::schemes` with all 156 schemes.
- The names check of the repository, which accepts any word in capitals as an acronym.
- A faster shared SHA-3 and SHA-2, for the families where the port is slower than the C library.
