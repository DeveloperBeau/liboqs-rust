# Randomness

## Purpose

An algorithm never reaches a random source by itself. Each operation takes a `RandomGenerating` source as an argument. The composition root passes the operating system source, and a test passes a seeded generator that gives the same bytes as the generator of the C library.

## Crates

| Crate | Ring | Gives |
|---|---|---|
| `oqs-native-system-random` (`OQSNativeSystemRandom`) | `infrastructure` | `SystemRandom`: the bytes of `/dev/urandom`. Unix only, by the decision of the owner. |
| `oqs-native-kat-random` (`OQSNativeKATRandom`) | `infrastructure` | `NISTKATRandom` and `HQCKATRandom`, the generators of the known-answer tests. They are not a source of secret randomness. |

## The NIST generator

`NISTKATRandom` translates liboqs `src/common/rand/rand_nist.c`, the AES-256 CTR DRBG of the NIST submission package.

1. `new` masks the 48 bytes of entropy with the optional personalization string, and updates a zero key and a zero counter with them.
2. Each `fillRandomBytes` call adds one to the 128-bit big-endian counter for each 16 bytes, encrypts the counter, and then updates the key and the counter.
3. The update encrypts three more counter blocks and mixes the provided data into them.

Because each request ends with an update, two requests of 32 and 16 bytes do not give the same bytes as one request of 48. So an algorithm must ask for its random bytes in the same amounts as the C code, or its output differs from the C library.

The C code keeps the state in a global variable. The port keeps it in a value, so tests can run in parallel. A clone is the saved state of `OQS_randombytes_nist_kat_get_state`.

## The HQC generator

`HQCKATRandom` is the generator that liboqs `tests/test_helpers.c` uses for the HQC known answers: SHAKE256 of the entropy, the optional personalization string and the domain byte zero. Its output does not depend on how the requests split the bytes.

## Tests

- The NIST generator gives the first two seeds of every NIST known-answer file. The first seed is also in the secret key of `tests/KATs/sig_stfl/xmss/XMSS-SHA2_10_256.rsp`.
- The split of requests changes the output, a clone restores the state, and personalization is a mask of the entropy.
- The HQC generator equals SHAKE256 of its input, which the SHA-3 crate proves with its own known answers.
- `SystemRandom` has a contract test, the only test that reads the random source of the operating system.
