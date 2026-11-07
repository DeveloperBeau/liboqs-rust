# Domain

## Purpose

`Modules/Domain` (package `oqs-native-domain`, library `OQSNativeDomain`) holds the capability interfaces that each algorithm family implements, and the rules that more than one family uses. It depends only on the entities crate and builds without the standard library.

## Interfaces

| Trait | Capability |
|---|---|
| `RandomGenerating` | A source of random bytes. The caller passes it to each operation. |
| `KeyEncapsulating` | Key generation, encapsulation and decapsulation of one parameter set, with the optional seed forms of liboqs `keypair_derand` and `encaps_derand`. |
| `Signing` | Key generation, signing and verification of one parameter set, with and without a context string, as `OQS_SIG_sign` and `OQS_SIG_sign_with_ctx_str`. |
| `StatefulSigning` | The same for a stateful scheme, with the counts of signatures left and in total. |
| `KeyStatePersisting` | The saving of an advanced stateful secret key. |

## Rules

- **Random bytes come from the caller.** An algorithm never reaches the operating system. A test passes the NIST KAT generator, which gives the same bytes as the C library gets from its own generator, so the outputs match byte for byte.
- **Input lengths are exact.** `InputLength::checked` returns the input or `OQSError::invalidLength`. Each family calls it for each key, ciphertext and seed.
- **A scheme without context support signs only with an empty context.** The default methods `signWithContext` and `isValidSignatureWithContext` of `Signing` give that rule. An empty context gives the plain signature. A scheme with context support overrides both methods.
- **Persist before release.** The default method `releaseSignature` of `StatefulSigning` saves the advanced secret key and returns the signature only when the save succeeds. A failed save gives `OQSError::persistenceFailed`.
- **No seed form unless the family has one.** The default seed methods of `KeyEncapsulating` return `OQSError::seedNotSupported`.

## Tests

`TestDoubles.rs` holds a small mechanism, a small scheme, a counting stateful scheme, a counting random source and a key store that records or refuses each save. The tests use them to prove each rule above, through the trait objects.
