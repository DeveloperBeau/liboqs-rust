# Entities

## Purpose

`Modules/Entities` (package `oqs-native-entities`, library `OQSNativeEntities`) holds the plain data types that every other crate shares. It depends on no other crate and builds without the standard library (`no_std` with `alloc`).

## Types

| Type | Holds |
|---|---|
| `KEMDescription` | The fixed facts of one key encapsulation mechanism, field for field as the liboqs `OQS_KEM` structure: name, version, claimed NIST level, IND-CCA claim and the five lengths, with the two seed lengths. |
| `SignatureDescription` | The facts of one signature scheme, as `OQS_SIG`: name, version, level, EUF-CMA and SUF-CMA claims, context support and the three lengths. |
| `StatefulSignatureDescription` | The facts of one stateful scheme, as `OQS_SIG_STFL`, with its object identifier. |
| `KeyPair` | A public key and its secret key. |
| `Encapsulation` | A ciphertext and its shared secret. |
| `SecretBytes` | Secret material. It wipes its bytes when it is dropped. |
| `OQSError` | The ways an operation can fail. |

All keys, ciphertexts and signatures use the byte formats of liboqs, so bytes from the C library work in the port and the other way around.

## Secret material

`SecretBytes` owns a vector of bytes and writes zero over it in `Drop`. The write uses `core::ptr::write_volatile` and a compiler fence, because the optimizer may remove a plain write to memory that is about to be freed. This is the one `unsafe` function of the shipped crates. `Documentation/Registers/UnsafeCode.md` lists it.

`SecretBytes` has no equality operator, because a plain comparison of secret bytes leaks their value through its run time. Its `Debug` text shows the length and never the bytes.

## Edge cases

- A description is a value of constants. A family crate defines one for each parameter set, and the C oracle tests compare each field with the C structure.
- `OQSError::invalidLength` carries both lengths, so a caller can see what the algorithm expected.

## Tests

Unit tests in each file: the wipe writes zero over every byte, the constructors and accessors keep the bytes, a clone is an independent copy, the debug text hides the bytes, and each error case has its message.
