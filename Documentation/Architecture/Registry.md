# The registry

## Purpose

The facade crate `oqs-native`, with the library name `OQSNative`, is the composition root of the port. `Registry` finds each algorithm by its liboqs name, and the crate re-exports the capability interfaces, the data types and the system random source, so a user needs only this crate.

## Crate

| Crate | Folder | Ring |
|---|---|---|
| `oqs-native` | `Modules/OQSNative` | `composition` |

## Data flow

1. Each family crate makes a constant for each parameter set, such as `MLKEM::mlkem768`.
2. The registry lists those values in three constant lists, one for KEMs, one for signature schemes and one for stateful signature schemes, in the order of the liboqs lists.
3. `Registry::mechanism("ML-KEM-768")` returns the mechanism whose description has that name, or `None`.

## Edge cases

- A name is the exact liboqs name. The lookup does not ignore case.
- The registry holds the families that are ported. Each family adds its values, and `Tools/Parity/NotYetPorted.txt` lists the algorithms that are not ported yet.

## Tests

- `everyNameIsUniqueAcrossTheThreeLists`, `eachAlgorithmIsFoundByItsOwnName` and `anUnknownNameFindsNothing` in `Registry.rs`.
- `AlgorithmCoverage.rs` in `Tools/Parity` checks the registry against the C library: the names, the facts of each algorithm and the order.
