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
3. A family with many schemes gives them as one slice, such as the 156 schemes of `SLHDSA::schemes`. The signature list is a list of such groups, and the constant function `joined` puts the groups one after another into one list when the crate compiles. So `Registry::signatureSchemes` is one slice, as before.
4. `Registry::mechanism("ML-KEM-768")` returns the mechanism whose description has that name, or `None`.

## Edge cases

- A name is the exact liboqs name. The lookup does not ignore case.
- The registry holds the families that are ported. Each family adds its values, and `Tools/Parity/NotYetPorted.txt` lists the algorithms that are not ported yet.
- `joined` fills the list with the first algorithm of the groups before it writes each place, so the groups must hold one algorithm or more. A count that is not the number of algorithms of the groups stops the build.

## Tests

- `everyNameIsUniqueAcrossTheThreeLists`, `eachAlgorithmIsFoundByItsOwnName` and `anUnknownNameFindsNothing` in `Registry.rs`.
- `groupsJoinInTheirOrderAndSkipEmptyGroups` and `signatureSchemesAreTheSchemesOfTheGroupsInOrder` in `Registry.rs`.
- `AlgorithmCoverage.rs` in `Tools/Parity` checks the registry against the C library: the names, the facts of each algorithm and the order.
