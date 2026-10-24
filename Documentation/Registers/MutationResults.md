# Mutation results

This register holds the result of the latest mutation run of each crate, and the named test that kills a mutant of each rule. A change that adds a rule adds its row in the same change.

## How to run

1. Run `cargo mutants --package <name> -j 4` from the repository root.
2. Read the summary line. `.cargo/mutants.toml` holds the settings.
3. Give each missed mutant a test, or record here why the mutant is equivalent.

A mutant is "caught" when a test fails. A "timeout" is a mutant that makes a loop run forever: the suite does not end, so it counts as caught. An "unviable" mutant does not build and proves nothing.

## Latest result for `xtask`

The run of 2026-10-23 on the branch `foundation/workspace`. The table counts each mutant once. `NamingCheck.rs` changed after the full run, so its row comes from a second run of that file alone.

| File | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `src/CargoManifest.rs` | 115 | 113 | 0 | 2 | 0 |
| `src/Command.rs` | 8 | 7 | 0 | 1 | 0 |
| `src/DeclarationScanner.rs` | 137 | 130 | 0 | 7 | 0 |
| `src/DiskFileSystem.rs` | 10 | 10 | 0 | 0 | 0 |
| `src/Finding.rs` | 1 | 1 | 0 | 0 | 0 |
| `src/HygieneCheck.rs` | 22 | 20 | 0 | 2 | 0 |
| `src/IdentifierCasing.rs` | 14 | 14 | 0 | 0 | 0 |
| `src/MarkdownTable.rs` | 18 | 17 | 0 | 1 | 0 |
| `src/NamingCheck.rs` | 37 | 33 | 0 | 4 | 0 |
| `src/RingCheck.rs` | 13 | 9 | 0 | 4 | 0 |
| `src/RustToken.rs` | 15 | 15 | 0 | 0 | 0 |
| `src/RustTokenizer.rs` | 91 | 80 | 8 | 3 | 0 |
| `src/TokenTree.rs` | 29 | 24 | 0 | 5 | 0 |
| `src/VersionCheck.rs` | 18 | 17 | 0 | 1 | 0 |
| `src/WorkspaceLayout.rs` | 9 | 8 | 0 | 1 | 0 |
| `src/lib.rs` | 5 | 3 | 0 | 2 | 0 |
| `src/main.rs` | 1 | 1 | 0 | 0 | 0 |
| All | 543 | 502 | 8 | 33 | 0 |

No mutant is missed, and no mutant is recorded as equivalent. The eight timeouts are in the low-level loops of `RustTokenizer`: with the mutant, the tokenizer stops moving and the suite does not end.

## Expected result for each rule

Each row names one mutant of a rule and the tests that fail under it. The test names are the expected result: if a later run does not fail these tests for this mutant, the tests have lost their link to the rule.

| Rule | Mutant | Killed by |
|---|---|---|
| A local dependency is one with a path | `RingCheck::findings`, line 138: operator replaced with `&&` | `allowedEdgeHasNoFinding`, `everyRingPairMatchesTheHandWrittenTable` and 12 more |
| A crate depends only on the rings of its register row | `RingCheck::findings`, line 102: operator deleted | `allowedEdgeHasNoFinding`, `crateWithoutRingAndCrateWithUnknownRingAreFindings` and 16 more |
| Each kind of name has its own casing rule | `NamingCheck::problem`, line 154: match arm deleted | `libraryNameMustBeUpperCamelCaseAndALibraryMustSetIt`, `mixedAcronymIsAFinding` and 7 more |
| A mixed acronym such as Kem is found | `titleCaseWords`, line 32: operator replaced with `||` | `titleCaseWordsSplitsMixedAcronymsAndSkipsWholeAcronyms`, `swiftCasingHasNoFinding` |
| Each part of a version is digits only | `VersionCheck::isReleaseVersion`, line 93: operator replaced with `||` | `malformedOrMissingVersionIsAFinding`, `versionWithAnEmptyOrNonNumericPartIsAFinding` |
| The workspace version equals LIBOQS_VERSION | `VersionCheck::findings`, line 37: match guard replaced with `false` | `agreeingVersionsHaveNoFinding`, `crateWithItsOwnVersionIsAFinding` and 5 more |
| A semicolon is a finding in prose only | `HygieneCheck::textFindings`, line 129: operator replaced with `||` | `absolutePathIsAFinding`, `cleanProseHasNoFinding` and 11 more |
| An empty word variable falls back to the local file | `HygieneCheck::forbiddenWords`, line 32: operator deleted | `forbiddenWordIsAFindingInTextAndInPathsInAnyLetterCase`, `forbiddenWordsComeFromTheVariableFirstAndElseFromTheLocalFile` and 4 more |
| A character literal is told apart from a lifetime | `RustTokenizer::readQuote`, line 124: operator replaced with `!=` | `characterLiteralsAndLifetimesAreToldApart`, `quoteInsideACharacterLiteralDoesNotStartAString` and 4 more |
| Block comments nest | `RustTokenizer::skipBlockComment`, line 80: operator replaced with `+=` | `blockCommentsNestAndEndAtTheirOwnClose`, `linesAreCountedThroughCommentsStringsAndRawStrings` and 3 more |
| Commas inside angle brackets do not split an item | `TokenTree::commaSeparatedItems`, line 59: operator replaced with `-=` | `commaSeparatedItemsSplitOnlyOutsideAngleBrackets`, `structureFieldsWithVisibilityAndAttributesAreFound` |
| The body of a macro_rules macro is not entered | `DeclarationScanner::scanMacro`, line 189: operator replaced with `-` | `keywordsAtTheEndOfTheInputRecordNothing`, `macroBodyIsSteppedOverAndTheScanGoesOnAfterIt` and 2 more |
| Generic parameters end at the matching close | `DeclarationScanner::scanGenerics`, line 222: operator replaced with `-=` | `commentsStringsCharactersAndLifetimesHideNoNames`, `functionWithGenericsAndParametersIsFound` and 9 more |
| An extern block is not entered | `DeclarationScanner::skipExtern`, line 206: operator replaced with `*` | `externBlockAndExternFunctionNamesAreLeftOut` |
| Each command word selects its check | `Command::parse`, line 25: match arm deleted | `parseReadsEachCommandWord`, `parseRejectsUnknownMissingAndExtraArguments` and 5 more |
| A finding gives exit status 1 | `run`, line 133: operator deleted | `runPassesWithStatusZeroAndThePassLine`, `runPrintsTheWordListNoteOnlyForAHygieneScanWithoutWords` and 2 more |
| A member pattern matches child folders only | `WorkspaceLayout::matches`, line 58: operator replaced with `!=` | `loadFindsMembersOfWildcardAndPlainPatternsOnly`, `libraryNameMustBeUpperCamelCaseAndALibraryMustSetIt` and 15 more |
| A bracket inside a string does not continue a value | `CargoManifest::openBracketCount`, line 260: match guard replaced with `true` | `bracketsInsideAStringDoNotContinueTheValue` |

## Latest result for `oqs-native-entities` and `oqs-native-domain`

The run of 2026-10-23 on the branch `foundation/entities-domain`.

| File | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| All files of both crates | 26 | 23 | 0 | 3 | 0 |

| Rule | Mutant | Killed by |
|---|---|---|
| Dropped secret bytes are wiped | `<impl Drop for SecretBytes>::drop`: body replaced with `()` | `dropWipesTheBytesBeforeTheMemoryIsFreed` |
| The wipe writes zero over every byte | `wipe`: body replaced with `()` | `wipeWritesZeroOverEveryByte`, `dropWipesTheBytesBeforeTheMemoryIsFreed` |
| Debug text never shows secret bytes | `<impl fmt::Debug for SecretBytes>::fmt`: body replaced | `debugTextShowsTheLengthButNeverTheBytes` |
| Inputs have the exact length | `InputLength::checked`: `==` replaced with `!=` | `checkedRejectsAShorterAndALongerInputWithBothLengths`, `checkedReturnsAnInputOfTheExpectedLength` |
| A scheme without context support accepts only an empty context | `Signing::isValidSignatureWithContext`: `&&` replaced with `||` | `verificationWithContextAcceptsOnlyAnEmptyContext` |

The `xtask` files that this branch changed (`Command.rs`, `UnsafeCodeCheck.rs`, `lib.rs`) gave 18 mutants: 13 caught, 5 unviable, 0 missed.

## Latest result for `oqs-native-sha3`, `oqs-native-sha2` and `oqs-native-aes`

The run of 2026-10-23 on the branch `foundation/primitives`.

| File | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `Modules/AES/src/AES128.rs` | 3 | 3 | 0 | 0 | 0 |
| `Modules/AES/src/AES256.rs` | 3 | 3 | 0 | 0 | 0 |
| `Modules/AES/src/Bitsliced.rs` | 511 | 510 | 0 | 0 | 1 |
| `Modules/AES/src/ExpandedKey.rs` | 15 | 15 | 0 | 0 | 0 |
| `Modules/SHA2/src/SHA256.rs` | 53 | 53 | 0 | 0 | 0 |
| `Modules/SHA2/src/SHA384.rs` | 5 | 5 | 0 | 0 | 0 |
| `Modules/SHA2/src/SHA512.rs` | 5 | 5 | 0 | 0 | 0 |
| `Modules/SHA2/src/SHA512Core.rs` | 50 | 49 | 1 | 0 | 0 |
| `Modules/SHA3/src/KeccakF1600.rs` | 34 | 34 | 0 | 0 | 0 |
| `Modules/SHA3/src/KeccakSponge.rs` | 30 | 30 | 0 | 0 | 0 |
| `Modules/SHA3/src/SHA3256.rs`, `SHA3384.rs`, `SHA3512.rs` | 15 | 15 | 0 | 0 | 0 |
| `Modules/SHA3/src/SHAKE128.rs`, `SHAKE256.rs` | 8 | 4 | 0 | 4 | 0 |
| `Modules/SHA3/src/SHAKEReader.rs` | 1 | 1 | 0 | 0 | 0 |

### The one equivalent mutant

`Bitsliced.rs`, `substitute`, the line `let t37 = t36 ^ t34;`: `^` replaced with `|` survives. The two signals of the Boyar and Peralta circuit never have a set bit in common, so `^` and `|` give the same value. The proof is the test `bitslicedSubstitutionMatchesTheTableForEveryByte`, which checks all 256 inputs of the S-box against the table of FIPS 197: the mutant passes it, so it is equal to the correct S-box for every input. A later run must show this mutant, and only this one, as missed.

| Rule | Mutant | Killed by |
|---|---|---|
| The S-box is the AES S-box | `substitute`: each other operator of the circuit replaced | `bitslicedSubstitutionMatchesTheTableForEveryByte`, `aes128EncryptsTheBlockOfFips197` |
| The counter is 32 bits, big-endian, and wraps | `ExpandedKey::fillCounterKeystream`: `wrapping_add` operands and the byte swap | `counterWrapsAtThirtyTwoBitsAndKeepsTheFirstTwelveBytes`, `counterKeystreamIsTheEncryptionOfCounterBlocks` |
| Counter blocks continue the stream | `AES256::fillCounterBlocks`: counter update removed | `counterBlocksContinueTheKeystreamAndAdvanceTheCounter` |
| Only AES-256 substitutes the fourth key word | `scheduleKey`: `==` replaced with `!=` | `aes256EncryptsTheBlockOfFips197` |
| SHA-2 pads at each block edge | `SHA256::absorbPadding`: `>=` replaced with `>` | `splitInputGivesTheOneShotDigestAtEveryLength` |
| The SHAKE stream does not depend on the call sizes | `KeccakSponge::squeeze`: block test replaced | `shake128SmallAbsorbAndSqueezeCallsGiveTheSameStream` |

## Latest result for `oqs-native-kat-random` and `oqs-native-system-random`

The run of 2026-10-23 on the branch `foundation/random`: 12 mutants, 12 caught, 0 missed.

| Rule | Mutant | Killed by |
|---|---|---|
| The DRBG gives the NIST seeds | `NISTKATRandom::update` and `incrementCounter`: each operator replaced | `nistGeneratorGivesTheSeedsOfTheNISTKnownAnswerFiles` |
| Each request ends with an update | `NISTKATRandom::fillRandomBytes`: the update removed | `nistGeneratorOutputDependsOnHowRequestsSplitTheBytes` |
| Personalization masks the entropy | `NISTKATRandom::new`: the mask removed | `personalizationIsMixedIntoTheSeedMaterial` |
| The HQC generator absorbs the domain byte | `HQCKATRandom::new`: the domain byte removed | `hqcGeneratorIsSHAKE256OfTheSeedAndTheDomainByte` |
| The system source fills the buffer | `SystemRandom::fillRandomBytes`: body replaced with `()` | `readsGiveFreshBytesThatAreNotZero` |

## History

| Run | Code | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|---|
| 1 | First version of the tool | 758 | 492 | 111 | 19 | 136 |
| 2 | Token trees, `run` and `Report`, new tests | 564 | 512 | 14 | 33 | 5 |
| 3 | The five survivors removed or killed | 544 | 503 | 8 | 33 | 0 |
| 4 | `NamingCheck.rs` only, after the module rule change | 37 | 33 | 0 | 4 | 0 |

`Documentation/Learnings/MutationTesting.md` records what the first two runs taught.
