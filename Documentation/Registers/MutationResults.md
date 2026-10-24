# Mutation results

This register holds the result of the latest mutation run of each crate, and the named test that kills a mutant of each rule. A change that adds a rule adds its row in the same change.

## How to run

1. Run `cargo mutants --package <name> -j 4` from the repository root.
2. Read the summary line. `.cargo/mutants.toml` holds the settings.
3. Give each missed mutant a test, or record here why the mutant is equivalent.
4. Run the facade as `cargo mutants --package oqs-native --test-package oqs-native,oqs-native-parity --timeout 900 -j 4`. The coverage tests of the parity crate are the tests that see a wrong registry. The baseline times only the tests of the mutated package, so the explicit timeout keeps the slower tests of the parity crate from reading as timeouts.

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
| The S-box is the AES S-box | `substitute`: each other operator of the circuit replaced | `bitslicedSubstitutionMatchesTheTableForEveryByte`, `aes128EncryptsTheBlockOfFIPS197` |
| The counter is 32 bits, big-endian, and wraps | `ExpandedKey::fillCounterKeystream`: `wrapping_add` operands and the byte swap | `counterWrapsAtThirtyTwoBitsAndKeepsTheFirstTwelveBytes`, `counterKeystreamIsTheEncryptionOfCounterBlocks` |
| Counter blocks continue the stream | `AES256::fillCounterBlocks`: counter update removed | `counterBlocksContinueTheKeystreamAndAdvanceTheCounter` |
| Only AES-256 substitutes the fourth key word | `scheduleKey`: `==` replaced with `!=` | `aes256EncryptsTheBlockOfFIPS197` |
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

## Latest result for the oracle, the known-answer programs, the registry and the parity harness

The runs of 2026-10-23 on the branch `foundation/oracle`, with `OQS_ORACLE_DIR` set to the oracle folder, because `cargo mutants` builds a copy of the workspace without `target`.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-c-oracle` | 138 | 112 | 0 | 26 | 0 |
| `oqs-native-algorithm-tests` | 63 | 59 | 0 | 4 | 0 |
| `oqs-native` | 21 | 2 | 0 | 7 | 12 |
| `oqs-native-parity` | 183 | 169 | 1 | 8 | 5, then 1 |
| `xtask`, the files of the oracle build | 26 | 21 | 0 | 5 | 0 |

The second run of `oqs-native-parity` covered the four files that changed after the first: 113 mutants, 108 caught, 1 timeout, 3 unviable and 1 missed.

### Equivalent mutants

- `oqs-native`, `Registry.rs`: the 12 missed mutants replace a list with an empty list, a lookup with `None`, or the name of an algorithm with another text. The three lists are empty until the first family registers an algorithm, so no test can see a difference yet. `eachAlgorithmIsFoundByItsOwnName` and the coverage tests of `Tools/Parity` kill each of them once its list holds an algorithm. The family pull requests record the runs that kill them.
- `oqs-native-parity`, `VariationGenerator::usesContextForm`: `==` replaced with `!=` in `self.below(2) == 0`. The coin decides the form of a variation with an empty context. The mutant inverts a fair coin, which gives the same distribution, so no test can tell the two apart.

| Rule | Mutant | Killed by |
|---|---|---|
| Every C call checks the input lengths first | `checkedLength`: `==` replaced with `!=` | `wrongLengthsAreErrorsBeforeAnyCCall` |
| The oracle lists only the enabled algorithms | `enabledNames`: `== 1` replaced with `!= 1` | `descriptionsHoldTheFactsOfTheCLibrary` |
| A second oracle on one thread stops at once | `COracle::new`: the assertion removed | `secondOracleOnOneThreadStopsAtOnceAndDoesNotWaitForItself` |
| The known-answer text prints an empty value as `00` | `KnownAnswerText::appendBytes`: the empty case removed | `linesFollowTheFormatOfTheCPrograms` |
| HQC uses the SHAKE256 generator | `KnownAnswerRandom::generator`: the condition replaced | `hqcUsesTheSHAKEGeneratorAndEveryOtherNameTheNISTGenerator` |
| Each layout of `kat_sig` joins its parts in its order | `SignedMessageForm::signedMessage`: each arm replaced | `signedMessagesJoinThePartsInTheOrderOfTheForm`, `falconFormMovesTheSaltBeforeTheMessageAndTheHeaderAfterIt` |
| A failure on one side only is a mismatch | `agreeOnFailure`: body replaced with `Ok(())` | `aFailureOnOneSideIsAMismatchThatNamesTheSide` |
| A changed input changes exactly one bit | `VariationGenerator::withChangedBit`: `^=` replaced with `|=` or `&=`, `/` replaced with `%` | `aChangedBitChangesExactlyOneBitAndReachesEveryBit` |
| A non-empty context always uses the context form | `VariationGenerator::usesContextForm`: `||` replaced with `&&`, `>` replaced | `aNonEmptyContextAlwaysUsesTheContextFormAndAnEmptyOneUsesBoth` |
| The variations reach each message length range | `VariationGenerator::messageLength`: `+` replaced with `*` | `messageLengthsCoverEachRangeAndStayInTheLimit` |
| A snapshot check counts each failure | `ParityJob::snapshotCheck`: `+=` replaced | `snapshotCheckCountsEachFailureAndEachMissedDigest` |
| The oracle build clones only a missing source | `OracleBuild::steps`: the clone condition replaced | `missingSourceIsClonedAtTheVersionTagAndThenBuilt`, `presentSourceOfTheVersionIsBuiltWithoutAClone` |
| The oracle build stops at the first failed step | `fetchOracle`: the early return removed | `fetchOracleStopsAtTheFirstFailedStep` |

## Latest result for ML-KEM, Kyber and the behavior programs

The runs of 2026-10-23 on the branch `family/ml-kem`, with `OQS_ORACLE_DIR` set to the oracle folder.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-ml-kem` | 339 | 292 | 4 | 40 | 3 |
| `oqs-native-algorithm-tests` | 242 | 217 | 8 | 17 | 0 |
| `oqs-native` | 21 | 5 | 0 | 7 | 9 |
| `xtask`, the files of the vector download | 26 | 21 | 0 | 5 | 0 |

The first run of `oqs-native-ml-kem` missed 7 of 350 mutants, and the first run of `oqs-native-algorithm-tests` missed 80 of 271, most of them in the signature programs, which had no tests yet. The table holds the second runs, after the new tests and the simpler JSON reader. The four timeouts of ML-KEM are in the rejection loop of `sampledUniform`, which then never ends. The eight of the test support are in the JSON reader, whose position then stops moving.

### Equivalent mutants

- `oqs-native-ml-kem`, `Polynomial.rs`, `twelveBitPair`: `|` replaced with `^`, twice. The operands of the first `|` hold bits 0 to 7 and bits 8 to 11, and the operands of the second hold bits 0 to 3 and bits 4 to 11. They have no set bit in common, so `|` and `^` give the same value for every input.
- `oqs-native-ml-kem`, `Polynomial.rs`, `rootPowers`: `|` replaced with `^` in `(reversed << 1) | bit`. The shift clears bit 0, and the other operand is bit 0 alone, so the two operators give the same value.
- `oqs-native`, `Registry.rs`: 9 of the 12 mutants that P0 recorded. Eight replace the signature list or the stateful list with an empty list, a lookup with `None`, or a name with another text, and those lists stay empty until the first signature family. The ninth replaces the KEM list with an empty list. It survived because this run had only the tests of the facade. The FrodoKEM run below adds the tests of `Tools/Parity`, which kill it. `eachAlgorithmIsFoundByItsOwnName` kills the other two mutants of the KEM list, the names and the lookup.

| Rule | Mutant | Killed by |
|---|---|---|
| The decapsulation compares every byte of the re-encryption | `MLKEM::decapsulation`, line 112, and `Kyber::decapsulate`, line 121: the or of the fold of the differences replaced with `^` | `aCiphertextWithTheSameBitChangedInTwoBytesIsRejected` |
| ML-KEM refuses a public key with a coefficient of q or more | `MLKEM::encapsulation`, line 64: `!` deleted | `fuzzTestKEMPassesForEveryParameterSet`, `aPublicKeyWithACoefficientAboveTheModulusIsRejected` |
| The modulus check refuses q and accepts q - 1 | `Polynomial::isCanonicalEncoding`, line 216: `<` replaced with `<=` | `decodingOfTwelveBitsReducesModuloQAndTheCheckSeesIt` |
| Sampling keeps only the values below q | `Polynomial::sampledUniform`, line 259: `<` replaced with `<=` | `uniformSamplingGivesCanonicalValuesThatDependOnTheIndexBytes` and the known-answer tests of each set |
| Compression rounds to the nearest value | `Polynomial::compressed`, line 223: `+` replaced with `-` | `compressionRoundsToTheNearestValueForEveryCoefficient` |
| A wrong length gives the length error with the expected length | `KEMFuzzTest::run`, line 93, and `SignatureFuzzTest::run`, line 68: match guard replaced with `true` | `fuzzTestReportsAWrongSecretAndAWrongLengthCheck`, `fuzzTestReportsEachFailingStepWithTheCaseAndTheSeed` |
| Each bit flip must fail the verification | `SignatureCorrectnessTest::checkBitFlips`: body replaced with `Ok(())` | `correctnessTestReportsTheFirstAcceptedBitFlip`, `correctnessTestFlipsTheSignatureOnlyForAnSUFCMAScheme` |
| The index of a flip is the random `u64` modulo the number of bits | `checkBitFlips`, line 124: `%` replaced with `/` or `+` | `correctnessTestReportsTheFirstAcceptedBitFlip` and 4 more |
| The signature flips belong to the second part only | `checkBitFlips`, line 126: `==` replaced with `!=` | `correctnessTestFlipsTheSignatureOnlyForAnSUFCMAScheme` |
| SLH-DSA steps through the context lengths by a prime | `SignatureCorrectnessTest::run`, line 44: `%` replaced with `/` | `correctnessTestSignsUnderEachContextLengthAndStepsThroughThemByAPrimeForSLHDSA` |
| The hostile values of a case can be made again | `FuzzRandom::hostile`, line 42: each operator replaced or deleted | `hostileValuesStartSplitMix64AtTheSeedAndTheComplementOfTheCase` |
| A wrong length is longer for an even case and shorter for an odd case | `FuzzRandom::wrongLength`, lines 48 and 50: each operator replaced | `wrongLengthsAreLongerForEvenCasesAndShorterForOddCases` |
| The vector folder is the folder of `OQS_ORACLE_DIR`, or else of the workspace | `TestVectorFiles::folder`: body replaced | `folderIsTheVectorFolderOfTheOracleFolder` |

## Latest result for the known-answer program of the stateful schemes

The runs of 2026-10-23 on the branch `foundation/stateful-known-answers`, on the files that the branch changed, with `OQS_ORACLE_DIR` set to the oracle folder.

| Crate and files | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-algorithm-tests`: `ResponseFile.rs`, `StatefulKnownAnswerDigests.rs`, `StatefulKnownAnswerTest.rs`, `KnownAnswerText.rs`, `TestVectorFiles.rs` | 91 | 87 | 1 | 1 | 2 |
| `oqs-native-c-oracle`: `OracleStatefulScheme.rs` and `isValidStatefulSignature` | 19 | 16 | 0 | 3 | 0 |
| `oqs-native-parity`: `ParityJob.rs` | 25 | 22 | 1 | 2 | 0 |

The timeout of the test support stops the position of `ResponseFile::value`, so the reader never ends. The timeout of the parity harness inverts the selection of `ParityJob::cSnapshot`, so its test takes the snapshot of every C algorithm.

### Equivalent mutants

- `oqs-native-algorithm-tests`, `ResponseFile::value`, lines 41 and 43: `|` replaced with `^` where a digit shifts into the value. The left operand is shifted left by four bits, so its low four bits are zero, and the right operand holds only four low bits, the high half of the next byte or the digit. The two operators give the same value.

| Rule | Mutant | Killed by |
|---|---|---|
| A response value takes the last digits of its line, with zeros in front of a short one | `ResponseFile::value`: body replaced with `None` | `aValueKeepsTheLastDigitsWithZerosInFrontOfAShortOne`, `readingSkipsTheCharactersBeforeTheFirstDigitAndStopsAtTheFirstOther` and 1 more |
| The length of an LMS value counts the characters of its line | `ResponseFile::valueLength`: body replaced with `0` | `lengthsCountTheCharactersOfTheLineAndNumbersReadDecimals` |
| Each check of the C program fails the run | `StatefulKnownAnswerTest::signedText`: body replaced with `Ok(String::new())` | `signedRunFailsAtEachCheckOfTheCProgram`, `signedRunPrintsTheValuesTheSignatureAndTheCountsOfTheAdvancedKey` |
| An LMS run prints the values of the file in lower case | `StatefulKnownAnswerTest::verifiedText`: body replaced with `Ok(String::new())` | `verifiedRunOfLMSPrintsTheValuesOfTheFileInLowerCase`, `verifiedRunFailsWithoutAMessageOrAKeyAndOnAFailedVerification` |
| A response file name writes each `/` as `-` | `TestVectorFiles::responseFilePath`: body replaced | `responseFilesAreInTheLiboqsSourceWithADashForEachSlash` |
| The stateful adapter saves the advanced key before it releases the signature | `OracleStatefulScheme::sign`: body replaced with `Ok(vec![])` | `statefulAdapterSavesTheAdvancedKeyBeforeItReleasesTheSignature` |
| The C verification of a stateful signature is the verdict | `COracle::isValidStatefulSignature`: body replaced with `true` | `statefulVerificationReadsARawLMSPublicKeyAsTheCLibraryDoes` and 2 more |

## Latest result for FrodoKEM and eFrodoKEM

The runs of 2026-10-23 on the branch `family/frodokem`, with `OQS_ORACLE_DIR` set to the oracle folder. The facade ran with the tests of `oqs-native-parity` as well, because the coverage tests of the parity crate are the tests that see a wrong registry.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-frodokem` | 256 | 244 | 1 | 11 | 0 |
| `oqs-native`, with the tests of `oqs-native-parity` | 21 | 6 | 0 | 7 | 8 |
| `oqs-native-parity`, `ParityJob.rs` | 28 | 25 | 1 | 2 | 0 |

The timeout of FrodoKEM multiplies in place of an addition in the noise length of `FrodoKEM::encryption`, so the encryption asks for some thousand times more noise and the test does not end in its time. The timeout of the parity harness inverts the selection of `ParityJob::cSnapshot`, as before.

### Equivalent mutants

- `oqs-native`, `Registry.rs`: the 8 missed mutants replace the signature list or the stateful list with an empty list, a lookup in those lists with `None`, or the name of a scheme of those lists with another text. Both lists stay empty until the first signature family, so no test can see a difference yet.

The empty list of KEMs is now caught by `knownAnswersOfOneAlgorithmPassWithItsLine`, a test of `Tools/Parity`. The run of F1 had only the tests of the facade, so that mutant survived it, and its record below is corrected.

| Rule | Mutant | Killed by |
|---|---|---|
| The comparison of decapsulation gathers every difference | `ConstantTime::mismatchSelector`, line 13: the or replaced with `^` | `twoEqualDifferencesInTwoValuesStillDiffer` |
| The selection takes the key for zero and the rejection secret for minus one | `ConstantTime::select`, line 29: each operator replaced | `selectionTakesTheFirstInputForZeroAndTheSecondForMinusOne` |
| The noise sampler gives the values of the C code | `ErrorDistribution::sample`: body replaced with `()` | `samplesOfEveryValueEqualTheSamplesOfTheCCode` and 2 more |
| A reduction keeps the low bits of the modulus | `MatrixArithmetic::reduce`: the and of the mask replaced with an or | `sumsDifferencesAndReductionsKeepTheLowBitsOfTheModulus` |
| Packing writes the high bit of each value first | `Packing::pack`, line 16: `/` replaced | `packingWritesTheHighBitOfEachValueFirst` and 3 more |
| A row of the public matrix comes from its row index and the seed | `MatrixGeneration::forEachRow`: body replaced with `()` | `aSHAKERowIsTheHashOfTheRowIndexAndTheSeed`, `anAESRowIsTheEncryptionOfTheRowAndColumnBlocks` |
| The lengths are the lengths of the liboqs header | `Parameters::secretKeyLength`, line 103: `-` replaced | `lengthsAreTheLengthsOfTheLiboqsHeader` |
| A known-answer job fails on a wrong Rust digest | `ParityJob::knownAnswerJobs`: body replaced with `vec![]` | `knownAnswerJobsFollowTheDigestFilesAndTheSelection` |

## History

| Run | Code | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|---|
| 1 | First version of the tool | 758 | 492 | 111 | 19 | 136 |
| 2 | Token trees, `run` and `Report`, new tests | 564 | 512 | 14 | 33 | 5 |
| 3 | The five survivors removed or killed | 544 | 503 | 8 | 33 | 0 |
| 4 | `NamingCheck.rs` only, after the module rule change | 37 | 33 | 0 | 4 | 0 |

`Documentation/Learnings/MutationTesting.md` records what the first two runs taught.
