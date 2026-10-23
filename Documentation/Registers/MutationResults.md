# Mutation results

This register holds the result of the latest mutation run of each crate, and the named test that kills a mutant of each rule. A change that adds a rule adds its row in the same change.

## How to run

1. Run `cargo mutants --package <name> -j 4` from the repository root, with the variable `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER` of the `Mutants` workflow, which caps the memory of each test program.
2. Read the summary line. `.cargo/mutants.toml` holds the settings.
3. Give each missed mutant a test, or record here why the mutant is equivalent.
4. Run the facade as `cargo mutants --package oqs-native --test-package oqs-native,oqs-native-parity --timeout 900 -j 4`. The coverage tests of the parity crate are the tests that see a wrong registry. The baseline times only the tests of the mutated package, so the explicit timeout keeps the slower tests of the parity crate from reading as timeouts.
5. A push to a branch `mutants/<package>`, such as `mutants/oqs-native-falcon`, runs step 1 for that package in ten shards of the `Mutants` workflow, and step 4 for `mutants/oqs-native`. A branch `mutants/<package>.<label>`, such as `mutants/oqs-native-falcon.2`, runs the package again on another commit. Each shard prints its counts and its missed and timed-out mutants, and keeps its `mutants.out` folder as an artifact. The summary job prints the counts of the ten shards together, with every missed and timed-out mutant, and the table of the crate takes them from there. A crate with more than a few hundred mutants runs there.

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
| A mixed acronym such as Kem is found | `titleCaseWords`, line 32: operator replaced with `\|\|` | `titleCaseWordsSplitsMixedAcronymsAndSkipsWholeAcronyms`, `swiftCasingHasNoFinding` |
| Each part of a version is digits only | `VersionCheck::isReleaseVersion`, line 93: operator replaced with `\|\|` | `malformedOrMissingVersionIsAFinding`, `versionWithAnEmptyOrNonNumericPartIsAFinding` |
| The workspace version equals LIBOQS_VERSION | `VersionCheck::findings`, line 37: match guard replaced with `false` | `agreeingVersionsHaveNoFinding`, `crateWithItsOwnVersionIsAFinding` and 5 more |
| A semicolon is a finding in prose only | `HygieneCheck::textFindings`, line 129: operator replaced with `\|\|` | `absolutePathIsAFinding`, `cleanProseHasNoFinding` and 11 more |
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
| A scheme without context support accepts only an empty context | `Signing::isValidSignatureWithContext`: `&&` replaced with `\|\|` | `verificationWithContextAcceptsOnlyAnEmptyContext` |

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
| A changed input changes exactly one bit | `VariationGenerator::withChangedBit`: `^=` replaced with `\|=` or `&=`, `/` replaced with `%` | `aChangedBitChangesExactlyOneBitAndReachesEveryBit` |
| A non-empty context always uses the context form | `VariationGenerator::usesContextForm`: `\|\|` replaced with `&&`, `>` replaced | `aNonEmptyContextAlwaysUsesTheContextFormAndAnEmptyOneUsesBoth` |
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

## Latest result for the linked oracle folder

The run of 2026-10-23 on the branch `foundation/crate-builds`, of the functions that changed: `resolvedPath` and `OracleBuild::steps`.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `xtask`, `resolvedPath` and `OracleBuild::steps` | 6 | 4 | 0 | 2 | 0 |

| Rule | Mutant | Killed by |
|---|---|---|
| The disk adapter resolves the links of a path and keeps the end that does not exist yet | `DiskFileSystem::resolvedPath`: body replaced with `Default::default()` | `resolvedPathFollowsALinkAndKeepsTheEndThatDoesNotExistYet` |
| The oracle build gives CMake the folders with every link resolved | Run by hand: `OracleBuild::steps` with the folders not resolved | `linkedOracleFolderIsClonedAndBuiltAtTheFolderThatTheLinkNames` |

## Latest result for the blocks of the parity run

The run of 2026-10-23 on the branch `foundation/parity-blocks`, of the functions that changed: `ParitySettings::caseBlocks`, `ParityOptions::parse`, `ParityJob::parityJobs`, `ParityJob::checkBlock` and `run` of the program, with the explicit timeout of the parity crate.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-parity`, the functions of the blocks | 26 | 17 | 0 | 9 | 0 |

| Rule | Mutant | Killed by |
|---|---|---|
| The blocks of an algorithm cover its cases in order, and the last block takes the rest | `ParitySettings::caseBlocks`: `+` replaced with `-` or `*` | `caseBlocksSplitTheVariationsInOrderAndTheLastBlockTakesTheRest` |
| Only the first block checks the base case | `ParityJob::checkBlock`: `==` replaced with `!=` | `parityJobsSplitTheVariationsOfEachAlgorithmIntoBlocksThatTheShardsSplit` |
| A block size is a count above zero | `ParityOptions::parse`: `>` replaced | `wrongOptionsAreErrorsThatNameTheOption` |
| A whole run keeps the summary of one job for each algorithm | `parityJobs`: the guard of the whole range replaced with `true` or `false` | `parityJobsSplitTheVariationsOfEachAlgorithmIntoBlocksThatTheShardsSplit`, `parityJobsReportExactlyTheBrokenAlgorithms` |

## Latest result for HQC

The runs of 2026-10-23 on the branch `family/hqc`, with `OQS_ORACLE_DIR` set to the oracle folder. The second run took the 38 missed and timed-out mutants of the first run again with `--iterate`, after the new tests, with a timeout of 600 seconds. The facade ran with the tests of `oqs-native-parity` as well.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-hqc`, first run | 864 | 793 | 9 | 33 | 29 |
| `oqs-native-hqc`, second run of the 38 | 38 | 13 | 7 | 0 | 18 |
| `oqs-native-hqc`, both runs | 864 | 806 | 7 | 33 | 18 |
| `oqs-native`, with the tests of `oqs-native-parity` | 21 | 6 | 0 | 7 | 8 |

The 18 missed mutants of the second run are the equivalent mutants below, and the 7 timeouts are the endless loops of the rejection sampler. The 8 missed mutants of the facade replace the signature list or the stateful list, which stay empty until the first signature family, as in the FrodoKEM run.

Seven of the nine timeouts stop the rejection loop of key generation, `rejectionSupport`: the deleted `!` of line 154, `barrettReduced` replaced with 0 or with 1, and four mutants of `Parameters::rejectionThreshold`, which replace the body with 0 or with 1, `*` with `/`, or `<<` with `>>`. With each of them no candidate gives a new position, so the loop never ends. The mutant of `rejectionThreshold` that replaces `/` with `%` ends. Its threshold is above every candidate, `derivedValuesAreTheValuesOfParametersHeader` fails at once, and `barrettReductionIsTheRemainderForEveryCandidateBelowTheThreshold` then reduces about 1.7 billion candidates in place of 50 million. The ninth timeout, `ReedSolomon::errorLocator` line 96, is an equivalent mutant. Every test that ended passed, and the suite did not end in 36 seconds on a loaded machine. It is in the list below.

The decoder tests of the first run decoded words with at most `delta` errors. The new tests compare the decoders and the FFT with the internal C functions of liboqs 0.16.0, also for words that the code cannot correct, for ties of the Reed-Muller peak and for any values. They kill 12 of the 29 missed mutants. The other 17 are equivalent.

### Equivalent mutants

- `AdditiveFFT.rs`, `errorPositions`, line 68: `^=` replaced with `|=`. Line 67 sets every entry to zero, and line 68 is the first write of entry 0. An or and an exclusive or with zero give the same value.
- `AdditiveFFT.rs`, `errorPositions`, lines 72 and 74: `^=` replaced with `|=`. For the indices from 1 to 127, the points `sums[index]` and `sums[index] ^ 1` are the 254 field elements other than 0 and 1, each once. `evaluationsAreTheValuesAtEveryFieldElement` checks that the points of the FFT are every element once. The logarithm takes these points to 254 different entries from 1 to 254, so each entry is written once, after line 67 set it to zero.
- `AdditiveFFT.rs`, `errorPositions`, line 73: `^` replaced with `|` in `sums[index] ^ 1`. The basis of line 17 holds 128, 64, 32, 16, 8, 4 and 2, so bit 0 of each subset sum is zero, and the two operators give the same value.
- `AdditiveFFT.rs`, `radix`, lines 102, 120 and 130: the match arm of 16, 8 or 4 coefficients deleted. That size then takes the general conversion of line 140, `radix_big` of the C code. The split `f(x) = f0(x^2 + x) + x f1(x^2 + x)`, with `f0` and `f1` of half the size of `f`, has one solution, because `f0(x^2 + x)` has an even degree and `x f1(x^2 + x)` has an odd degree. Both conversions only add coefficients. `radixConversionIsTheSplitOfItsDefinitionAtEverySize` checks the case and the general conversion of each size against the definition for each polynomial with a single coefficient 1, so the two give the same split for every polynomial. The test passes with each of the three mutants.
- `AdditiveFFT.rs`, `recursiveEvaluations`, line 225: `-` replaced with `/` in `basisLength - 1`. The loop of line 226 then also writes the entry `basisLength - 1` of `gammas` and `deltas` when that entry is below 6. Lines 231 and 240 read only the first `basisLength - 1` entries, and the two arrays belong to the call.
- `BinaryVector.rs`, `supportWithoutRejection`, line 177: `|` replaced with `^`. The fold tells whether a later position equals the position at `index`. The later positions are distinct, so at most one term is 1, and the two operators give the same value. Each position is at least its own index: line 171 adds a number of at least 0 to the index, and line 179 sets a position to its own index. The loop goes down from the second last index. Before the step of an index, the positions after it are distinct. The step keeps the position when it equals none of them, or sets it to the index, which is below each of them. So the positions from the index on are distinct after the step. The proof needs `n` below `2^32`, so that the cast of line 171 keeps the number, and `n` is at most 57637.
- `CarrylessMultiplication.rs`, `karatsubaProduct`, lines 46, 47 and 48: `*` replaced with `+` in `2 * count`. The split happens only for more than 16 words (line 40). Then the mutant gives the low, high or middle product `count + 2` words in place of `2 count`, which still holds the `2 lowCount` or `2 highCount` words of that product. The regions stay apart, and only the scratch of the next level grows. The lines after the split read the words of each product only after the product wrote them, and each product first sets its whole result to zero (lines 79 and 101). So the result depends only on the factors.
- `CarrylessMultiplication.rs`, `karatsubaProduct`, lines 81 and 87: `^=` replaced with `|=`. Line 79 sets the result to zero. The loop of line 80 writes the words below `2 lowCount`, and the loop of line 83 writes the words from `2 lowCount` to `2 count`, each word once. So each word is zero before its write.
- `ReedMuller.rs`, `peakPosition`, line 96: `>` replaced with `>=` in `value > 0`. The mask changes only for the value 0, where `value` and `-value` are both 0, so line 97 gives the absolute value 0 either way.
- `ReedMuller.rs`, `peakPosition`, line 103: `+` replaced with `-`. The peak position is from 0 to 127, and the cast to `u8` keeps the number modulo 256, where `p + 128` and `p - 128` are equal.
- `ReedSolomon.rs`, `errorLocator`, line 96: `+` replaced with `*` in the size of `savedSigma`. The array then has 29 entries in place of 30. Lines 108 and 135 use only the first `delta` entries, and `delta` is at most 29. The first run reported this mutant as a timeout.
- `ReedSolomon.rs`, `errorLocator`, line 111: `+` replaced with `*` in `step + 1`. Step `mu` then adds the shifted polynomial and sums the discrepancy up to the coefficient `mu`, in place of `mu + 1`. Let `mu0` be the first step whose discrepancy is not zero, and `a` that discrepancy, `S_(mu0 + 1)`. Before `mu0` the shifted polynomial is `x^(mu + 1)`, but its factor is zero. After `mu0` the shifted polynomial is `x^(mu - rho)` times the locator before step `rho`, whose degree is at most `rho`, and after a step `mu` above `mu0` the degree of the locator is at most `mu`. So each coefficient `mu + 1` that the mutant leaves out is zero, except the term `a x^(mu0 + 1)` of step `mu0` and the discrepancy term `sigma_1 S_1` after step 0. For `mu0` of `delta` or more, both forms stop at `delta`. For `mu0 = 0`, the degree cannot grow at step 1, and step 1 gives the same `sigma_1` in both forms. For `mu0` from 1 to `delta - 1`, `S_1` is zero. The degree is `mu0 + 1` after step `mu0`, and a later step `mu` up to `2 mu0 + 1` has the candidate degree `mu - mu0`, so the degree does not grow and the shifted polynomial is `x^(mu - mu0)`. The discrepancies of the two forms agree up to step `2 mu0`. At step `2 mu0 + 1` the discrepancy of the mutant differs by `a^2`, so that step adds `a x^(mu0 + 1)` to the locator of the mutant, and from there on the two forms are the same. `decodingOfWordsWhoseFirstSyndromesAreZeroGivesTheMessageOfTheCFunction` feeds words whose discrepancies are zero before each step `m` from 1 to `2 delta`, and it passes with the mutant.

| Rule | Mutant | Killed by |
|---|---|---|
| The Reed-Solomon decoder gives the message of the C code for a word that it cannot correct | `ReedSolomon::errorLocator`, line 130: `^=` replaced with `\|=` or `&=`, and `^` replaced with `&`, line 137: `&` replaced with `\|` or `^` | `decodingOfEveryWeightGivesTheMessageOfTheCFunction`, `decodingOfWordsWhoseFirstSyndromesAreZeroGivesTheMessageOfTheCFunction`, `decodingOfAnyWordGivesTheMessageOfTheCFunction` |
| The Reed-Muller peak is the first largest absolute value | `ReedMuller::peakPosition`, line 101: `^=` replaced with `\|=`, and `^` replaced with `\|` | `peakFollowsEachLargerAbsoluteValueInTurn`, `decodingOfManyErrorsAndTiesGivesTheBytesOfTheCFunction`, `decodingOfAnyWordGivesTheMessageOfTheCFunction` |
| The FFT gives the values of the C code also for coefficients at and above the count | `AdditiveFFT::evaluations`, line 48, and `recursiveEvaluations`, line 255: `/` replaced with `*` | `evaluationsGiveTheValuesOfTheCFunctionForEveryCount` |
| The error positions take the zero tests of the C code for any values | `AdditiveFFT::errorPositions`, line 68: `^=` replaced with `&=`, line 69: `^=` replaced with `\|=` | `errorPositionsGiveThePositionsOfTheCFunctionForAnyValues` |
| The radix conversion of two coefficients is the split of its definition | `radix`, line 136: match arm 1 deleted | `radixConversionIsTheSplitOfItsDefinitionAtEverySize` |

## Latest result for BIKE

The runs of 2026-10-23 on the branch `family/bike`, with `OQS_ORACLE_DIR` set to the oracle folder. A restart of the machine stopped the run of the crate after 238 mutants, and the run went on with `--iterate`, which skips the mutants that the first part caught or found unviable. The facade ran with the tests of `oqs-native-parity` as well.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-bike` | 539 | 475 | 0 | 59 | 5, then 4 |
| `oqs-native`, with the tests of `oqs-native-parity` | 21 | 6 | 0 | 7 | 8 |
| `oqs-native-bike`, `BIKE::decapsulation` after the new test | 16 | 15 | 0 | 1 | 0 |

The missed mutant of the comparison of decapsulation is a test gap, and `aDecodedErrorThatDiffersOnlyInTheTopBitOfTwoWordsIsRejected` now kills it. The other four are equivalent.

### Equivalent mutants

- `oqs-native-bike`, `Sampler::positions`, line 38: `+` replaced with `*` in `positions[index + 1..]`. The slice then starts at `index`, whose entry is still 0 when the candidate is compared. A candidate is at least `index`, so it equals 0 only when `index` is 0, and then the candidate and the index are both 0, so the result is the same.
- `oqs-native-bike`, `Sampler::positions`, line 40: `|` replaced with `^` in the fold that finds a repeated value. The later positions are different from each other, so a candidate equals at most one of them, and the or and the exclusive or of the matches agree.
- `oqs-native-bike`, `Decoder::thresholdOfWeight`, line 169: `*` replaced with `+` or with `/` in `high * factorLow`. A syndrome weight is at most r, so `high` is at most 4 in the three sets, and the mutant changes the high word of the product by at most 5 before the shift by 26. `theHighWordOfTheCCodeGivesTheThresholdOfTheExactHighWordForEveryWeight` checks every weight from 0 to r of each set, and both mutants give the threshold of the C code for each of them.
- `oqs-native`, `Registry.rs`: the 8 missed mutants replace the signature list or the stateful list with an empty list, a lookup in those lists with `None`, or the name of a scheme of those lists with another text. Both lists stay empty until the first signature family, as in the FrodoKEM run.

| Rule | Mutant | Killed by |
|---|---|---|
| The comparison of decapsulation counts a difference in the top bit of a word | `BIKE::decapsulation`, line 144: `\|` replaced with `^` | `aDecodedErrorThatDiffersOnlyInTheTopBitOfTwoWordsIsRejected` |
| The comparison of decapsulation gathers every difference | `BIKE::decapsulation`, line 141: `\|` replaced with `^` | `aDecodedErrorThatDiffersInTheSameBitOfTwoWordsIsRejected` |
| The Karatsuba product is the product of the definition for every split | `karatsubaProduct`: each operator replaced | `karatsubaProductEqualsTheSchoolbookProductForEverySplit` |
| The power of a polynomial is the power of the C code | `PolynomialRing::power`: `<=` replaced with `>` | `permutedPowerGivesThePowerOfTheCCodeAndOfRepeatedSquaring` |
| The weight of a syndrome counts only the coefficients below r | `Syndrome::weight`: each operator replaced | `weightCountsTheCoefficientsBelowR` |
| The sampler gives the positions of the C sampler | `Sampler::positions`: the scaling and the repeat rule replaced | `decoderGivesTheErrorOfTheCDecoderForACiphertextBeyondItsReach`, `decoderGivesTheErrorsOfTheCDecoderForHostileInputs` |

## Latest result for ML-DSA

The first runs of 2026-10-23 on the branch `family/ml-dsa`, with `OQS_ORACLE_DIR` set to the oracle folder. The load average of the machine was 15 to 28, and the disk filled up before the run of the crate ended. The runs of the shared crates took the files that the port added or changed, and the facade ran with the tests of `oqs-native-parity` as well. The second runs took the crate, the facade and the whole parity crate in the ten shards of the `Mutants` workflow of CI, on the commit of the new tests below: [the crate](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40028751030), [the facade](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40028751411) and [the parity crate](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40028751618).

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-ml-dsa`, first run | 624 | 547 | 21 | 43 | 11 |
| `oqs-native-ml-dsa`, second run in CI | 626 | 558 | 12 | 40 | 16 |
| `oqs-native-sha2`, `SHA224.rs`, `SHA256.rs`, `SHA512224.rs` and `SHA512256.rs` | 69 | 68 | 1 | 0 | 0 |
| `oqs-native-sha3`, `SHA3224.rs` | 5 | 5 | 0 | 0 | 0 |
| `oqs-native-algorithm-tests`, `VectorRandom.rs` | 7 | 7 | 0 | 0 | 0 |
| `oqs-native-parity`, `SignatureParity.rs` | 11 | 9 | 0 | 1 | 1 |
| `oqs-native-parity`, second run of the whole crate in CI | 207 | 189 | 1 | 16 | 1 |
| `oqs-native`, with the tests of `oqs-native-parity` | 21 | 9 | 0 | 7 | 5 |
| `oqs-native`, with the tests of `oqs-native-parity`, second run in CI | 21 | 10 | 0 | 7 | 4 |

The full disk spoiled the results of five mutants of `decomposed` in `Polynomial.rs`: `*` replaced with `+` or with `/` at both places of line 117, and `-` replaced with `+` in `low - modulus`, line 118. Two of them never ran, so the counts of the table add up to 622. Applied by hand, each mutant of line 117 fails 26 tests and the mutant of line 118 fails 17, among them `decompositionAndHintsFollowFIPS204ForEveryValue` and the known answers of every count of each set.

Eleven of the 21 timeouts are endless loops of the samplers. Applied by hand, each kept the unit tests that sample a polynomial running for 300 seconds, where the whole unit test binary ends in under a second.

- `sampledUniform`, line 390, and `sampledShort`, line 420: `<` replaced with `<=`. The loop goes on at 256 coefficients and takes no candidate.
- `sampledUniform`, line 393, and `sampledShort`, line 424: `==` replaced with `!=`. The inner loop stops before its first candidate.
- `sampledUniform`, line 403, and `sampledShort`, line 429: `+=` replaced with `*=`. The count stays at 0.
- `sampledUniform`, line 400: `&` replaced with `|`. Each candidate is at least `2^23 - 1`, which is above q.
- `boundedCoefficient`, line 441: the body replaced with `None`, and line 444: `<` replaced with `>`. No half byte gives a coefficient for eta 2, so `sampledShort` never ends. `boundedCoefficientsAreTheCoeffFromHalfByteOfFIPS204` fails at once.
- `sampledInBall`, line 483: `+=` replaced with `*=`. The position stays at byte 8 of the stream, and the loop never ends when that byte is above `256 - tau`.
- `sampledInBall`, line 484: `<=` replaced with `>`. At the index 255 no byte is above the index.

One more timeout ends with a failed test, but only after hours. In `sampledUniform`, line 401, `<` replaced with `==` lets only a candidate of exactly q count, and such a candidate comes once in 2^23 candidates. One polynomial then takes about 2^31 candidates, about 30 seconds in the test build. `samplesStayInTheirRangesAndDependOnTheirSeeds` fails after one such polynomial, because its coefficients are q. `keyPairsHaveTheLayoutOfFIPS204` samples 204 of them, so the unit tests end after more than an hour.

The other nine timeouts are equivalent mutants. Applied by hand, each passed every test of the crate. A caught mutant usually stops the suite at the first test binary that fails, and an equivalent mutant runs every binary, so on the loaded machine the equivalent mutants passed the time limit. They are in the list below.

Of the 11 missed mutants, four are test gaps. `eachConstantIsTheConstantOfFIPS204AndOfTheHeaderOfMLDSANative` and `uniformSamplingSkipsACandidateOfQAndGivesThePolynomialOfTheCFunction` kill them. The other seven are equivalent.

The second run of the crate confirms the first. Its 16 missed mutants are the 16 equivalent mutants below, among them the nine that the first run reported as timeouts, and its 12 timeouts are the 11 endless loops and the mutant of line 401 above.

The timeout of `oqs-native-sha2` replaces the body of `SHA256::withInitialState` with `Default::default()`. `default` calls `new`, which calls `withInitialState` again, so the calls never end. The missed mutant of `SignatureParity.rs` makes `checkEveryCase` return `Ok(())`. The parity jobs check blocks with `checkCase`, so only tests that expect success called `checkEveryCase` for a scheme, and `aSignatureDefectInTheBaseCaseNamesTheSnapshotField` now runs it on a broken scheme. The missed mutant and the timeout of the second run of the parity crate are the coin of `VariationGenerator::usesContextForm` and the selection of `ParityJob::cSnapshot`, which the sections of the parity harness and of the stateful known answers record.

The first run of the facade missed the mutant that replaces `Registry::signatureSchemes` with an empty list. The coverage test looked up each C name with `Registry::signatureScheme`, and the parity program checks the schemes of the list, so an empty list checked no scheme and every test passed. `everyCAlgorithmIsRegisteredOrListedAsNotYetPorted` now reads the three lists, and the second run caught the mutant. The other four missed mutants replace the stateful list with an empty list, a lookup in it with `None`, or the name of a stateful scheme with another text. The stateful list stays empty until the first stateful family, as in the FrodoKEM run.

### Equivalent mutants

- `Parameters.rs`, the gamma2 of `mldsa44`, `mldsa65` and `mldsa87` at the lines 161, 175 and 189, which were the lines 154, 168 and 182 in the first run, `Parameters::commitmentBits`, line 54, and `Polynomial.rs`, `isNarrowRounding`, line 102: `-` replaced with `+` or with `/` in `(q - 1) / 88` and `(q - 1) / 32`. These are ten mutants, five missed and five timeouts. q - 1 = 8380416 is 88 times 95232 and 32 times 261888. q + 1 and q leave the remainders 2 and 1, so the quotients stay 95232 and 261888. The constant does not change, so the program does not change.
- `Polynomial.rs`, `rootPowers`, line 47, and `decomposed`, line 118: `-` replaced with `/` in `(q - 1) / 2`. q is odd, so `q / 2` is 4190208 as well.
- `Polynomial.rs`, `rootPowers`, line 47: `>` replaced with `>=`, and `-` replaced with `+` in `(modulusWide - 1) / 2`. The first mutant changes the centering only for an entry of 4190208 before the centering, and the second only for an entry of 4190209. No entry from 1 to 255 has one of these values. `twiddleFactorsAreTheTableOfMLDSANative` checks every entry against its definition and passes with both mutants, and `zetas` is a constant, so the program does not change.
- `Polynomial.rs`, `rootPowers`, line 30: `%` replaced with `+` in `(1i64 << 32) % modulusWide`. The start value is then `2^32 + q`, which is congruent to `2^32 mod q`. Each entry from 1 to 255 multiplies the start value by 1753 at least once, because BitRev8 of its index is at least 1, and takes the product modulo q. The product stays below 2^43, so it does not overflow, and each remainder is the same. `twiddleFactorsAreTheTableOfMLDSANative` passes with the mutant.
- `Polynomial.rs`, `decomposed`, line 118: `-` replaced with `+` in `(modulus - 1) / 2 - low`. The selection then subtracts q only above 4190209 in place of above 4190208, so the output changes only for a low part of exactly 4190209. For a standard representative, line 117 gives a low part from `-gamma2 + 1` to gamma2 when the high part does not wrap, and the value itself, from `q - gamma2` to `q - 1`, when the high part wraps to 0. gamma2 is at most 261888, so no low part is 4190209. `decompositionAndHintsFollowFIPS204ForEveryValue` checks every value from 0 to `q - 1` for both values of gamma2 and passes with the mutant. Only standard representatives reach `decomposed`. In `InternalAlgorithms.rs`, `attemptedSignature` and `isValidSignature` give `Polynomial::decomposed` and `Polynomial::hintedHigh` the output of `nonNegative`, which maps each coefficient of `inverseTransform`, below q in absolute value, into the range from 0 to `q - 1`.

| Rule | Mutant | Killed by |
|---|---|---|
| A signature makes the attempts of mldsa-native before it fails | `InternalAlgorithms::signature`, line 210 of the first run, now `Parameters::signingAttemptCount`: `-` replaced with `+` or `/`, `/` replaced with `*` | `eachConstantIsTheConstantOfFIPS204AndOfTheHeaderOfMLDSANative` |
| The uniform sampler refuses a candidate of q | `Polynomial::sampledUniform`, line 401: `<` replaced with `<=` | `uniformSamplingSkipsACandidateOfQAndGivesThePolynomialOfTheCFunction` |
| Decompose gives the high and the low part of FIPS 204 | `decomposed`, line 117: `*` replaced with `+` or `/`, line 118: `-` replaced with `+` in `low - modulus` | `decompositionAndHintsFollowFIPS204ForEveryValue` and the known answers of every count of each set |
| The parity program checks the signature schemes of the registry list | `Registry::signatureSchemes`: the list replaced with an empty list | `everyCAlgorithmIsRegisteredOrListedAsNotYetPorted` |
| The check of every case of a scheme reports a broken scheme | `SignatureParity::checkEveryCase`: the body replaced with `Ok(())` | `aSignatureDefectInTheBaseCaseNamesTheSnapshotField` |

## Latest result for Falcon

The run of 2026-10-23 on the branch `family/falcon`, in the ten shards of the `Mutants` workflow of CI, with `OQS_ORACLE_DIR` set to the oracle folder. The unmutated suite took 3.6 seconds, so the time limit of a mutant was about 18 seconds. The line numbers below are those of the code of the run. The owner runs the crate again after the changes of this section and adds the counts of that run.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-falcon`, ten shards | 2486 | 1202 | 1134 | 45 | 105 |

1082 of the 1134 timeouts had a failed test before the time limit. The other 52 had no failed test at the limit. Each of them ran by hand as the unit test binary of the code of the run with its diff applied, with one thread for each test, for 300 seconds. The last 40 ran with the address space capped at 6 GiB. The first 12 ran before the cap, and their memory did not grow. None of the 52 passes.

Two end with a failed test:

- `BigInteger::bezout`, line 348: `-=` replaced with `+=`. The count of steps only grows, and the overflow check of the test build stops it. Seven tests fail, among them `bezoutGivesTheCoefficientsOfTwoCoprimeIntegers`.
- `KeyGenerator::gaussianPolynomial`, line 187: `!` deleted. `eachCandidateIsRefusedOrAcceptedAsTheCCodeDecides` fails.

The other 50 did not end in 300 seconds. Each leaves the tests of one loop unfinished, and no test fails:

- The signer draws a new vector without end, because no vector is short. `complexQuotient`, line 36: `*` replaced with `/`. `Signer::sampleTree`, line 211: `*` replaced with `+` or with `/`. `Signer::loadBasis`, line 95: `*` replaced with `+`, and line 98: `*` replaced with `+` or with `/`. The quotient, the leaf of the tree or the slots of the basis are wrong. `decompositionGivesTheBitsOfPolyLDLFFTAlsoForAComplexG00` now fails at once for the mutant of line 36.
- The trial of the sampler accepts no candidate, or almost none, so a test that samples a few hundred values takes hours or more. `GaussianSampler::isBernoulliExponentialTrue` replaced with `false`. Line 111: `&` replaced with `^` or with `|`, which makes the shift 63, so the threshold is 0 or 1 and a candidate passes only when eight random bytes are zero. Line 122: `>>` replaced with `<<`, which makes the first seven bytes of the threshold zero. `GaussianSampler::sample`, line 63: `-` replaced with `+`, which makes the fraction of a large center about twice the center. `halfGaussian`, line 92: `|` replaced with `&`, which makes the top limb of the random value zero, so the half-Gaussian value is 10 or more for each draw.
- `KeyGenerator::gaussianPolynomial` never returns. `KeyGenerator::nextWord` replaced with 0 or with 1, `gaussianValue` replaced with -1, 0 or 1, line 159: `<<` replaced with `>>`, which draws no value below degree 1024, line 170: `|=` replaced with `&=`, `&` replaced with `^` or with `|` at either place, and `^` replaced with `&` or with `|`, and line 187: `-` deleted, which keeps only the value 127, give every coefficient of a degree below 1024 the same parity. N is even, so the sum of N such coefficients is even, and no last coefficient makes it odd. Line 163: `>>` replaced with `<<`, line 164: `&` replaced with `^` or with `|`, `!` deleted and `<<` replaced with `>>`, and line 173: `^` replaced with `&` or with `|`, give most values the same sign. At degree 2 a coefficient is the sum of 512 values, and the sum is then never within `-127..=127`. A simulation of 400 coefficients for each of these mutants found none in the range.
- The key generator refuses every candidate. `KeyGenerator::isOrthogonalizedNormBelowBound` replaced with `false`. Line 167: `&` replaced with `|`, and line 169: `^` replaced with `&`, make the variance of a value 13 to 19 times smaller than with the code of the run, so the squared norm of the orthogonalized vector is above 100000, against the bound 16822. A simulation of 20 pairs at degrees 32 and 512 found none below 150000. Line 171: `|=` replaced with `&=` makes the variance about 100 times larger, so a pair either does not fit the encoding or has a squared norm far above 16823. Line 82: `!` deleted refuses each pair that fits the encoding, and up to degree 32 every pair fits. Line 93: `<<` replaced with `>>` makes the limit of `F` equal to -1, so every `F` is out of range.
- A transform loop never ends. `HashToPoint::point`, line 64, `ModularPolynomial::transform`, line 104, and `PrimeModulus::transform`, line 189: the doubling of the step replaced with a halving. The step becomes 0, and the loop condition stays true. `PrimeModulus::powerOfR`, line 115: `+=` replaced with `*=`. The bit index stays 0.
- The reduction loop of the solver never ends. `NTRUSolver::reduce`, line 577: `<` replaced with `==` or with `>`, and line 578: `-` deleted. A negative `dc` stays negative, and `dc >>= 1` stops at -1. Line 644: `-` replaced with `+`. The scale grows, so `scaleOfK <= 0` never holds before the overflow check, about 86 million steps later.
- `FloatingPoint::sub`, line 346: `+` replaced with `-`. The subtraction calls itself through `self - -other`, so it never returns.
- `Falcon::encodedValue`, line 109: `!` deleted, or the match guard replaced with `false`. A compressed set then draws a new vector without end when no vector fits, which `aCompressedSetFailsWhenTheVectorDoesNotFitAndAPaddedSetSignsAgain` gives.

Of the 105 missed mutants, 36 are test gaps, and the new tests kill them. 22 join disjoint fields with `|`, which now are `+`. Each new mutant of the 22 sums, `-` and `*` at each place, fails a test, except `-` of `reversals` in `PrimeModulus.rs`, which does not build. 3 are in copies of the saturated norm in `KeyGenerator::isNormBelowBound` and `Signer::shortVector`, which now call `SignatureNorm::saturatedSquaredNorm`, the one owner of the decision. Each mutant of that function fails `saturatedSquaredNormIsTheSumBelow2To31AndElseSaturates`. 33 are equivalent, and 11 are open.

### Equivalent mutants

- `BigInteger.rs`, `bezout`, line 285: `+` replaced with `*` in `62 * length + 30`. The loop then makes more reductions. The C code states that each reduction removes at least 30 bits from the total length, so the count of `62 length + 30` bits in steps of 30 reaches the GCD. A hill climb over pairs of 2 to 12 words never needed more than 2 length of the 2 length + 1 reductions. After a reaches 1, it is odd, so a step never halves it. A subtraction of b from a needs an odd b whose top words are below those of a, and no b of at least 1 has such top words. So pa is then `2^31` and pb is 0, and a, u and v stay the same. For a GCD other than 1, or an even x or y, the result is false in both forms. The proof rests on the bound of the C code.
- `BigInteger.rs`, `bezout`, lines 294 and 296: `^=` replaced with `|=`, and `^` replaced with `|` in `(a0 ^ aw)` and `(b0 ^ bw)`. a0 and b0 start at 0. `c0` is all ones exactly for the indices from the top down to the highest index where a or b is not zero, and above that index the words are 0. So a0 is still 0 when it takes the word of that index. An or and an exclusive or with 0 give the same value, and below that index `c0` is 0, so a0 keeps its value in both forms. The same holds for b0.
- `BigInteger.rs`, `bezout`, line 314: `^` replaced with `|` in `difference ^ (...)`, and `^` replaced with `&` or with `|` in `aHigh ^ bHigh` and in `aHigh ^ difference`. aHigh and bHigh start below `2^62`. Line 321 subtracts bHigh from aHigh only when aHigh is above, line 325 subtracts aHigh from bHigh only when it is not above, and the shifts of lines 332 and 336 make them smaller, so both stay below `2^62`, and the comparison of line 314 is the comparison of the two values. Bit 63 of `aHigh ^ bHigh`, of `aHigh & bHigh` and of `aHigh | bHigh` is then 0, so the term in parentheses has bit 63 at 0 in each form, and bit 63 of the result is bit 63 of `difference`.
- `BigInteger.rs`, `bezout`, line 355: `|` replaced with `^` in `nonOne | nonOne.wrapping_neg()`. Each reduction ends with `negate`, which masks every word of a to 31 bits, so `nonOne` is below `2^31`. For a `nonOne` that is not zero, bit 31 of its negation is 1 and its own bit 31 is 0, so both forms give bit 31 as 1. For 0 both give 0.
- `BigInteger.rs`, `normalizeAroundZero`, line 86: `|` replaced with `^`. The half word and the word of x are below `2^31`, so the difference lies between `-2^31` and `2^31` and is never `2^31` modulo `2^32`. The first term is 1 only for a positive difference and the second term is all ones only for a negative one, so they are never both set.
- `Encoding.rs`, `modularEncoded`, line 72: `*` replaced with `+` or with `/`. The value is only the capacity of the vector of the writer, and the bytes are the same.
- `Encoding.rs`, `modularDecoded`, line 83: `*` replaced with `+` or with `/`. The length only serves the early check. For a shorter input, the loop of line 91 runs out of bytes before it has N values, and `bytes.next()?` returns `None`, the result of the check.
- `Falcon.rs`, `generateKeyPair`, line 134: `-` replaced with `+`. Each trimmed encoding has the fixed length of N times its bits, and the room before each one is at least that length, so the room never refuses an encoding in either form.
- `Falcon.rs`, `isValidSignature`, line 193: `<` replaced with `<=`. The mutant also refuses a signature of exactly 41 bytes. The code of the run refuses it at line 204, where the value after the nonce is empty.
- `FloatingPoint.rs`, `scaled`, line 78: `|` replaced with `^`. For an absolute value below `2^63`, bit 63 of the value is 0, so both forms give bit 63 of the negation. Only `-2^63` has an absolute value of `2^63`, and no caller gives it. The callers of `of` outside the tests convert an `i8`, `u16` or `i32`, except `NTRUSolver::depthOne`, line 729, which converts a value that lines 724 and 725 keep strictly between `-2^63` and `2^63` as a binary64 value, so at least `-2^63 + 1024`. `scaled` has no other caller outside the tests.
- `FloatingPoint.rs`, `squareRoot`, line 198: `|` replaced with `^`. Before the step of each bit b, the loop of lines 187 to 195 keeps the remainder equal to `(X - Q^2) / b` for `X = M 2^53`, where M is the mantissa below `2^55` and Q the root so far. After the step of b = 1 and its shift, it is `2 (X - Q^2)`. Q is the integer square root of X, so this is at most `4 Q`, below `2^56`. So bit 63 of the remainder is 0, and both forms give bit 63 of its negation.
- `FloatingPoint.rs`, `isLessThan`, line 214: `^` replaced with `|` in `isBelow ^ isAbove`. The term counts only when both values are negative. Then line 210 keeps `right`, the difference of two negative 64-bit values does not overflow, and `left - right` and `right - left` are never both negative. So `isBelow` and `isAbove` are never both 1.
- `FloatingPoint.rs`, `div`, line 422: `|` replaced with `^`. The loop keeps `xMantissa` below twice `yMantissa`: a subtraction leaves it below `yMantissa`, and the shift doubles it. `yMantissa` is below `2^53`, so the remainder is below `2^54` and its bit 63 is 0.
- `GaussianSampler.rs`, `isBernoulliExponentialTrue`, line 111: `^=` replaced with `|=`. For a shift of 63 or less the mask is 0, and both forms keep the shift. For a larger shift, the code of the run gives 63, and the mutant gives the shift with its low six bits set. `wrapping_shr` on line 115, the only use of the shift, shifts by the value modulo 64, which is 63 in both forms.
- `HashToPoint.rs`, `point`, line 61: `^` replaced with `|` in `sourceValue ^ swapped`. Without a swap, `swapped` is 0. With a swap, the target slot holds the refused marker `0xFFFF`, and `s | (s ^ 0xFFFF)` is `0xFFFF` for every 16-bit s. The target is always refused: let `J_r = p_r - r` be the jump of the accepted value of rank r at position `p_r`. The jumps do not decrease with the rank. Before the pass of the shift `2^t`, the value of rank r is at `r + 2^t floor(J_r / 2^t)`, and `jump` on line 49 is that position minus r. When it moves by `2^t`, the value of rank `r - 1` has already had its pass, and it lies at `r - 1 + 2^(t+1) floor(J_(r-1) / 2^(t+1))`. Bit t of `J_r` is 1, so that position is below the target `r + 2^t (floor(J_r / 2^t) - 1)`. The values of a lower rank lie below it, and the values of a higher rank lie above the position of r. So no accepted value is in the target slot.
- `ModularPolynomial.rs`, `inverseTransform`, line 114, and `PrimeModulus.rs`, `inverseTransform`, line 207: `>` replaced with `>=`. The extra pass has `hm = 0`, so its loop body never runs. It changes only `t` and `m`, which no line reads after the loop.
- `NTRUSolver.rs`, `halvedPair`, lines 174 and 198: `*` replaced with `+` in the split at `hn * tlen`. These lines run only when `isOutTransform` is false. Only `deepest`, line 242, calls `pairAtDepth` with false, and with the depth equal to the logn. `pairAtDepth` then passes false only to its last call of `halvedPair`, at line 223 or 229, with the logn 1. There `hn` is 1, and the inverse transforms of the split have the logn 0, which return at once.
- `NTRUSolver.rs`, `reduce`, line 577: `<` replaced with `<=`. For `dc = 0` the mutant takes the other branch, but the loop of line 584 does not run, so the scale is 1 in both forms.
- `NTRUSolver.rs`, `reduce`, line 634: `<` replaced with `<=`. At the first step the new maximum is `31 llen + 12 std + 10`, above `31 llen`. It falls by 25 each step until the scale reaches 0, and by less at that step. So before the scale reaches 0 it can equal `31 llen` only when `12 std + 10` is a multiple of 25, and at the scale 0 it is `avg + 6 std + 10`, far below `31 llen` at each depth. For the deviations 0, 1, 2, 4, 5, 8 and 13 of the depths of the intermediate levels, `12 std + 10` is 10, 22, 34, 58, 70, 106 and 166, and none is a multiple of 25. Once the maximum moved below `31 llen`, each new maximum is below the one before. So the two values are never equal.
- `NTRUSolver.rs`, `reduce`, line 647: `<` replaced with `<=`. For a large length equal to `slen`, the fill of line 652 covers the empty range `slen..slen`.
- `NTRUSolver.rs`, `depthOne`, line 691: `*` replaced with `/`, and `+` replaced with `-` in `v * slen + u`. At depth 1 `slen` is 1 and the line runs only for `u < slen`, so u is 0. `v / 1 + 0` and `v * 1 - 0` are both v.

### Open mutants

No test kills them, and no proof shows them equivalent. The evidence:

- `BigInteger.rs`, `bezout`, lines 295 and 297: `^=` replaced with `&=` or with `|=`, and `^` replaced with `&` or with `|`, in the second word of a or of b. Line 301 and line 303: `|=` replaced with `&=`. These ten mutants change only the approximation of a or of b from its two top words. When the GCD is 1, every run that reaches a = 1 gives the same u and v, because u below y and v below x are unique. So the mutants differ only when the approximation makes the algorithm run out of reductions. Copies of `zint_bezout` with each mutation gave the result and the coefficients of `zint_bezout` for 400000 random pairs of six kinds and for 400000 pairs with tops of one to three bits. A hill climb over pairs of 2 to 12 words, which maximizes the last reduction after which a is not 1, found at most 2 length for the mutants that drop the second word, which are `^=` replaced with `&=`, `^` replaced with `&`, and lines 301 and 303, and at most 2 length - 1 for the others. The budget is 2 length + 1, and the code of the run needs at most 2 length - 1. The same climb found the pairs that kill line 299.
- `NTRUSolver.rs`, `reduce`, line 604: `<=` replaced with `>`. The mutant swaps the plain product and the product in the transform. The two agree when each coefficient of `k f` lies within half the product of the `slen + 1` primes, about `2^(31 slen + 30)`. A coefficient of k is below `2^31` and a coefficient of f below `2^(31 slen - 1)`, so a sum of N such terms can pass the bound, and no line of the code keeps it within. A C copy of `solve_NTRU_intermediate` with the mutation gave the result of the C function for 3600 inputs with random deeper values and top polynomials of four kinds, at depths 2 to 8 and degrees up to 1024. For a key, the coefficients of f have about the bits of `BITLENGTH`, and the products stay several bits below the bound.

| Rule | Mutant | Killed by |
|---|---|---|
| The binary GCD takes the top words where either value is not zero | `BigInteger::bezout`, line 299: `\|` replaced with `&` or with `^` | `bezoutGivesTheCoefficientsOfZintBezoutForEveryKindOfPair` |
| A negated a or b negates its factors | `BigInteger::bezout`, line 340: `-` deleted, line 341: `-` deleted, or `>>` replaced with `<<` | `bezoutGivesTheCoefficientsOfZintBezoutForEveryKindOfPair` |
| The count of reductions of the binary GCD is the count of the C code | `BigInteger::bezout`, line 285: `+` replaced with `-` | `bezoutGivesTheCoefficientsOfZintBezoutForEveryKindOfPair` |
| The co-reduction gives the negations of `zint_co_reduce` | `BigInteger::coReduce`, lines 173 and 174: `>>` replaced with `<<`, line 177: `\|` replaced with `&`, `<<` replaced with `>>` | `coReductionGivesTheValuesOfZintCoReduceAlsoWhenItNegates` |
| The modular finish adds or subtracts the modulus as `zint_finish_mod` does | `BigInteger::finishReduction`, line 190: `\|` replaced with `^` | `modularCoReductionGivesTheValuesOfZintCoReduceMod` |
| The normalization around zero compares with half the modulus | `BigInteger::normalizeAroundZero`, line 83: `<<` replaced with `>>`, line 84: `&` replaced with `^` or with `\|` | `normalizationAroundZeroGivesTheValuesOfZintNormZeroAtHalfTheModulus` |
| Rounding keeps each dropped bit in the sticky bit | `FloatingPoint::roundedToNearest`, lines 117 and 118: `\|` replaced with `^` | `roundingToNearestKeepsEachDroppedBitInTheStickyBit` |
| The normalization shifts each mantissa until its top bit is set | `normalize64`, line 283: `\|` replaced with `^` | `normalizationShiftsEachMantissaUntilItsTopBitIsSet` |
| A product keeps the sticky bit of equal low limbs | `FloatingPoint::mul`, line 388: `\|` replaced with `^` | `productsWhoseLowLimbsAreEqualKeepTheStickyBit` |
| A zero factor gives the signed zero | `FloatingPoint::mul`, line 398: `+` replaced with `-` | `aZeroFactorInEitherPlaceGivesTheSignedZeroOfIEEE754` |
| The inverse transform of degree 1 does not scale | `FourierTransform::inverseTransform`, line 106: `>` replaced with `>=` | `transformsOfEveryDegreeGiveTheBitsOfFFTAndIFFT` |
| The LDL decomposition divides by a complex g00 | `complexQuotient`, line 34: `+` replaced with `-`, line 36: `-` deleted | `decompositionGivesTheBitsOfPolyLDLFFTAlsoForAComplexG00` |
| The half-Gaussian value is the count of the table values above the random bits | `GaussianSampler::halfGaussian`, lines 90 and 91: `&` replaced with `^` or with `\|`, `>>` replaced with `<<`, line 96: `>>` replaced with `<<` | `halfGaussianIsTheCountOfTheTableValuesAboveTheRandomBits` |
| The exponential trial saturates its shift at 63 | `GaussianSampler::isBernoulliExponentialTrue`, line 111: `^` replaced with `&` or with `\|`, `>>` replaced with `<<` | `bernoulliTrialIsBerExpOfTheCCodeAlsoWhereTheShiftSaturates` |
| HashToPoint reads the samples of the C code and no more | `HashToPoint::point`, line 25: `+` replaced with `*` | `pointReadsTheSamplesOfTheCCodeAndNoMore` |
| The approximation of a negative value carries across zero words | `NTRUSolver::approximations`, line 282: `>>` replaced with `<<` | `approximationsGiveTheValuesOfPolyBigToFpAlsoWhenTheCarryCrossesZeroWords` |
| The bit lengths of f and g set the scales of the reduction | `NTRUSolver::reduce`, lines 537 and 538: `*` replaced with `+` | `intermediateLevelsGiveTheValuesOfSolveNTRUIntermediateAndFailWhereItFails` |
| Depth 1 fails where `solve_NTRU_binary_depth1` fails | `NTRUSolver::depthOne`, line 725: `\|\|` replaced with `&&` | `depthOneGivesTheValuesOfSolveNTRUBinaryDepth1AndFailsWhereItFails` |
| The saturated norm saturates once the sum reaches `2^31` | `SignatureNorm::saturatedSquaredNorm`: each operator of the overflow word replaced, and the start set to 0 | `saturatedSquaredNormIsTheSumBelow2To31AndElseSaturates` |

## Latest result for MAYO

The run of 2026-10-23 is the `Mutants` workflow of CI, in ten shards, on the branch `mutants/oqs-native-mayo.2`, which holds the code of the branch `family/mayo`: [run 40026053155](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40026053155).

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-mayo` | 963 | 948 | 0 | 6 | 9 |

The [second run](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40037053418), on the commit of the new test and the new forms, had 942 mutants: 936 caught, no timeout, 6 unviable and no missed mutant.

The run had no timeout. Five of the six unviable mutants replace a function with `Default::default()` for a type that has no default. The sixth replaces `+` with `-` in `Parameters::publicKeyLength`, and the subtraction then overflows when the compiler evaluates the lengths of the sets.

Of the nine missed mutants, one is a test gap. With `*` replaced with `/` in line 126 of `EchelonForm.rs`, the index of the clearing is `row / columnCount + unknownCount`. In every set m is below k o + 1, so the index is the same for each row, and `sampledSolution` clears the last column of the matrix only in the first row before the product `A r`. The other rows then reach the product only through the element of the randomizer after the k o unknowns, and the unit tests gave only randomizers whose element there is zero, as the signature does. The known-answer program of the unit tests now also calls `sample_solution` with the element 9, in the case `randomizerTail` of `solutionGivesTheSolutionOfTheCCodeOrNone`, and the case kills the mutant. The same case showed that the solution started as a copy of the whole randomizer, where `x <- r` of the C code copies only the k o unknowns. The solution now starts as the unknowns and a zero. The signature sets the element to zero, so its output does not change.

The other eight are equivalent. Each of their lines now has a form whose mutants change the output. The list below gives the proof for each mutant at the lines of the run. Applied by hand, each mutant of the new forms fails at least one unit test. The changed lines have had no second run of the workflow.

With the new case, the known-answer program and the unit tests of the crate moved to the shared contract of `Documentation/Learnings/COracle.md`. The inputs come from `LinearCongruentialSequence` and the digests from `OutputDigest`, as its rule "The internal C functions give known answers for the arithmetic" asks. Before, each input was SHAKE256 of a label.

### Equivalent mutants

- `EchelonForm.rs`, `echelonForm`, line 66: `|` replaced with `^` in `isPivotRow | (isBelowPivotRow & pivotIsZero)`. Line 64 sets `isPivotRow` to all ones only for the pivot row, and line 65 sets `isBelowPivotRow` to all ones only for a row below it. So at most one of the two terms is not zero, and the or and the exclusive or give the same mask. The line now joins the two masks with `+`.
- `EchelonForm.rs`, `sampledSolution`, line 149: `^=` replaced with `|=` in `columnBytes ^= u64::from(...) << (8 * offset)`, the word of the elements of a column in eight rows. Line 147 sets the word to zero, and the step `offset` writes the byte `offset` alone, because each element is one byte. So each byte is zero before its write. The word is now one assignment with `u64::from_le_bytes`.
- `LinearSystem.rs`, `rightHandSide`, line 41: `%` replaced with `+` in `((sum[last] >> topShift) % 16) as u8`. `top` is only the first factor of `field::product` (line 48), which reads only the bits 0 to 3 of that factor (`Field.rs`, lines 8 to 11). Adding 16 does not change those bits. The line now takes the bits with `& 0x0F`.
- `LinearSystem.rs`, `rightHandSide`, line 44: `^=` replaced with `|=` in `sum[limb + 1] ^= sum[limb] >> 60`. The shift of line 42, or of line 45 in the step before, leaves the low nibble of `sum[limb + 1]` zero, and `sum[limb] >> 60` is below 16. So the two operators give the same word. The line now adds the carry with `+=`.
- `LinearSystem.rs`, `systemMatrix`, line 183: `-` replaced with `+` or with `/` in `(0..columnCount - 1).step_by(16)`. The starts are the multiples of 16 below the end of the range, and the mutants raise the end from k o to k o + 2 or k o + 1. k o is 80, 68, 110 and 144 in the four sets, so the only new start is k o, in `MAYO-1` and `MAYO-5`. For that start, line 185 gives the count 0, so the step writes nothing. Its read of line 184 takes a word of the next 16 rows, and `words` has room for them (line 116).
- `LinearSystem.rs`, `systemMatrix`, line 185: `-` replaced with `/` in `16.min(columnCount - 1 - start)`. The count then grows by one at the last start when k o is not a multiple of 16, in `MAYO-2` and `MAYO-3`. So the step also writes the column k o, from the nibble of the column k o in the word. That element is zero. Lines 133 and 135 write only the columns below k o, the transposition of line 150 changes only the layout of the elements, and the reduction of lines 159 to 176 adds to an element only multiples of an element of the same column. Line 177 already set the last column to zero.
- `MatrixProducts.rs`, `quadraticForms`, line 309: `+` replaced with `*` in `accumulator[start..start + limbCount]`, where line 306 sets `start` to an element of the signature times `limbCount`. Each element is below 16, because the only caller decodes the signature with `field::decode` (`InternalAlgorithms.rs`, line 255). For the element 0 the range is empty, so the bin 0 misses the entry, but `multiplyBins` never reads the bin 0 (`PackedVectors.rs`, lines 57 to 72 and line 87). For an element from 1 to 15 the range starts at the same word and is at least as long, because `limbCount` is at least 4. `add` zips the range with the entry of `limbCount` words (`PackedVectors.rs`, line 18), so it changes the same words. The longest range ends at word `15 limbCount^2`, inside the accumulator of `16 limbCount n` words. Each bin is now `mutableEntry` of the accumulator.

| Rule | Mutant | Killed by |
|---|---|---|
| The solution does not depend on the element of the randomizer after the k o unknowns, as in the C code | `sampledSolution`, line 126: `*` replaced with `/` | `solutionGivesTheSolutionOfTheCCodeOrNone`, case `randomizerTail` |
| The solution starts as the k o unknowns of the randomizer and a zero | `sampledSolution`: the copy of the unknowns deleted, by hand | `solutionGivesTheSolutionOfTheCCodeOrNone` |
| The back substitution reads the elements of a column in eight rows at a time | `sampledSolution`: `+` replaced with `*` in `first + offset`, and with `-` before `column`, by hand | `solutionGivesTheSolutionOfTheCCodeOrNone` |
| The pivot search joins the mask of the pivot row and the mask of a lower row while the pivot is zero | `echelonForm`: `+` of the two masks replaced with `-` or `*`, and `&` replaced with `\|` or `^`, by hand | `echelonFormGivesTheMatrixOfTheCCode`, `solutionGivesTheSolutionOfTheCCodeOrNone` |
| The top element of the right-hand side is the low nibble above `topShift` | `rightHandSide`: `& 0x0F` replaced with `\| 0x0F` or `^ 0x0F`, by hand | `rightHandSideGivesTheAnswerOfTheCFunction` |
| The shift of the right-hand side carries the top nibble of each word into the next word | `rightHandSide`: `+=` of the carry replaced with `-=` or `*=`, by hand | `rightHandSideGivesTheAnswerOfTheCFunction` |
| The matrix of the system holds the k o unknowns of each row and a zero last column | `systemMatrix`: `-` replaced with `+` or `/` in `columnCount - 1`, and `*` replaced with `+` or `/` in `16 * block`, by hand | `systemMatrixGivesTheAnswerOfTheCFunction` |
| Each bin of `S P S^T` is the bin of its row and its element | `quadraticForms`: each operator of `bin` replaced, by hand | `publicMapGivesTheValueOfTheCCode` |

## Latest result for NTRU, NTRU Prime and the sorting network

The runs of 2026-10-23 on the branch `family/ntru`, in the ten shards of the `Mutants` workflow of CI: [the NTRU crate](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40026053067), [the sorting network](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40026053272) and [the NTRU Prime crate](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40032859400). The first two runs took the branch before its rebase onto the memory cap of the workflow and the ML-DSA results, which did not change the code of the three crates. The two earlier runs of the NTRU Prime crate each lost shard 7 when the runner ran out of memory, because mutants of the byte loop of `RadixEncoding::encode` made the loop endless while it wrote bytes, and the run of the table has the memory cap.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-ntru` | 1011 | 990 | 0 | 9 | 12 |
| `oqs-native-sorting-network` | 120 | 104 | 8 | 0 | 8 |
| `oqs-native-ntru-prime` | 706 | 641 | 43 | 5 | 17 |

The [second run of NTRU Prime](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40040181702), on the commit of the new tests, had 706 mutants: 645 caught, 43 timeouts, 5 unviable and 13 missed. The 13 missed mutants are the 13 equivalent mutants below, and the timeouts are the timeouts of the first run.

The 12 missed mutants of NTRU and the 8 of the sorting network are equivalent mutants. Of the 17 missed mutants of NTRU Prime, four are test gaps, and `decodingReadsTheBytesOfEncodeAtEachThresholdOfTheRanges` and `residueModuloModulusIsCenteredUpToTheLimitOfThe32BitProductOfFqFreeze` now kill them. The other 13 are equivalent.

Seven of the eight timeouts of the sorting network stop a loop of `SortingNetwork::sortWith`: `+=` replaced with `*=` at the lines 89, 98, 115, 126 and 131, `+=` replaced with `-=` at line 89, and `*` replaced with `/` in `2 * p` at line 98. Each keeps `top` at 1 or at 0, keeps `i` at 0 or `j` at its place, or adds 0 to `i` for a `p` of 4 or more, so its loop never ends. Applied by hand, each kept the unit test program running for 120 seconds, where it ends in under a second. The eighth, `*` replaced with `/` in `2 * p` at line 126, failed `sortUnsignedGivesTheUnsignedValuesInAscendingOrderForEveryLength` before the limit.

Of the 43 timeouts of NTRU Prime, 35 failed a unit test before the limit: the 22 mutants of `PolynomialRing::ternaryReciprocal`, the four of the masks and the two of `residueModuloThree` in `ModularReduction`, the three of `Parameters::wordRequestLength`, the three of `Sampler::words` and `Sampler::smallFromWords`, and `PublicKeyEncryption::keyPair`, line 33, with `==` replaced with `!=`. In each, `theOperationsOfASequenceGiveTheBytesOfTheCCode`, which makes a key pair, had not ended, and in 33 of them `aCandidateGWithoutAnInverseIsDrawnAgain` had not ended either. The loop of `keyPair` draws `g` again until a candidate passes the check of line 33, and no candidate passed. The other eight failed no test before the limit:

- `RadixEncoding::encode`, line 48: `>` replaced with `>=`, the lines 51 and 67: `>>` replaced with `<<`, and line 71: `+=` replaced with `*=`. The byte loop never ends while it writes bytes. In CI each test program printed "memory allocation of 2147483648 bytes failed" under the memory cap and had not ended at the limit of 10 seconds, so the run counts the mutant as a timeout. Applied by hand under the same cap, each unit test program stopped with SIGABRT after 17 to 19 seconds at a load average of 27, with "memory allocation of 8589934592 bytes failed" in `eachFormHasTheBytesOfTheCFunctions`.
- `RadixEncoding::decode`, line 141: `+=` replaced with `*=` keeps `index` at 0, so the last loop never ends and writes nothing new. Applied by hand, it kept the unit test program running for 180 seconds.
- `Sampler::randomWords` replaced with an empty list, and `Sampler::smallPolynomial` replaced with an empty list or with `[0]`. No candidate `g` has an inverse, so the loop of `keyPair` never ends. Applied by hand, each kept the unit test program running for 180 seconds.

### Equivalent mutants of NTRU

- `Packing.rs`, `sumZeroPolynomial`, line 117: `-` replaced with `/` in `count - 1`. The fold then also subtracts the coefficient `n - 1`, which is 0, because `modulusPolynomial` starts from `n` zeros (line 94) and writes only the first `n - 1` (line 98).
- `PolynomialInversion.rs`, `inverseModuloThree`, line 91: `*` replaced with `/` in `2 * g[0] * f[0]`. `f[0]` is 1 at line 81 and changes only at line 97, where a swap gives `f` the values of `g`. A swap needs `g[0]` above 0 (line 92), and the lines 85, 98, 105, 111 and 112 keep `g` in `{0, 1, 2}`, so `f[0]` is 1 or 2. For 1 the two operators agree. For 2 the mutant gives `g[0]` and the code gives `4 g[0]`, which are equal modulo 3, so `smallResidueModuloThree` gives the same residue.
- `PolynomialMultiplication.rs`, `karatsubaEvaluation`, line 134: `*` replaced with `/` in `4 * k`. `k` is a sixteenth of the padded length `32 ceil(n / 32)` (lines 56 and 114), at least 32 for every set, so `4 / k` is 0. The mutant reads `value[index]`, which line 132 copied to `value[4 * k + index]`. The loop writes only entries from `4 k` up, and the entry `4 k + index` only after it reads it.
- `PolynomialMultiplication.rs`, `schoolbookProduct`, line 150: `-` replaced with `/` in `k - 1`. The inner loop then also adds `left[leftIndex] right[k - 1]` to the entry `leftIndex + k - 1`, and line 154 then sets that entry to the same product, as the C code does.
- `PolynomialRing.rs`, `residueModuloThree`, line 31: `^` replaced with `|`. The mask of line 30 is 0 or -1, so one operand is 0. `residueModuloThreeIsTheRemainderForEverySixteenBitValue` checks every input and passes with the mutant.
- `PolynomialRing.rs`, `ternaryFromModulus`, line 94: `-` replaced with `+` in `1 - (bits & 1)`. For the even exponents 12 and 14 both give the shift 1. For the odd exponents 11 and 13 the mutant adds 4 in place of 1 to a coefficient from `q / 2` up, which is the same modulo 3. Each value stays below `q + 4`, so the sum of line 70, in `reduceModuloThreeAndPhi`, stays below `3 (q + 4)` and does not wrap, and `reduceModuloThreeAndPhi` gives the same residues.
- `PolynomialRing.rs`, `liftByXMinusOne`, line 143: `-` replaced with `/` in `3 - (count % 3)`, and line 152: `*` replaced with `/` in `2 * t`. Only `lift` of NTRU-HRSS calls the function (line 131), and `n` is 701 or 1373, both 2 modulo 3. So `t` is 1, which is also `3 / 2`, and `2 / t` equals `2 t`.
- `Sampler.rs`, `fixedTypePolynomial`, line 64: `-` replaced with `+` or with `/` in `coefficientCount - 1`, and line 67: `/` replaced with `*` in `count / 4`. `count` sets only the capacity of `keys` and the number of groups that `take` keeps. Every set has `n = 1` modulo 4, so `n / 4` and `(n + 1) / 4` equal `(n - 1) / 4`. Every caller gives the function the `15 (n - 1) / 4` bytes of `fixedTypeSampleLength`: `NTRU.rs`, the lines 63 and 82, draw `sampleLength` bytes, and `Sampler.rs`, the lines 25 and 41, split them at `n - 1`. So `chunks_exact(15)` gives `(n - 1) / 4` groups, and a `take` of `4 (n - 1)` keeps each of them.
- `Sampler.rs`, `correlatedPolynomial`, line 113: `-` replaced with `/` in `count - 1`. The map of line 114 then also takes the coefficient `n - 1`, which is 0, because `independentPolynomial` starts from `n` zeros (line 52) and every caller gives `n - 1` bytes: `keyPolynomials` splits the `2 (n - 1)` bytes of NTRU-HRSS at `n - 1` (line 25). The map takes 0 to 0.

### Equivalent mutants of the sorting network

Two facts about one pass of `sortWith`, with `p` fixed, give the proofs. A place `k` is low when `k mod 2p < p` and high otherwise. A merge at a low place `k` with the reach `q` compares the value at the high place `k + p` with the values at the low places `k + r`, for `r` from `q` down to `2p`, and keeps the smaller value at `k + p`.

1. Each pass starts the loop of line 106 with `j = i` (the lines 103 and 104). Line 122 leaves `i` at the smallest multiple of `2p` above `n - q - p`, because `i` enters the loop at that value or below it, and the lines 128 to 132 leave `j = max(i, n - q)`. So the loop of line 108 runs only when `i < j = n - 2q < i + p`, and then `i + p < n - q`, so `j` reaches `i + p` at line 116 before line 109 holds. The lines 109 to 112 never run, and the level `q` merges the low places from `max(0, n - 2q)` to `n - q - 1` in ascending order.
2. For an input of zeros and ones, a value at a low place only changes from 0 to 1 during the loop, and a value at a high place only from 1 to 0. The pass ends with the values of each class of places modulo `p` in ascending order, because the pass is the merge of Batcher's merge exchange, Algorithm M of Knuth, The Art of Computer Programming, volume 3, section 5.2.2, with its comparisons in an order that keeps the order of any two comparisons of one place. A 1 at a low place before a 0 at a high place of its class would stay to the end of the pass, so at each point of the loop a value at a low place is at most each value at a later high place of its class. A merge at a high place `k` compares the value at the low place `k + p` with the values at the later high places `k + r`, so it changes nothing. A second merge of a low place, with a reach no longer than its first merge, changes nothing as well: after the first merge the value at `k + p` is 0, or it is 1 and each value of its chain is 1, and no value changes back. A comparison commutes with each threshold of the values, so what holds for every input of zeros and ones holds for every input.

The equivalent mutants:

- `merge`, line 69: `>` replaced with `>=`. The extra comparison with `r = p` compares the running minimum with the value that line 67 read from `place + p`, which no step of the loop writes, so it changes nothing.
- Line 88: `<` replaced with `<=`. For `n` a power of two, `top` becomes `n` in place of `n / 2`. The pass with `p = n` makes no comparison, and each later pass starts with a level `q = n` that merges nothing, because `n - q` is 0, and keeps `j = i = 0`.
- Line 106: `>` replaced with `>=`. The extra level `q = p` merges with no comparison, because line 69 needs `r > p`, and each merge writes back the value that it read. By fact 1 the places stay below `n - p`.
- Line 109: `-` replaced with `+`, and line 111: `>>=` replaced with `<<=`. The lines 109 to 112 never run (fact 1).
- Line 107: `!=` replaced with `==`. With `j = i`, the loop of line 108 merges the places that the lines 122 to 131 merge, and leaves the same `i` and `j`. With `j` not equal to `i`, line 122 merges the whole block from `i`, so the places from `i` to `n - 2q - 1` get a second merge with the reach `q` after their merge at the level `2q` (fact 2).
- Line 116: `+` replaced with `*` in `i + p`. The loop of line 108 leaves at line 116 only when `j` reaches `i p`. For `i = 0` or `p = 1` this never happens, so the loop merges every place up to `n - q - 1`, high places included, and leaves at line 109. For a larger `i`, `i p` is at least `i + 2p`, so the lines 122 to 131 start where the network starts them and merge again the places from `i + 2p` to `i p - 1`. After a level that leaves at line 109, the next level starts its loop at `n - 2q` with the same `i`. So each level merges every low place of its range, the first time in ascending order, and each other merge is at a high place or repeats a low place of that level or of an earlier level (fact 2).
- Line 122: `-` replaced with `/` in `n - q`. `n / q` is at most `n - q` for `q` from 2 to `n - 1`, so line 122 stops at or before the block where the network stops, and line 129 then merges every place up to `n - q - 1`, high places included. Each later level starts its loop of line 108 at `n - 2q` and merges every place up to `n - q - 1`. Only the second level of a pass with `n - top` below `i + p` differs, and it merges the low places of its range in ascending order and some high places. So the low places of each level are those of the network in the same order, and each extra merge is at a high place (fact 2).

The merges depend only on `n`. A check of the lists of merges confirms the three descriptions for every `n` up to 4096 and for 6688, 8192, 8193, 12289, 16383, 16385, 65535, 65537 and 100003: the merges of the network appear in the same order, and each other merge is at a high place or repeats a low place whose first merge had the same or a longer reach.

### Equivalent mutants of NTRU Prime

- `ModularReduction.rs`, `residueModuloModulus`, the lines 20 to 22: seven of the nine mutants of the estimates `q16`, `q20` and `q28`. `/` replaced with `%` in `q / 2` keeps `q16 = 14` and `q20 = 228`. The others give `q20 = 227` or 230, or `q28 = 58469` or 58471. Each line subtracts a multiple of `q`, so the value stays congruent to the input. For every input up to `2^31 / 14 = 153391689` in absolute value, where the product `14 x` of line 24 fits in 32 bits as in the C code, the lines 24 and 25 leave at most 9746 in absolute value with `q20 = 228`, 22688 with 227 and 25278 with 230. Line 26 gives the centered residue of every value up to 34432 in absolute value with `q28 = 58469` or 58470, and up to 29840 with 58471. So each mutant gives the centered residue, the value of `Fq_freeze`, for every such input. `residueModuloModulusIsCenteredForEveryInputOfTheCallers` checks every input of the callers, and it passes with each of the seven, as does `residueModuloModulusIsCenteredUpToTheLimitOfThe32BitProductOfFqFreeze`. The other two mutants of line 20 give `q16 = 13` or 16, and their products overflow 32 bits from 105412007 and from 77901825 in absolute value. The second test kills them.
- `NTRUPrime.rs`, `decapsulate`, line 107: `^` replaced with `|` in `sessionPrefix ^ rejectedSessionPrefix`. The prefixes are 1 and 0 (`HashFunctions.rs`, the lines 10 and 13), which have no set bit in common.
- `Parameters.rs`, `halfModulus`, line 23: `-` replaced with `/` in `(self.modulus - 1) / 2`. `q = 4591` is odd, so `q / 2` is 2295 as well.
- `PolynomialRing.rs`, `ternaryReciprocal`, line 124: `*` replaced with `/` in `-g[0] * f[0]`. `f[0]` is 1 at line 114 and changes only at line 134, where a swap gives `f` the values of `g`. A swap needs `g[0]` not 0 (line 127), and `g` holds only the values `{-1, 0, 1}` of the small input and of line 142, so `f[0]` is 1 or -1, and a division by it is a product with it.
- `PolynomialRing.rs`, `ternaryReciprocal`, line 140: `+` replaced with `*` in `0..p + 1`. The loop then leaves out the entry `p` of `g`. Line 149 sets `g[p]` to 0 at the end of each step, and a swap gives `f` the entry `g[p]`, so `f[p]` is -1 before the first swap and 0 after it. Before the first swap `delta` is above 0, so a step without a swap has `g[0] = 0` and `sign = 0` (the lines 124 to 128). So `sign f[p]` is 0 at every step, and line 142 gives `g[p]` its own value.
- `PolynomialRing.rs`, `ternaryReciprocal`, line 144, and `reciprocalOfTriple`, line 197: `+` replaced with `*` in `0..p + 1`. The loop then leaves out the entry `p` of `r`. The entries `p` of `r` and `v` pass values only to each other, at the swap (the lines 136 to 138 and 188 to 190) and at the update of `r` (the lines 145 and 198). The shift of the lines 122 and 176 overwrites `v[p]` with `v[p - 1]` at the start of each step, and the result reads only `v[0]` to `v[p - 1]` (the lines 153 and 208). So the entry `p` of `r` never reaches the result.

| Rule | Mutant | Killed by |
|---|---|---|
| Decode takes one byte for a product of 256 times 16383, and the next pair reads from the next byte | `RadixEncoding::decode`, line 111: `>` replaced with `>=` | `decodingReadsTheBytesOfEncodeAtEachThresholdOfTheRanges` |
| Decode rounds the range of a pair of two bytes up twice | `RadixEncoding::decode`, line 116: `+` replaced with `-` | `decodingReadsTheBytesOfEncodeAtEachThresholdOfTheRanges` |
| The reduction modulo q is centered up to the limit of the 32-bit products of `Fq_freeze` | `ModularReduction::residueModuloModulus`, line 20: `+` replaced with `-`, `/` replaced with `*` in `q / 2` | `residueModuloModulusIsCenteredUpToTheLimitOfThe32BitProductOfFqFreeze` |
| A candidate g without an inverse in R3 is drawn again | `PublicKeyEncryption::keyPair` of NTRU Prime, line 33: `==` replaced with `!=` | `aCandidateGWithoutAnInverseIsDrawnAgain` |
| The comparison of the sort orders two values across the sign boundary | `SortingNetwork::ordered`, line 33: `-` replaced with `+` | `orderedGivesTheSmallerValueFirstAlsoAcrossTheSignBoundary` and 4 more |
| The unsigned sort is the signed sort with the top bit flipped | `SortingNetwork::orderedUnsigned`, line 42: `^` replaced with `\|` | `orderedGivesTheSmallerValueFirstAlsoAcrossTheSignBoundary`, `sortUnsignedGivesTheUnsignedValuesInAscendingOrderForEveryLength` and 2 more |
| The check of r accepts only 0, 1 and q - 1, and 0 at n - 1 | `PublicKeyEncryption::blindingFailure` of NTRU, the lines 124, 126 and 128: `\|=` replaced with `&=` | `theBlindingCheckAcceptsOnlyZeroOneAndMinusOne` and 1 more |
| The ciphertext check reads only the unused bits of the last byte | `PublicKeyEncryption::ciphertextFailure`, line 111: `&` replaced with `\|` | `theCiphertextCheckReadsOnlyTheUnusedBitsOfTheLastByte` |
| A failed check of NTRU gives the rejection secret | `NTRU::decapsulate`, line 117: `^=` replaced with `\|=` | `constantRandomBytesGiveTheKeyFZeroAsInTheCCode` |

## Latest result for SLH-DSA

The run of 2026-10-23 of the crate in the ten shards of the `Mutants` workflow of CI, on a commit of the branch `family/slh-dsa`: [the crate](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40026767732). The branch moved to a new base after the run, and no file of the crate changed. The workflow of the run did not yet cap the memory of the test programs, and every shard ended.

| Crate | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|
| `oqs-native-slh-dsa`, first run in CI | 539 | 496 | 0 | 41 | 2 |

The run had no timeout. One of the two missed mutants is a test gap, and `nodesOfEveryHeightUpToAWholeTreeAreTheNodesOfTheCFunction` now kills it. The other is equivalent.

The test gap replaces `+` with `*` in the size of the stack of `FORS::node`, line 30, so the stack holds 14 nodes in place of 15. The node of height z needs z + 1 places. `FORS::sign` asks only for the heights from 0 to a - 1, so a signature needs at most 14 places, and the root of a whole tree of height 14 needs 15. `fors_node` of the C code takes every height up to a, because its stack of 14 nodes, `SLH_MAX_A`, and its output hold 15 nodes. The new test compares the nodes of every height from 0 to 14 of `SHA2_192S` and `SHAKE_256S` with the digests of `fors_node`. The C program that printed them includes `slh_dsa.c`, because the function is static, and takes the hash functions from `liboqs.a`. Its copy of `slh_sign_internal` gives the signatures of `liboqs.a`. With the mutant, the test fails with an index out of bounds at the index 14 of the stack. With `-` in place of `+`, the stack holds 13 nodes, and the new test and `testSigMemPassesForEachSchemeOfTheSuiteSampleAndEachPureSmallSet`, which signs with trees of height 14, both fail.

### Equivalent mutants

- `Hypertree.rs`, `chainDigits`, line 243: `-` replaced with `+` in `(8 - (checksumBits & 7)) & 7`. The port keeps the formula of FIPS 205, Algorithm 7, and of `wots_csum` of the C code. `checksumBits` is `len_2 lg_w`. `Parameters::checksumChainCount` gives 3 and `Parameters::winternitzBits` is 4 for every set, so `checksumBits` is 12 and `checksumBits & 7` is 4. The shift is `(8 - 4) & 7 = 4`, and with the mutant it is `(8 + 4) & 7 = 4`. So the checksum, its bytes and its digits are the same for every message. With `/` in place of `-` the shift is 2, and `chainDigitsOfTheZeroMessageCarryTheLargestChecksum` kills that mutant.

| Rule | Mutant | Killed by |
|---|---|---|
| A FORS node of every height up to a whole tree of the largest height is the node of the C code | `FORS::node`, line 30: `+` replaced with `*` or `-` in the size of the stack | `nodesOfEveryHeightUpToAWholeTreeAreTheNodesOfTheCFunction`, and for `-` also `testSigMemPassesForEachSchemeOfTheSuiteSampleAndEachPureSmallSet` |
| The stack of `Hypertree::xmssNode` holds the whole top tree of height 9 of a key pair | `Hypertree::xmssNode`, line 102: `+` replaced with `*` or `-` | `testSigMemPassesForEachSchemeOfTheSuiteSampleAndEachPureSmallSet` |
| The WOTS+ checksum adds w - 1 minus each digit, shifted so that its digits fill whole bytes | `Hypertree::chainDigits`, line 240: `-` replaced with `+`, line 243: `<<=` replaced with `>>=` | `chainDigitsOfTheZeroMessageCarryTheLargestChecksum` |
| The tree and the leaf index take their bits after the FORS digest | `SLHDSA::treeAndLeafIndex`: each operator replaced | `treeAndLeafIndexTakeTheirBitsAfterTheFORSDigest` |
| A context of 255 bytes signs and verifies, and a longer one is refused | `signWithContext`, line 395, and `isValidSignatureWithContext`, line 420: `>` replaced with `>=` | `aContextOfMoreThan255BytesIsRefusedAfterTheRandomRequest`, `testSigPassesForEachPureSchemeOfTheSuiteSample` and 2 more |
| Only the SHA2 sets of categories 3 and 5 use SHA-512 | `Parameters::usesSHA512`, line 98: `>` replaced with `==` | `onlyTheSHA2SetsAboveCategoryOneUseSHA512`, `sha2FunctionsHashTheSeedBlockTheCompressedAddressAndTheInput` |
| `PRF_msg` and `H_msg` of a SHA2 set of category 3 or 5 use SHA-512 | `HashContext::prfMessage`, line 191, and `messageDigest`, line 229: the match guard replaced | `signatureVectorsOfTheFastSHA2SetsGiveTheirSignatures`, `verificationVectorsGiveTheirVerdicts` |
| A verification compares the last root with `PK.root` | `Hypertree::isValid`, line 92: `==` replaced with `!=` | `hypertreeSignatureVerifiesAndAChangedMessageDoesNot` |
| Each field of the address is a big-endian word at its place | `Address::setWord`: each operator replaced | `eachFieldIsABigEndianWordAtItsPlaceOfFIPS205Figure2`, `compressedAddressKeepsTheBytesOfFIPS205Section11Point2` and 9 more |

## History

| Run | Code | Mutants | Caught | Timeout | Unviable | Missed |
|---|---|---|---|---|---|---|
| 1 | First version of the tool | 758 | 492 | 111 | 19 | 136 |
| 2 | Token trees, `run` and `Report`, new tests | 564 | 512 | 14 | 33 | 5 |
| 3 | The five survivors removed or killed | 544 | 503 | 8 | 33 | 0 |
| 4 | `NamingCheck.rs` only, after the module rule change | 37 | 33 | 0 | 4 | 0 |

`Documentation/Learnings/MutationTesting.md` records what the first two runs taught.
