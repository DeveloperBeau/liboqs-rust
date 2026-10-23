# Mutation testing

## Index arithmetic that only skips ahead gives equivalent mutants

- **Trap.** A scanner that moves an index past a bracket with `position = close + 1` gives the same result with `position = close`, because the next loop step skips the bracket anyway. A mutant of that line survives, and no test can kill it.
- **Finding.** The first mutation run of `Tools/Xtask` had 106 surviving mutants in the declaration scanner. Most were of this kind.
- **Rule.** Group the tokens by brackets first (`TokenTree`). Then a handler steps over a group as one item, and a step that is wrong by one changes the result. Leave a group that the main loop can enter without harm for the main loop, and step over only the groups that must not be entered.

## Equivalent at one level is not equivalent at the level below

- **Trap.** A tokenizer mutant can give the same declaration list for every test source, although the token list is different.
- **Finding.** Mutants in the character literal code survived the scanner tests. A tokenizer test that compares the whole token list kills them.
- **Rule.** Test each layer at its own output. Test the tokenizer with token lists, the tree builder with tree shapes, and the scanner with declarations.

## A loop without progress hangs instead of failing

- **Trap.** A mutant that stops a loop from moving makes the suite hang. The run waits for its timeout, which is slow, and the result says "timeout", not the name of a test.
- **Finding.** The first run had 111 timeouts at 20 seconds each, which was most of its 14 minutes.
- **Rule.** Put a `debug_assert!` of progress in each main loop, so a stuck loop fails at once with a message. Keep a short test timeout in `.cargo/mutants.toml`. A timeout still counts as caught.

## The mutation copy of the tree has no git folder

- **Trap.** `cargo mutants` copies the source tree without `.git`, so a test that runs git on the repository itself fails in the copy and stops the run.
- **Finding.** The contract test of `DiskFileSystem` must run git, because the adapter calls git.
- **Rule.** A test that needs git makes its own repository in a temporary folder and deletes it at the end. No test reads the git state of the repository that it tests.

## A `no_std` library makes most mutants unviable

- **Trap.** `cargo mutants` puts values such as `Vec::new()` and `vec![]` into a function. In a library that is always `no_std`, those names are not in scope, so the mutant does not build and proves nothing.
- **Finding.** The first run of `oqs-native-entities` and `oqs-native-domain` gave 16 unviable mutants of 26, among them each mutant of the "persist before release" rule. With the `std` feature on by default, the same run gave 23 caught and 3 unviable.
- **Rule.** A crate that must build without the standard library gets a `std` feature, on by default, and `#![cfg_attr(not(feature = "std"), no_std)]`. CI builds the workspace and each crate alone with `--no-default-features`, so the `no_std` form cannot rot.

## The workspace build hides a crate that needs the standard library

- **Trap.** `cargo build --workspace --lib --no-default-features` passes, and a crate of the workspace still fails to build without `std`.
- **Finding.** Cargo unifies the features of the crates of one build. The tools turn on the `std` feature of the facade crate, and the facade crate turns on `std` in every family, so the workspace build compiles each family with `std`. `cargo build -p oqs-native-ml-kem --lib --no-default-features` failed, because `vec!` was not in scope in `PublicKeyEncryption.rs`.
- **Rule.** CI also builds each crate of `Modules` alone with `--no-default-features`. Before a change goes up, build each crate that it adds or changes alone in the same way.

## Drop code needs an allocator to prove it

- **Trap.** A test cannot read memory after it is freed, so the wipe of `SecretBytes` in `Drop` had no test, and the mutant that deletes the body of `drop` survived.
- **Finding.** A test-only global allocator that inspects each freed block of one unusual size sees whether the block was wiped. A plain vector of the same size is the control, so the test can tell a wipe from no wipe.
- **Rule.** Prove a wipe on drop with the recording allocator of `SecretBytes.rs`, and keep its control case.

## Disjoint bit fields make `|` and `^` the same

- **Trap.** Code that joins bit fields that cannot overlap, such as `(x & 0x00FF) | (y << 8)`, gives the same value with `^`. The mutant that swaps the two operators survives, and no test can kill it.
- **Finding.** The first run of the primitives had 25 such survivors in the bitsliced AES and in the choice and majority functions of SHA-2. One more is inside the S-box circuit, where two signals never share a set bit.
- **Rule.** Join disjoint fields with `+`, which gives the same value with no carry, and whose mutants change the value. Write choice as `g ^ (e & (f ^ g))` and majority as `(a & b) + (c & (a ^ b))`. Where a circuit from a paper has such a line, keep the line as the paper gives it, prove the equivalence with an exhaustive test, and record the mutant as expected in the register.

## A timeout can be a slow suite and not an endless loop

- **Trap.** On a loaded machine, a mutant that changes nothing can pass the time limit of the suite, and the run counts it as caught.
- **Finding.** The first run of `oqs-native-hqc` had nine timeouts at 36 seconds. Seven left the three tests of the rejection sampler unfinished, which is an endless loop. One had already failed `derivedValuesAreTheValuesOfParametersHeader` and was still in a test that loops up to the threshold that the mutant made larger. The last one, a smaller `savedSigma` in `ReedSolomon::errorLocator`, passed every test that ended, and it is equivalent.
- **Rule.** Read the log of each timeout. An endless loop leaves the tests of the loop unfinished. A timeout whose finished tests all pass is a missed mutant until a test or a proof closes it.

## An input that the caller never gives hides a mutant

- **Trap.** A mutant that changes the output of a function only for inputs that its caller never gives survives every test through the caller.
- **Finding.** The Reed-Solomon decoder of HQC gives the FFT a locator whose coefficients above `delta` are zero and whose value at 0 is 1, and the FFT never asks `radix` for two coefficients. Five mutants of `AdditiveFFT.rs` changed the output only for other inputs, and every decoder test passed. `evaluationsGiveTheValuesOfTheCFunctionForEveryCount` and `errorPositionsGiveThePositionsOfTheCFunctionForAnyValues` compare the functions with `fft` and `fft_retrieve_error_poly` for any inputs, and `radixConversionIsTheSplitOfItsDefinitionAtEverySize` converts every size. They kill the five.
- **Rule.** The known-answer test of an internal function feeds it every kind of input that the C function or the definition accepts, not only the inputs of its caller.

## Writes into zeroed or unused space give equivalent mutants

- **Trap.** An exclusive or into a word that is zero gives the same value as an or, and a region that is larger than its content changes nothing. A mutant of such a write survives, and no test can kill it.
- **Finding.** Ten of the 18 equivalent mutants of `oqs-native-hqc` are of this kind: `^=` into the zeroed positions of `errorPositions` and into the zeroed result of `karatsubaProduct`, the split of the scratch of `karatsubaProduct`, an extra entry of `gammas` and `deltas` that no line reads, and a smaller `savedSigma` whose last entry no line uses.
- **Rule.** Write a value into a zeroed buffer with an assignment or a copy where the form of the C code allows it. Where the port keeps the form of the C code, the register names the line that zeroed each word or the lines that read the region.

## A special case that equals the general path gives an equivalent mutant

- **Trap.** A function with its own cases for small sizes and a general path for the other sizes gives an equivalent mutant for each deleted case, because the general path also handles the small sizes.
- **Finding.** `radix` of `AdditiveFFT.rs` has cases for 2, 4, 8 and 16 coefficients, as the C code has. A deleted case of 4, 8 or 16 coefficients sends that size to `radixOfManyCoefficients`, which gives the same split.
- **Rule.** Keep the cases of the C code. Prove with a test that each case and the general path give the same output at each size, and record each such mutant as equivalent.

## A later step can repair the change of a mutant

- **Trap.** A mutant that skips a term in one step of an iterative algorithm can be equivalent, because a later step adds the term back.
- **Finding.** In `ReedSolomon::errorLocator`, `step + 1` replaced with `step * 1` skips the term `a x^(mu0 + 1)` at the first step `mu0` whose discrepancy is not zero. Words of every weight, and words whose first syndromes are zero, did not kill it. The degree cannot grow up to step `2 mu0 + 1`, and the discrepancy of that step differs by `a^2`, which adds the term back.
- **Rule.** When the tests of an iterative algorithm cannot kill a mutant, run the two forms side by side on many inputs before writing more tests, and write the proof of the equivalence when no input differs.

## A large crate needs the shards of CI

- **Trap.** Each mutant of a family crate builds the crate and its test programs again and runs the whole suite of the crate. On the shared development machine, other builds share the four processors.
- **Finding.** `oqs-native-falcon` has 2486 mutants. With three jobs at a load average of about 30, each mutant took 150 to 190 seconds to build and up to 126 seconds to test, so the run would have taken about 70 hours.
- **Rule.** Run a crate with more than a few hundred mutants in the `Mutants` workflow, whose ten shards run on runners of their own.

## An endless loop that fills a list takes the memory of the machine

- **Trap.** A mutant can make a loop endless while the loop adds to a list in each turn. The list then takes the memory of the machine before the time limit of the test stops the test, and the machine stops in place of the test.
- **Finding.** The first CI runs of two families each lost a shard to "The runner has received a shutdown signal". In each, a mutant made a loop endless while the loop wrote into a list: the byte loop of a radix encoding, whose changed condition held for every range, and a loop of signing attempts whose count stayed at 0 while its test recorded each attempt. Applied by hand under a cap of 4 GiB on the address space, each test program stopped within 6 seconds with "memory allocation of ... bytes failed".
- **Rule.** Run the tests of a mutation run under a cap on the address space of each test program, above the largest test program of the workspace. The `Mutants` workflow starts each test program through `prlimit`, so a failed allocation stops the test program, and the mutant counts as caught.

## A coverage test reads the list that the program reads

- **Trap.** A test that looks up each name of the C library with `Registry::signatureScheme` proves that the lookup finds the scheme. The parity program checks the schemes of `Registry::signatureSchemes`, which is another function.
- **Finding.** With `signatureSchemes` replaced by an empty list, the parity program checked no signature scheme, and every test passed. The facade run of ML-DSA missed the mutant. `cNamesOutsideTheRegistry` of `AlgorithmCoverage.rs` now reads the three lists, so with the empty list the names of ML-DSA are outside the registry and the test fails.
- **Rule.** A coverage test reads the same list as the program whose coverage it proves.

## A function that only the tests call needs a test that sees it fail

- **Trap.** When the program stops calling a function, the tests that still call it can all expect success. A mutant that returns success then survives.
- **Finding.** Since the parity jobs check blocks with `checkCase`, only the harness tests call `SignatureParity::checkEveryCase`, and for a signature scheme each of them expected `Ok(())`. The mutant that returns `Ok(())` survived the ML-DSA run of `SignatureParity.rs`. `aSignatureDefectInTheBaseCaseNamesTheSnapshotField` now runs it on a broken scheme, as `aKEMDefectInTheBaseCaseNamesTheSnapshotField` does for a mechanism.
- **Rule.** When a change moves the program off a function, check that a test still sees the function fail, or remove the function.

## Integer division hides a small change of the dividend

- **Trap.** A mutant that turns `q - 1` into `q + 1` or into `q / 1` in `(q - 1) / 88` survives every test, because the quotient does not change.
- **Finding.** The first run of `oqs-native-ml-dsa` had twelve such mutants, in the gamma2 of each parameter set and in the threshold `(q - 1) / 2`. q - 1 is a multiple of 88, of 32 and of 2, and q + 1 and q leave a remainder below the divisor. The mutant that replaces `2^32 % q` with `2^32 + q` in `rootPowers` is of the same kind, because the loop takes the product modulo q after its first step.
- **Rule.** Compute the value of each mutant of a constant before writing a test for it. A test of the constant cannot kill a mutant that keeps the value. Record such a mutant as equivalent, with the values on both sides.

## A threshold that no input reaches gives an equivalent mutant

- **Trap.** A comparison with a threshold gives the same result with `>=` in place of `>`, or with the threshold one higher, when no input of the comparison lies at the threshold.
- **Finding.** The centering of the twiddle factors of ML-DSA compares each entry with `(q - 1) / 2`, and no entry is 4190208 or 4190209. The selection of `decomposed` compares the low part with `(q - 1) / 2`, and each low part is at most gamma2 or at least `q - gamma2`. Three mutants survived. `twiddleFactorsAreTheTableOfMLDSANative` and `decompositionAndHintsFollowFIPS204ForEveryValue` check every input and pass with them.
- **Rule.** Prove such a mutant with a test that checks every input of the domain of the comparison. The register names the lines that keep the inputs in that domain.

## An equivalent mutant is the first to pass the time limit

- **Trap.** On a loaded machine, a timeout is more likely an equivalent mutant than a mutant that a test kills.
- **Finding.** `cargo test` stops at the first test binary that fails, so the suite of a caught mutant usually ends after the unit tests. An equivalent mutant runs every test binary. In the first run of `oqs-native-ml-dsa`, at a load average of 15 to 28, nine of the 21 timeouts were equivalent mutants, and each passed every test by hand.
- **Rule.** Check each timeout by hand with a generous limit before the register counts it as caught. Look first at the timeouts in constant expressions, whose mutants cannot make a loop endless.

## A shard that builds its own copy repeats the work of every other shard

- **Trap.** Each shard of a workflow ran the same setup before its own part: the build of the C oracle, the release build of the parity program, and the install of cargo-mutants.
- **Finding.** A shard of the parity gate spent about three minutes on the build of the C oracle before 40 seconds of parity, and the shards of a mutation run each spent about as long on the oracle. When fifteen shards start at once, they race to save the same cache key, so most of them miss it and build the oracle again.
- **Rule.** One job builds what every shard needs. The shards depend on it, restore the oracle with `fail-on-cache-miss`, and take a program from its artifact, so a shard builds only what is its own, such as the mutants of its part.

## The diff of a mutant, not its name, gives its value

- **Trap.** A copy of a mutant in another language, written from the name of the mutant, can compute another value than the mutant.
- **Finding.** cargo-mutants replaces the text of the operator. For "replace `*` with `+`" in `average - 6 * deviation` of `NTRUSolver::reduce`, the mutated line reads `average - 6 + deviation`, which is `(average - 6) + deviation`. The first C copy of the mutant computed `average - (6 + deviation)`, which moves the start of the scale of k the other way.
- **Rule.** Write the copy of a mutant from the text of its diff in the `diff` folder of `mutants.out`.

## A path that random inputs never take needs an input built from its condition

- **Trap.** A mutant of a rare path of an approximate algorithm survives millions of random inputs.
- **Finding.** `zint_bezout` negates a only when the top words of the two values put a above b while a is below b. 20 million pairs of random and of nearly equal values never negated a in a pair whose GCD is 1, so two mutants of the negation of the factors of a survived. The condition of the second step gives the pair `x = 2^k (3 b + 2) + 1` and `y = 2^k b + 2^k - 1`, whose first reduction negates a. A C copy of `zint_bezout` that counts the negations confirmed it for each of the 28 such pairs of `bezoutGivesTheCoefficientsOfZintBezoutForEveryKindOfPair`.
- **Rule.** When random inputs do not take a path, write down the condition of the path and build the input from it. Prove with a counting copy of the C function that the input takes the path.

## A mutant that only slows a loop down needs the slowest inputs

- **Trap.** A mutant that makes an algorithm with a fixed count of steps converge more slowly gives the same result for every input that converges early, which is nearly every random input.
- **Finding.** The mutant of `BigInteger::bezout` that skips the top words where a and b are equal gave the result of `zint_bezout` for 400000 random pairs. A hill climb over pairs, which maximizes the last reduction after which a is not 1, found pairs with top words of all ones that need the whole count of reductions of the mutant. A seed search of `LinearCongruentialSequence` then found three seeds whose pairs of that shape kill it. The climb also measures the margin of the mutants that it cannot push over the count: the copies that drop the second top word need at most 2 length of the 2 length + 1 reductions.
- **Rule.** When a mutant only changes the speed of a loop with a fixed count of steps, climb on the count of steps. Kill the mutant with the slowest inputs, or record the margin that the climb found.

## A copy of a shared decision keeps the mutants of the copy

- **Trap.** A decision that one function owns, written again inside another function, needs its own tests of each path. The tests of the owner do not reach the copy.
- **Finding.** The saturated squared norm of `poly_small_sqnorm`, `is_short` and `do_sign_dyn` was written three times, in `SignatureNorm`, in `KeyGenerator::isNormBelowBound` and in `Signer::shortVector`. No test reached the saturation of the two copies, and three of their mutants survived. `SignatureNorm::saturatedSquaredNorm` is now the one owner, and `saturatedSquaredNormIsTheSumBelow2To31AndElseSaturates` tests both sides of the saturation.
- **Rule.** A survivor in a copy of a decision is the finding of section 2.3 of `standards.md`. Move the decision to one owner and test the owner.

## A sticky bit differs from its mutant only at a tie

- **Trap.** An or of two words, or of a word and its negation, that sets a sticky bit or tests for zero gives the same bit as an exclusive or, except when the two words are equal or the word is `2^31`. Random operands never meet these ties.
- **Finding.** In `FloatingPoint.rs`, the sticky bit of a product, `z0 | z1`, and the sticky bit of the dropped bits of a rounding, at lines 117 and 118 of the first Falcon run, survived 20000 random products and conversions. Products whose low limbs are equal, which a C search found, and values with one dropped bit at each position kill the three mutants. The limb comparisons of `GaussianSampler::halfGaussian` survived in the same way, and values next to each table value kill them.
- **Rule.** For each sticky bit, zero test and limb comparison, the tests include the inputs at its ties: equal limbs, a single set bit at each position, and the values next to each bound.

## A zip with a longer slice hides a wrong end of the range

- **Trap.** A helper that zips two slices, such as `add` of `PackedVectors.rs` in MAYO, stops at the shorter one. A mutant that makes the range of the target longer changes nothing, and it survives.
- **Finding.** In `quadraticForms` of MAYO, `start * limbCount` in place of `start + limbCount` survived the first run of `oqs-native-mayo`. The range started at the same word and was longer. For the element 0 it was empty, and the bin 0 is the one bin that no line reads.
- **Rule.** Take each entry of a list with the one helper that gives its exact range, such as `mutableEntry` of `MatrixProducts.rs`. A mutant of the range is then a mutant of the helper, and every use of the helper checks it.

## A remainder by 16 before a read of the low nibble gives an equivalent mutant

- **Trap.** `(x % 16) as u8` gives the low nibble of x. The mutant `(x + 16) as u8` keeps the low nibble, and a function that reads only the low nibble cannot tell the two apart.
- **Finding.** The top element of the right-hand side of MAYO goes only into `field::product`, which reads the bits 0 to 3 of its first factor. The mutant survived the first run of `oqs-native-mayo`.
- **Rule.** Take a nibble with `& 0x0F`. Its mutants `| 0x0F` and `^ 0x0F` change the low nibble.

## A stepped range with a count of its own hides a wrong end

- **Trap.** A loop over `(0..length).step_by(16)` that writes `16.min(length - start)` elements at each start gives the same writes when the end of the range is one or two too high. The extra start writes no element, or no extra start is a multiple of 16.
- **Finding.** In `systemMatrix` of MAYO, three mutants of the end of the range and of the count survived the first run of `oqs-native-mayo`. The one extra element of the count was in a column whose element is always zero.
- **Rule.** Walk a slice of the exact length with `chunks_mut(16)`. A slice end that is too high then panics, or it writes into a place that a test checks.

## A branch of the C code that no input takes gives equivalent mutants

- **Trap.** A mutant of a guard that never fires survives every test, and no test can reach the guard.
- **Finding.** The `goto done` of `crypto_sort_int32`, the lines 109 to 112 of `SortingNetwork.rs`, never runs. The loop of line 108 runs only when `i < j = n - 2q < i + p`, and then `j` reaches `i + p` before `n - q`. The two mutants of the branch survived the run of the sorting network.
- **Rule.** Keep the branch as the C code has it. Prove from the invariant of the loop that it never runs, and record its mutants as equivalent with that invariant.

## Extra comparisons that change nothing give an equivalent sorting network

- **Trap.** A mutant of the loop control of a sorting network adds or repeats comparisons. Every sorting network gives the one sorted list, so neither a test of the output nor a random input can tell whether the mutant is equivalent.
- **Finding.** Three mutants of `SortingNetwork::sortWith` passed every test. One repeats merges, and two add merges at the high places of a pass. For an input of zeros and ones, a pass of the merge exchange only raises the values at its low places and only lowers the values at its high places, so each extra merge compares two values that are already in order, and a repeated merge finds its chain as the first merge left it.
- **Rule.** Compare the list of comparisons of the mutant with the list of the network, which depends only on the length, and prove with inputs of zeros and ones that each extra comparison changes nothing. A comparison commutes with each threshold of the values, so the proof holds for every input.

## A reduction by estimated quotients stays exact with other estimates

- **Trap.** A mutant that changes the estimate of a quotient in a reduction such as `Fq_freeze` survives every test of the residues, because the later steps correct a worse estimate.
- **Finding.** Seven of the nine mutants of the constants `q16`, `q20` and `q28` of `ModularReduction::residueModuloModulus` give the centered residue for every input up to `2^31 / 14`, the limit of the 32-bit products of the C code. The other two, with `q16` of 13 and 16, give it for every input of the callers, which stay below `2 * 2295^2`, but their products overflow 32 bits from 105412007 and from 77901825 in absolute value.
- **Rule.** Test a reduction up to the limit of the integer type of the C code as well as over the inputs of its callers. Record a mutant that stays exact over the whole range as equivalent, with the bound that each step leaves.

## A mutant stopped by the memory cap can count as a timeout

- **Trap.** A mutant whose loop fills a list reaches the memory cap of the `Mutants` workflow, and the run reports a timeout in place of a failed test. A reading of the log that looks only for a failed test or a panic puts the mutant among the timeouts with no failure.
- **Finding.** The four mutants of the byte loop of `RadixEncoding::encode` of NTRU Prime printed "memory allocation of 2147483648 bytes failed" in CI, and their test programs had not ended at the limit of 10 seconds. Applied by hand under the same cap, each test program stopped with SIGABRT.
- **Rule.** Read the log of each timeout for "memory allocation of". The cap stopped such a mutant. Count it with the timeouts, as the run reports it, and say in the register that the cap stopped it.

## A stack for the whole tree hides a mutant when the program builds only subtrees

- **Trap.** The stack of a tree hash without recursion needs one place more than the height of the tree. When the program asks only for subtrees below the full height, the mutant that removes that place survives every test through the program.
- **Finding.** `FORS::sign` of SLH-DSA asks for the FORS nodes of the heights from 0 to a - 1, which need at most 14 places. With 14 places in place of 15, every test of the crate passed, because only a whole tree of height 14 needs the 15th place. `fors_node` of the C code takes every height up to a. `nodesOfEveryHeightUpToAWholeTreeAreTheNodesOfTheCFunction` builds a whole tree of height 14 and kills the mutant. The stack of `Hypertree::xmssNode` needs no such test, because a key pair builds the whole top tree.
- **Rule.** The known-answer test of a tree hash builds every height that its definition accepts, up to a whole tree of the largest height, with the answer of the C function. This is the rule of "An input that the caller never gives hides a mutant" for the size of a buffer.

## A remainder that is its own negative hides a changed sign

- **Trap.** A formula over the constants of the parameter sets, such as `(8 - (x & 7)) & 7`, gives the same value with `+` in place of `-` when `x & 7` is 0 or 4. These two values are their own negatives modulo 8, so the mutant survives every test.
- **Finding.** The WOTS+ checksum of SLH-DSA is shifted by `(8 - ((len_2 lg_w) & 7)) & 7`, the formula of FIPS 205 and of `wots_csum` of the C code. `len_2 lg_w` is 12 in every set, so the shift is 4 with either operator, and the mutant of `Hypertree::chainDigits` survived the CI run.
- **Rule.** Compute the value of each mutant of a formula over the constants of the sets, for every set, before you write a test. When a mutant keeps the value, record it as equivalent with the values on both sides, as for a small change of the dividend of an integer division.

## A deliberate defect can be equivalent to the code

- **Trap.** A test that passes against a deliberate defect looks too weak, when the defect changes nothing.
- **Finding.** The first defect of the 3-bit padding check of CROSS used the mask `(0xFF << (n * 3)) & 0xFF`. For the 3 or 7 values after the last group of 8 in the RSDP sets, the shift is 9 or 21 bits, so this mask is zero as well, and every test passed. The mask `0xFF << (3 n mod 8)` of the real padding bits failed three tests.
- **Rule.** Before a deliberate defect judges a test, check that the defect changes what the code computes, for example with the values of the changed expression for the inputs of the tests.

## A guard that no caller trips needs a test that trips it

- **Trap.** An assertion that checks the shapes of the arguments of an internal function never fails in a test, because every caller passes the right shapes. The mutant that replaces the body of the check with `()` passes every test.
- **Finding.** The CI run of `oqs-native-uov` missed `BatchedMatrix::checkShapes` replaced with `()`. Without the check, `addTriangleProduct` takes a triangle that is one entry short and a target that is one entry long with no panic. `aTargetOfAnotherShapeIsRefused` and `aTriangleOfAnotherShapeIsRefused` each break one of the two assertions alone, and both failed with the mutant.
- **Rule.** Give each assertion of a guard a test with `#[should_panic(expected = ...)]`, the message of that assertion and an input that breaks that assertion alone. The message keeps a panic of another kind, such as an index out of range, from passing the test. `bytesOfAnotherShapeAreRefused` in `OilMatrix.rs` of UOV is the template.

## A capacity request outside `with_capacity` gives equivalent mutants

- **Trap.** A mutant of the size that `reserve_exact` requests changes only the capacity of the vector. The bytes stay the same, and every test passes.
- **Finding.** The CI run of `oqs-native-uov` missed `+` replaced with `*` and with `-` in `signature.reserve_exact(oilValues.len() + saltLength)` of `Signer::signature`. By default cargo-mutants 27.1.0 makes no mutant in the arguments of a call named `with_capacity`, through its setting `skip_calls`, so `Vec::with_capacity(publicSeedLength + oilBlock.len())` in `KeyGenerator::compressedPublicKey` gave no mutant. The tool mutates the arguments of `reserve_exact`.
- **Rule.** Make a new vector of a known length with `Vec::with_capacity`. For a request that grows a vector that exists, check that no changed request can panic, with no subtraction below zero in the test build and no request above the cap of the test program, and record the mutants as equivalent with the values on both sides.
