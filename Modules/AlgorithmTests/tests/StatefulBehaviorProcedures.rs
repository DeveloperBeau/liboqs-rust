//! Tests of the replicated stateful programs `tests/test_sig_stfl.c`,
//! `tests/fuzz_test_sig_stfl_xmss.c` and `tests/fuzz_test_sig_stfl_lms.c`: the C schemes pass
//! both programs, and a C scheme with each kind of fault fails at the step that the fault breaks.

use OQSNativeAlgorithmTests::{
    FuzzRandom, StatefulSignatureCorrectnessTest, StatefulSignatureFuzzTest, TestVectorFiles,
};
use OQSNativeCOracle::OracleStatefulScheme;
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, StatefulSignatureDescription};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The C schemes that pass both programs: one XMSS set, one XMSS^MT set, one LMS set and one LMS
/// set of two levels, each with trees of height 10 or less.
const passingSchemes: [&str; 4] = [
    "XMSS-SHA2_10_256",
    "XMSSMT-SHA2_20/2_256",
    "LMS_SHA256_H5_W1",
    "LMS_SHA256_H5_W8_H5_W8",
];

/// The scheme of the fault tests, whose key generation and signatures take milliseconds.
const fastScheme: &str = "LMS_SHA256_H5_W1";

/// The seed of the random source of the correctness program.
const correctnessSeed: u64 = 7;

/// The seed of the fuzz cases.
const fuzzSeed: u64 = 0x5EED;

/// How a C scheme goes wrong.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Fault {
    none,
    failsEveryKeyPair,
    failsEverySignature,
    rejectsEverySignature,
    refusesTheSecondVerification,
    acceptsEverySignature,
    checksHalfTheSignature,
    acceptsAShortSignature,
    acceptsAZeroSignatureOfItsLength,
    failsTheTotalCount,
    failsTheRemainingCount,
    savesTwice,
    savesTheKeyBeforeItAdvances,
    doesNotAdvance,
    corruptsTheAdvancedKey,
    releasesAfterAFailedSave,
    reportsAnotherErrorForAFailedSave,
    restoresTheKeyAfterAFailedSave,
    countsOneMoreRemaining,
    totalIsTheRemainingCount,
    countsTwoPerSignature,
    failsTheMessagesOfTheLockTest,
    rejectsTheMessagesOfTheLockTest,
    acceptsSignaturesOfAWrongLength,
    ignoresThePublicKey,
    signsWhenTheCLibraryRefuses,
}

/// A store that keeps nothing, for the inner signatures of a faulty scheme.
struct DiscardingStore;

impl KeyStatePersisting for DiscardingStore {
    fn persist(&mut self, _: &[u8]) -> Result<(), OQSError> {
        Ok(())
    }
}

/// A C scheme with one fault, under the description of the C scheme or a changed copy.
struct FaultyScheme {
    inner: OracleStatefulScheme,
    description: &'static StatefulSignatureDescription,
    fault: Fault,
    verificationCount: AtomicUsize,
    /// The last signature of the scheme, for the fault that checks only half of a signature.
    lastSignature: Mutex<Vec<u8>>,
    /// The first public key of a verification, for the fault that ignores the public key.
    firstPublicKey: Mutex<Option<Vec<u8>>>,
}

impl FaultyScheme {
    fn new(name: &str, fault: Fault) -> Self {
        let inner = OracleStatefulScheme::named(name).expect("a C scheme");
        let description = inner.description();
        Self::described(inner, description, fault)
    }

    /// A C scheme under a changed copy of its description.
    fn changed(
        name: &str,
        fault: Fault,
        change: impl FnOnce(&mut StatefulSignatureDescription),
    ) -> Self {
        let inner = OracleStatefulScheme::named(name).expect("a C scheme");
        let mut description = *inner.description();
        change(&mut description);
        // A test makes a few schemes, so each description lives for the rest of the process, as
        // the trait asks.
        Self::described(inner, Box::leak(Box::new(description)), fault)
    }

    fn described(
        inner: OracleStatefulScheme,
        description: &'static StatefulSignatureDescription,
        fault: Fault,
    ) -> Self {
        FaultyScheme {
            inner,
            description,
            fault,
            verificationCount: AtomicUsize::new(0),
            lastSignature: Mutex::new(Vec::new()),
            firstPublicKey: Mutex::new(None),
        }
    }

    fn isLockTestMessage(message: &[u8]) -> bool {
        message.starts_with(b"The quick brown fox")
    }
}

impl StatefulSigning for FaultyScheme {
    fn description(&self) -> &'static StatefulSignatureDescription {
        self.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        if self.fault == Fault::failsEveryKeyPair {
            return Err(OQSError::operationFailed);
        }
        self.inner.generateKeyPair(random)
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &mut SecretBytes,
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        let lockTestFailure =
            self.fault == Fault::failsTheMessagesOfTheLockTest && Self::isLockTestMessage(message);
        if self.fault == Fault::failsEverySignature || lockTestFailure {
            return Err(OQSError::operationFailed);
        }
        let before = secretKey.clone();
        let signature = match self.fault {
            Fault::savesTwice => {
                let signature = self.inner.sign(message, secretKey, persisting)?;
                persisting.persist(secretKey.bytes())?;
                signature
            }
            Fault::savesTheKeyBeforeItAdvances => {
                persisting.persist(before.bytes())?;
                self.inner.sign(message, secretKey, &mut DiscardingStore)?
            }
            Fault::doesNotAdvance => {
                let mut copy = before.clone();
                let signature = self.inner.sign(message, &mut copy, &mut DiscardingStore)?;
                self.releaseSignature(signature, before.bytes(), persisting)?
            }
            Fault::corruptsTheAdvancedKey => {
                let signature = self.inner.sign(message, secretKey, &mut DiscardingStore)?;
                // Byte 20 is in the seed of the private key of LMS.
                secretKey.mutableBytes()[20] ^= 1;
                self.releaseSignature(signature, secretKey.bytes(), persisting)?
            }
            Fault::releasesAfterAFailedSave => {
                let signature = self.inner.sign(message, secretKey, &mut DiscardingStore)?;
                let _ = persisting.persist(secretKey.bytes());
                signature
            }
            Fault::reportsAnotherErrorForAFailedSave => self
                .inner
                .sign(message, secretKey, persisting)
                .map_err(|error| match error {
                    OQSError::persistenceFailed => OQSError::operationFailed,
                    other => other,
                })?,
            Fault::restoresTheKeyAfterAFailedSave => {
                match self.inner.sign(message, secretKey, persisting) {
                    Err(OQSError::persistenceFailed) => {
                        *secretKey = before;
                        return Err(OQSError::persistenceFailed);
                    }
                    other => other?,
                }
            }
            Fault::signsWhenTheCLibraryRefuses => self
                .inner
                .sign(message, secretKey, persisting)
                .unwrap_or_else(|_| vec![0u8; self.description.signatureLength]),
            _ => self.inner.sign(message, secretKey, persisting)?,
        };
        *self.lastSignature.lock().expect("the last signature") = signature.clone();
        Ok(signature)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        let count = self.verificationCount.fetch_add(1, Ordering::SeqCst);
        let length = self.description.signatureLength;
        match self.fault {
            Fault::rejectsEverySignature => false,
            Fault::acceptsEverySignature => true,
            Fault::refusesTheSecondVerification if count == 1 => false,
            Fault::rejectsTheMessagesOfTheLockTest if Self::isLockTestMessage(message) => false,
            Fault::acceptsAShortSignature if signature.len() < length => true,
            Fault::acceptsAZeroSignatureOfItsLength
                if signature.len() == length && signature.iter().all(|byte| *byte == 0) =>
            {
                true
            }
            Fault::acceptsSignaturesOfAWrongLength if signature.len() != length => true,
            Fault::checksHalfTheSignature => {
                // The second half of a signature whose first half is that of the last signature
                // counts as the second half of the last signature.
                let last = self
                    .lastSignature
                    .lock()
                    .expect("the last signature")
                    .clone();
                let half = last.len() / 2;
                let checked = if signature.len() == last.len() && signature[..half] == last[..half]
                {
                    &last[..]
                } else {
                    signature
                };
                self.inner.isValidSignature(checked, message, publicKey)
            }
            Fault::ignoresThePublicKey => {
                let mut first = self.firstPublicKey.lock().expect("the first public key");
                let key = first.get_or_insert_with(|| publicKey.to_vec()).clone();
                self.inner.isValidSignature(signature, message, &key)
            }
            _ => self.inner.isValidSignature(signature, message, publicKey),
        }
    }

    fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        let remaining = self.inner.remainingSignatureCount(secretKey)?;
        match self.fault {
            Fault::failsTheRemainingCount => Err(OQSError::operationFailed),
            Fault::countsOneMoreRemaining => Ok(remaining + 1),
            Fault::countsTwoPerSignature => {
                let total = self.inner.totalSignatureCount(secretKey)?;
                Ok((2 * remaining).saturating_sub(total))
            }
            _ => Ok(remaining),
        }
    }

    fn totalSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        match self.fault {
            Fault::failsTheTotalCount => Err(OQSError::operationFailed),
            Fault::totalIsTheRemainingCount => self.inner.remainingSignatureCount(secretKey),
            _ => self.inner.totalSignatureCount(secretKey),
        }
    }
}

/// The response file of a scheme in the liboqs source of the oracle.
fn responseFile(name: &str) -> String {
    TestVectorFiles::responseFile(name).unwrap_or_else(|message| panic!("{message}"))
}

/// Runs the correctness program with the seed of the tests, and with the response file for an
/// XMSS name, as `test_cmdline.py` of liboqs runs `test_sig_stfl`.
fn correctness(scheme: &dyn StatefulSigning, responseFileName: &str) -> Result<(), String> {
    let file = scheme
        .description()
        .name
        .contains("XMSS")
        .then(|| responseFile(responseFileName));
    StatefulSignatureCorrectnessTest::run(
        scheme,
        &mut FuzzRandom::seeded(correctnessSeed),
        file.as_deref(),
    )
}

fn fastCorrectness(fault: Fault) -> Result<(), String> {
    correctness(&FaultyScheme::new(fastScheme, fault), fastScheme)
}

#[test]
fn theCSchemesPassTheCorrectnessProgram() {
    for name in passingSchemes {
        let scheme = OracleStatefulScheme::named(name).expect("a C scheme");
        assert_eq!(
            correctness(&scheme, name),
            Ok(()),
            "{name}, seed {correctnessSeed}"
        );
    }
}

#[test]
fn theCSchemesPassTheFuzzProgram() {
    for name in passingSchemes {
        let scheme = OracleStatefulScheme::named(name).expect("a C scheme");
        assert_eq!(
            StatefulSignatureFuzzTest::run(&scheme, &responseFile(name), fuzzSeed, 20),
            Ok(()),
            "{name}, seed {fuzzSeed:#x}"
        );
    }
}

#[test]
fn theCorrectnessProgramReportsEachFailingStepOfTheSignature() {
    assert_eq!(
        fastCorrectness(Fault::failsEveryKeyPair),
        Err("LMS_SHA256_H5_W1: the key pair failed: the operation failed".to_string())
    );
    assert_eq!(
        fastCorrectness(Fault::failsEverySignature),
        Err("LMS_SHA256_H5_W1: the signature failed: the operation failed".to_string())
    );
    assert_eq!(
        fastCorrectness(Fault::rejectsEverySignature),
        Err("LMS_SHA256_H5_W1: the signature does not verify".to_string())
    );
    assert_eq!(
        fastCorrectness(Fault::refusesTheSecondVerification),
        Err(
            "LMS_SHA256_H5_W1: the signature does not verify with the stored public key"
                .to_string()
        )
    );
}

/// A random source that records the length of each request.
struct RecordingRandom {
    inner: FuzzRandom,
    requestLengths: Vec<usize>,
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.requestLengths.push(bytes.len());
        self.inner.fillRandomBytes(bytes);
    }
}

/// A separate model of the random words that the correctness program draws before its bit
/// flips: SplitMix64 from the seed gives the 100 bytes of the message in 13 words, then the
/// requests of the C key generation, which the model records, one word for each 8 bytes or part
/// of 8 bytes. Returns the source after those words.
fn randomAtTheFirstFlip() -> FuzzRandom {
    let mut recording = RecordingRandom {
        inner: FuzzRandom::seeded(0),
        requestLengths: Vec::new(),
    };
    OracleStatefulScheme::named(fastScheme)
        .expect("a C scheme")
        .generateKeyPair(&mut recording)
        .expect("key pair");
    let keyPairWords: usize = recording
        .requestLengths
        .iter()
        .map(|length| length.div_ceil(8))
        .sum();
    let mut random = FuzzRandom::seeded(correctnessSeed);
    for _ in 0..13 + keyPairWords {
        random.nextWord();
    }
    random
}

#[test]
fn theCorrectnessProgramReportsTheFirstAcceptedBitFlipOfTheMessage() {
    // The first flip draws the next word, read as a little-endian `u64`, modulo the 800 bits of
    // the message.
    let bit = randomAtTheFirstFlip().nextWord() % 800;
    assert_eq!(
        fastCorrectness(Fault::acceptsEverySignature),
        Err(format!(
            "LMS_SHA256_H5_W1: the verification accepts the message with bit {bit} flipped"
        ))
    );
}

#[test]
fn theCorrectnessProgramFlipsTheSignatureOnlyForAnSUFCMAScheme() {
    let strong = FaultyScheme::changed(fastScheme, Fault::checksHalfTheSignature, |description| {
        description.isSUFCMASecure = true
    });
    let signatureBits = 8 * strong.description().signatureLength as u64;
    // The 50 message flips are refused, and the first signature flip in the second half of the
    // bits is accepted.
    let mut random = randomAtTheFirstFlip();
    for _ in 0..StatefulSignatureCorrectnessTest::bitFlipCount {
        random.nextWord();
    }
    let bit = (0..StatefulSignatureCorrectnessTest::bitFlipCount)
        .map(|_| random.nextWord() % signatureBits)
        .find(|bit| *bit >= signatureBits / 2)
        .expect("a flip in the second half");
    assert_eq!(
        correctness(&strong, fastScheme),
        Err(format!(
            "LMS_SHA256_H5_W1: the verification accepts the signature with bit {bit} flipped"
        ))
    );
    // The C scheme claims EUF-CMA only, so the program flips no bit of its signature.
    assert_eq!(fastCorrectness(Fault::checksHalfTheSignature), Ok(()));
    // The false negative side: the correct C scheme refuses each flip of its signature.
    let correctStrong = FaultyScheme::changed(fastScheme, Fault::none, |description| {
        description.isSUFCMASecure = true
    });
    assert_eq!(correctness(&correctStrong, fastScheme), Ok(()));
}

#[test]
fn theInvalidSignatureTestRunsForXMSSAndReportsEachAcceptedSignature() {
    let xmss = "XMSS-SHA2_10_256";
    assert_eq!(
        correctness(
            &FaultyScheme::new(xmss, Fault::acceptsAShortSignature),
            xmss
        ),
        Err("XMSS-SHA2_10_256: the verification accepts a signature of 10 bytes".to_string())
    );
    assert_eq!(
        correctness(
            &FaultyScheme::new(xmss, Fault::acceptsAZeroSignatureOfItsLength),
            xmss
        ),
        Err("XMSS-SHA2_10_256: the verification accepts a zero signature for a zero public key with the object identifier 2".to_string())
    );
    // The C program runs `test_invalid_sig` for XMSS names only.
    assert_eq!(fastCorrectness(Fault::acceptsAShortSignature), Ok(()));
    assert_eq!(
        fastCorrectness(Fault::acceptsAZeroSignatureOfItsLength),
        Ok(())
    );
}

#[test]
fn theSecretKeyTestReportsEachBrokenRuleOfTheSavedKey() {
    let cases = [
        (
            Fault::failsTheTotalCount,
            "the total count failed: the operation failed",
        ),
        (
            Fault::failsTheRemainingCount,
            "the remaining count failed: the operation failed",
        ),
        (
            Fault::savesTwice,
            "the signature comes back with 2 saved keys, not one",
        ),
        (
            Fault::savesTheKeyBeforeItAdvances,
            "the saved key differs from the key in memory",
        ),
        (
            Fault::doesNotAdvance,
            "the key in memory does not change with a signature",
        ),
        (
            Fault::corruptsTheAdvancedKey,
            "the signature of the reloaded key does not verify",
        ),
        (
            Fault::releasesAfterAFailedSave,
            "a refused save releases a signature",
        ),
        (
            Fault::reportsAnotherErrorForAFailedSave,
            "a refused save gives the error \"the operation failed\", not the persistence error",
        ),
        (
            Fault::restoresTheKeyAfterAFailedSave,
            "the key in memory does not change after a refused save",
        ),
    ];
    for (fault, message) in cases {
        assert_eq!(
            fastCorrectness(fault),
            Err(format!("LMS_SHA256_H5_W1: {message}")),
            "{fault:?}"
        );
    }
}

#[test]
fn theSignatureGenerationTestReportsEachWrongCountAndSignature() {
    let cases = [
        (
            Fault::countsOneMoreRemaining,
            "a new key has 32 signatures left of 31",
        ),
        (
            Fault::totalIsTheRemainingCount,
            "the total count changes from 31 to 30 with a signature",
        ),
        (
            Fault::countsTwoPerSignature,
            "the remaining count goes from 31 to 29 with a signature",
        ),
        (
            Fault::failsTheMessagesOfTheLockTest,
            "the signature of message 1 failed: the operation failed",
        ),
        (
            Fault::rejectsTheMessagesOfTheLockTest,
            "the signature of message 1 does not verify",
        ),
    ];
    for (fault, message) in cases {
        assert_eq!(
            fastCorrectness(fault),
            Err(format!("LMS_SHA256_H5_W1: {message}")),
            "{fault:?}"
        );
    }
}

#[test]
fn aSlowXMSSSetTakesItsKeyPairFromTheResponseFile() {
    // The C scheme of height 10 under the name of a set of height 16, whose key pair the C
    // program reads from the response file. The key generation of the scheme fails, so the run
    // passes only if every key pair comes from the file.
    let slow = FaultyScheme::changed(
        "XMSS-SHA2_10_256",
        Fault::failsEveryKeyPair,
        |description| description.name = "XMSS-SHA2_16_256",
    );
    let file = responseFile("XMSS-SHA2_10_256");
    let run = |file: Option<&str>| {
        StatefulSignatureCorrectnessTest::run(&slow, &mut FuzzRandom::seeded(correctnessSeed), file)
    };
    assert_eq!(run(Some(&file)), Ok(()));
    assert_eq!(
        run(Some(&file.replace("sk = ", "sx = "))),
        Err("XMSS-SHA2_16_256: unable to read 'sk' from the response file".to_string())
    );
    assert_eq!(
        run(Some(&file.replace("pk = ", "px = "))),
        Err("XMSS-SHA2_16_256: unable to read 'pk' from the response file".to_string())
    );
    assert_eq!(
        run(None),
        Err("XMSS-SHA2_16_256: a response file must be provided for XMSS".to_string())
    );
    // Any other set generates its key pairs, also with a response file.
    assert_eq!(
        correctness(
            &FaultyScheme::new("XMSS-SHA2_10_256", Fault::failsEveryKeyPair),
            "XMSS-SHA2_10_256"
        ),
        Err("XMSS-SHA2_10_256: the key pair failed: the operation failed".to_string())
    );
}

fn fuzz(fault: Fault) -> Result<(), String> {
    StatefulSignatureFuzzTest::run(
        &FaultyScheme::new(fastScheme, fault),
        &responseFile(fastScheme),
        fuzzSeed,
        3,
    )
}

#[test]
fn theFuzzProgramReportsEachAcceptedHostileInputWithTheCaseAndTheSeed() {
    assert_eq!(
        fuzz(Fault::rejectsEverySignature),
        Err("LMS_SHA256_H5_W1: the signature of the response file does not verify".to_string())
    );
    // Case 0 has the field selector 0 and writes zeros in the order 0, over the public key of 56
    // bytes, the signature of 8688 bytes and the message, as far as the length of its input
    // reaches.
    let file = responseFile(fastScheme);
    let messageLength = file
        .lines()
        .find_map(|line| line.strip_prefix("msg = "))
        .expect("a message")
        .len()
        / 2;
    let length =
        FuzzRandom::hostile(fuzzSeed, 0).nextWord() % (56 + 8688 + messageLength as u64 + 1);
    assert_eq!(
        fuzz(Fault::acceptsEverySignature),
        Err(format!(
            "LMS_SHA256_H5_W1, fuzz case 0 of seed 0x5eed: the verification accepts the values of the file with {length} fuzz bytes written over them with the field selector 0"
        ))
    );
    let wrongLength = FuzzRandom::wrongLength(0, 8688);
    assert_eq!(
        fuzz(Fault::acceptsSignaturesOfAWrongLength),
        Err(format!(
            "LMS_SHA256_H5_W1, fuzz case 0 of seed 0x5eed: the verification accepts a hostile signature of {wrongLength} bytes"
        ))
    );
    assert_eq!(
        fuzz(Fault::ignoresThePublicKey),
        Err(
            "LMS_SHA256_H5_W1, fuzz case 0 of seed 0x5eed: the verification accepts a hostile public key of 60 bytes"
                .to_string()
        )
    );
    assert_eq!(
        fuzz(Fault::signsWhenTheCLibraryRefuses),
        Err(
            "LMS_SHA256_H5_W1, fuzz case 0 of seed 0x5eed: a signature with a hostile secret key of 64 bytes comes back without its saved key"
                .to_string()
        )
    );
}
