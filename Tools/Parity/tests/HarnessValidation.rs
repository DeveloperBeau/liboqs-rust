//! Validation of the parity harness and of the known-answer harness, before any Rust family
//! depends on them.
//!
//! False positive validation: the C algorithms themselves, behind the Rust interfaces, pass
//! every check. False negative validation: each kind of defect in a mechanism or a scheme is
//! reported at its own step.

use OQSNativeAlgorithmTests::{
    KEMKnownAnswerTest, KnownAnswerDigests, SignatureKnownAnswerTest, StatefulTreeHeight,
    SuiteSample,
};
use OQSNativeCOracle::{
    COracle, OracleMechanism, OracleRandomness, OracleSignatureScheme, OracleStatefulScheme,
};
use OQSNativeDomain::{
    KeyEncapsulating, KeyStatePersisting, RandomGenerating, Signing, StatefulSigning,
};
use OQSNativeEntities::{
    Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes, SignatureDescription,
    StatefulSignatureDescription,
};
use OQSNativeParity::{
    KEMParity, LargeStack, ParityJob, ParityMismatch, ParityOptions, ParitySettings,
    SignatureParity, StatefulParity,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const caseCount: u64 = 3;

fn mechanism(name: &str) -> OracleMechanism {
    OracleMechanism::named(name).unwrap_or_else(|| panic!("the C library has {name}"))
}

fn scheme(name: &str) -> OracleSignatureScheme {
    OracleSignatureScheme::named(name).unwrap_or_else(|| panic!("the C library has {name}"))
}

fn statefulScheme(name: &str) -> OracleStatefulScheme {
    OracleStatefulScheme::named(name).unwrap_or_else(|| panic!("the C library has {name}"))
}

#[test]
fn cMechanismsPassEveryKEMCheck() {
    LargeStack::run(|| {
        for name in [
            "ML-KEM-512",
            "ML-KEM-768",
            "Kyber512",
            "HQC-1",
            "BIKE-L1",
            "FrodoKEM-640-SHAKE",
            "eFrodoKEM-640-AES",
            "sntrup761",
            "NTRU-HPS-2048-509",
            "Classic-McEliece-348864",
        ] {
            let result = KEMParity::new(&mechanism(name), ParitySettings::defaultSeed)
                .checkEveryCase(caseCount);
            assert_eq!(result, Ok(()), "{name}");
        }
    });
}

#[test]
fn cSchemesPassEverySignatureCheck() {
    LargeStack::run(|| {
        for name in [
            "ML-DSA-44",
            "Falcon-512",
            "Falcon-padded-512",
            "SLH_DSA_PURE_SHA2_128F",
            "MAYO-1",
            "cross-rsdp-128-fast",
            "OV-Is",
            "SNOVA_24_5_4",
            "mqom2_cat1_gf16_fast_r3",
        ] {
            let result = SignatureParity::new(&scheme(name), ParitySettings::defaultSeed)
                .checkEveryCase(caseCount);
            assert_eq!(result, Ok(()), "{name}");
        }
    });
}

/// The defects that a broken mechanism can have.
#[derive(Clone, Copy, PartialEq)]
enum KEMDefect {
    keyPairFails,
    publicKeyByte,
    randomRequestSplit,
    ciphertextByte,
    wrongRecoveredSecret,
    fixedRejectionSecret,
    acceptsShortCiphertext,
    noSeededForm,
}

/// A C mechanism with one defect.
struct BrokenMechanism {
    inner: OracleMechanism,
    defect: KEMDefect,
    /// The ciphertext of the last encapsulation, so that the rejection defect can tell its own
    /// ciphertexts from changed ones.
    lastCiphertext: Mutex<Vec<u8>>,
}

impl BrokenMechanism {
    fn new(name: &str, defect: KEMDefect) -> Self {
        BrokenMechanism {
            inner: mechanism(name),
            defect,
            lastCiphertext: Mutex::new(Vec::new()),
        }
    }
}

/// Splits each request in two, which changes the output of the NIST DRBG.
struct SplittingRandom<'random> {
    inner: &'random mut dyn RandomGenerating,
}

impl RandomGenerating for SplittingRandom<'_> {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        let (first, second) = bytes.split_at_mut(bytes.len() / 2);
        self.inner.fillRandomBytes(first);
        self.inner.fillRandomBytes(second);
    }
}

impl KeyEncapsulating for BrokenMechanism {
    fn description(&self) -> &'static KEMDescription {
        self.inner.description()
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        if self.defect == KEMDefect::keyPairFails {
            return Err(OQSError::operationFailed);
        }
        if self.defect == KEMDefect::randomRequestSplit {
            return self
                .inner
                .generateKeyPair(&mut SplittingRandom { inner: random });
        }
        let mut keyPair = self.inner.generateKeyPair(random)?;
        if self.defect == KEMDefect::publicKeyByte {
            keyPair.publicKey[3] ^= 0x10;
        }
        Ok(keyPair)
    }

    fn generateKeyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, OQSError> {
        if self.defect == KEMDefect::noSeededForm {
            return Err(OQSError::seedNotSupported);
        }
        self.inner.generateKeyPairFromSeed(seed)
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        let mut encapsulation = self.inner.encapsulate(publicKey, random)?;
        if self.defect == KEMDefect::ciphertextByte {
            let last = encapsulation.ciphertext.len() - 1;
            encapsulation.ciphertext[last] ^= 1;
        }
        *self.lastCiphertext.lock().expect("the lock") = encapsulation.ciphertext.clone();
        Ok(encapsulation)
    }

    fn encapsulateWithSeed(
        &self,
        publicKey: &[u8],
        seed: &[u8],
    ) -> Result<Encapsulation, OQSError> {
        self.inner.encapsulateWithSeed(publicKey, seed)
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let expected = self.description().ciphertextLength;
        if self.defect == KEMDefect::acceptsShortCiphertext && ciphertext.len() + 1 == expected {
            return Ok(SecretBytes::zeroed(self.description().sharedSecretLength));
        }
        let secret = self.inner.decapsulate(ciphertext, secretKey)?;
        match self.defect {
            KEMDefect::wrongRecoveredSecret => {
                let mut bytes = secret.bytes().to_vec();
                bytes[0] ^= 0x80;
                Ok(SecretBytes::new(bytes))
            }
            KEMDefect::fixedRejectionSecret => {
                // The right secret for the last ciphertext of the mechanism, and zero for any
                // other ciphertext in place of the implicit-rejection secret.
                if *self.lastCiphertext.lock().expect("the lock") == ciphertext {
                    Ok(secret)
                } else {
                    Ok(SecretBytes::zeroed(secret.bytes().len()))
                }
            }
            _ => Ok(secret),
        }
    }
}

fn firstKEMMismatchStep(defect: KEMDefect) -> &'static str {
    LargeStack::run(|| {
        let broken = BrokenMechanism::new("ML-KEM-768", defect);
        let mismatch = KEMParity::new(&broken, ParitySettings::defaultSeed)
            .checkCase(0)
            .expect_err("a broken mechanism fails");
        assert_eq!(mismatch.case, Some(0));
        assert_eq!(mismatch.algorithm, "ML-KEM-768");
        mismatch.step
    })
}

#[test]
fn aFailureOnOneSideIsAMismatchThatNamesTheSide() {
    LargeStack::run(|| {
        let broken = BrokenMechanism::new("ML-KEM-512", KEMDefect::keyPairFails);
        let mismatch = KEMParity::new(&broken, ParitySettings::defaultSeed)
            .checkCase(0)
            .expect_err("a failing mechanism fails");
        assert_eq!(mismatch.step, "key pair");
        assert_eq!(
            mismatch.detail,
            "the C key pair succeeds and the Rust one fails: the operation failed"
        );
        let brokenScheme = BrokenScheme {
            inner: scheme("ML-DSA-44"),
            defect: SignatureDefect::keyPairFails,
        };
        let mismatch = SignatureParity::new(&brokenScheme, ParitySettings::defaultSeed)
            .checkCase(0)
            .expect_err("a failing scheme fails");
        assert_eq!(
            (mismatch.step, mismatch.detail.as_str()),
            (
                "key pair",
                "the C key pair succeeds and the Rust one fails: the operation failed"
            )
        );
        let failingSigner = BrokenScheme {
            inner: scheme("ML-DSA-44"),
            defect: SignatureDefect::signingFails,
        };
        let mismatch = SignatureParity::new(&failingSigner, ParitySettings::defaultSeed)
            .checkCase(0)
            .expect_err("a failing scheme fails");
        assert_eq!(
            (mismatch.step, mismatch.detail.as_str()),
            (
                "signature",
                "C succeeds and Rust fails: the operation failed"
            )
        );
    });
}

#[test]
fn eachKEMDefectIsReportedAtItsStep() {
    assert_eq!(firstKEMMismatchStep(KEMDefect::publicKeyByte), "public key");
    // ML-KEM draws `d || z` in one request of 64 bytes. Two requests of 32 bytes give the same
    // `d`, so the same public key, and another `z`, which only the secret key holds.
    assert_eq!(
        firstKEMMismatchStep(KEMDefect::randomRequestSplit),
        "secret key"
    );
    assert_eq!(
        firstKEMMismatchStep(KEMDefect::ciphertextByte),
        "ciphertext"
    );
    assert_eq!(
        firstKEMMismatchStep(KEMDefect::wrongRecoveredSecret),
        "Rust decapsulation of the C ciphertext"
    );
    assert_eq!(
        firstKEMMismatchStep(KEMDefect::acceptsShortCiphertext),
        "decapsulation of a short ciphertext"
    );
    assert_eq!(
        firstKEMMismatchStep(KEMDefect::noSeededForm),
        "public key from a seed"
    );
}

#[test]
fn aWrongRejectionSecretIsReportedAtTheChangedCiphertext() {
    assert_eq!(
        firstKEMMismatchStep(KEMDefect::fixedRejectionSecret),
        "decapsulation of a changed ciphertext"
    );
    // The base case decapsulates only the ciphertext of the mechanism, so it passes.
    LargeStack::run(|| {
        let broken = BrokenMechanism::new("ML-KEM-512", KEMDefect::fixedRejectionSecret);
        assert_eq!(
            KEMParity::new(&broken, ParitySettings::defaultSeed).checkBaseCase(),
            Ok(())
        );
    });
}

#[test]
fn aKEMDefectInTheBaseCaseNamesTheSnapshotField() {
    LargeStack::run(|| {
        let broken = BrokenMechanism::new("ML-KEM-512", KEMDefect::ciphertextByte);
        let mismatch = KEMParity::new(&broken, ParitySettings::defaultSeed)
            .checkEveryCase(caseCount)
            .expect_err("a broken mechanism fails");
        assert_eq!((mismatch.case, mismatch.step), (None, "ct"));
    });
}

#[test]
fn aSignatureDefectInTheBaseCaseNamesTheSnapshotField() {
    LargeStack::run(|| {
        let broken = BrokenScheme {
            inner: scheme("ML-DSA-44"),
            defect: SignatureDefect::signatureByte,
        };
        let mismatch = SignatureParity::new(&broken, ParitySettings::defaultSeed)
            .checkEveryCase(caseCount)
            .expect_err("a broken scheme fails");
        assert_eq!((mismatch.case, mismatch.step), (None, "sig"));
    });
}

/// The defects that a broken scheme can have.
#[derive(Clone, Copy, PartialEq)]
enum SignatureDefect {
    keyPairFails,
    signingFails,
    signatureByte,
    plainSignatureByte,
    contextSignatureByte,
    ignoresContext,
    acceptsEverySignature,
    acceptsShortSignature,
    rejectsCSignatures,
}

/// A C scheme with one defect.
struct BrokenScheme {
    inner: OracleSignatureScheme,
    defect: SignatureDefect,
}

impl Signing for BrokenScheme {
    fn description(&self) -> &'static SignatureDescription {
        self.inner.description()
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        if self.defect == SignatureDefect::keyPairFails {
            return Err(OQSError::operationFailed);
        }
        self.inner.generateKeyPair(random)
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        if self.defect == SignatureDefect::signingFails {
            return Err(OQSError::operationFailed);
        }
        let mut signature = self.inner.sign(message, secretKey, random)?;
        if self.defect == SignatureDefect::signatureByte
            || self.defect == SignatureDefect::plainSignatureByte
        {
            signature[0] ^= 4;
        }
        Ok(signature)
    }

    fn signWithContext(
        &self,
        message: &[u8],
        context: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        if self.defect == SignatureDefect::signingFails {
            return Err(OQSError::operationFailed);
        }
        if self.defect == SignatureDefect::ignoresContext {
            return self.inner.signWithContext(message, &[], secretKey, random);
        }
        let mut signature = self
            .inner
            .signWithContext(message, context, secretKey, random)?;
        if self.defect == SignatureDefect::signatureByte
            || self.defect == SignatureDefect::contextSignatureByte
        {
            signature[0] ^= 4;
        }
        Ok(signature)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        let isShort = signature.len() + 1 == self.description().signatureLength;
        match self.defect {
            SignatureDefect::acceptsEverySignature => true,
            SignatureDefect::acceptsShortSignature if isShort => true,
            SignatureDefect::rejectsCSignatures => false,
            _ => self.inner.isValidSignature(signature, message, publicKey),
        }
    }

    fn isValidSignatureWithContext(
        &self,
        signature: &[u8],
        message: &[u8],
        context: &[u8],
        publicKey: &[u8],
    ) -> bool {
        let isShort = signature.len() + 1 == self.description().signatureLength;
        match self.defect {
            SignatureDefect::acceptsEverySignature => true,
            SignatureDefect::acceptsShortSignature if isShort => true,
            SignatureDefect::rejectsCSignatures => false,
            _ => self
                .inner
                .isValidSignatureWithContext(signature, message, context, publicKey),
        }
    }
}

/// The first step that reports a defect over a few cases of ML-DSA-44.
fn firstSignatureMismatchStep(defect: SignatureDefect) -> &'static str {
    LargeStack::run(|| {
        let broken = BrokenScheme {
            inner: scheme("ML-DSA-44"),
            defect,
        };
        let parity = SignatureParity::new(&broken, ParitySettings::defaultSeed);
        (0..20)
            .find_map(|case| parity.checkCase(case).err())
            .expect("a broken scheme fails in some case")
            .step
    })
}

#[test]
fn eachSignatureDefectIsReportedAtItsStep() {
    assert_eq!(
        firstSignatureMismatchStep(SignatureDefect::signatureByte),
        "signature"
    );
    // A defect of one form shows up, so the variations use both forms.
    assert_eq!(
        firstSignatureMismatchStep(SignatureDefect::plainSignatureByte),
        "signature"
    );
    assert_eq!(
        firstSignatureMismatchStep(SignatureDefect::contextSignatureByte),
        "signature"
    );
    assert_eq!(
        firstSignatureMismatchStep(SignatureDefect::acceptsShortSignature),
        "verification of a short signature"
    );
    assert_eq!(
        firstSignatureMismatchStep(SignatureDefect::ignoresContext),
        "signature"
    );
    assert_eq!(
        firstSignatureMismatchStep(SignatureDefect::rejectsCSignatures),
        "Rust verification of the C signature"
    );
    assert_eq!(
        firstSignatureMismatchStep(SignatureDefect::acceptsEverySignature),
        "verification of a changed signature"
    );
}

#[test]
fn cStatefulSchemesPassEveryStatefulCheck() {
    LargeStack::run(|| {
        for name in [
            "XMSS-SHA2_10_256",
            "XMSSMT-SHA2_20/2_256",
            "LMS_SHA256_H5_W1",
            "LMS_SHA256_H5_W8_H5_W8",
        ] {
            let result = StatefulParity::new(&statefulScheme(name), ParitySettings::defaultSeed)
                .checkEveryCase(caseCount);
            assert_eq!(result, Ok(caseCount), "{name}");
        }
    });
}

#[test]
fn aStatefulRunSignsAtMostTheRemainingCountOfTheKey() {
    // A new key of LMS_SHA256_H5_W1 has 31 signatures left. Its job says so, and a run of fewer
    // cases than the remaining count signs each case.
    let scheme = statefulScheme("LMS_SHA256_H5_W1");
    let statefulSchemes: [&dyn StatefulSigning; 1] = [&scheme];
    let summary = |cases: &str| {
        let options =
            ParityOptions::parse(&["--cases".to_string(), cases.to_string()]).expect("valid");
        let jobs = ParityJob::parityJobs(&[], &[], &statefulSchemes, &options);
        let lines = Mutex::new(Vec::new());
        assert_eq!(
            ParityJob::runAll(jobs, &|line| lines.lock().expect("lines").push(line)),
            0
        );
        lines.into_inner().expect("lines").join("\n")
    };
    let capped = summary("1000");
    assert!(
        capped.starts_with(
            "ok    LMS_SHA256_H5_W1 (base case and 31 of 1000 variations identical, the remaining count of the key, "
        ),
        "{capped}"
    );
    let full = summary("31");
    assert!(
        full.starts_with("ok    LMS_SHA256_H5_W1 (base case and 31 variations identical, "),
        "{full}"
    );
}

/// The defects that a broken stateful scheme can have.
#[derive(Clone, Copy, PartialEq, Debug)]
enum StatefulDefect {
    keyPairFails,
    publicKeyByte,
    secretKeyByte,
    totalCountsOneMore,
    signingFails,
    signatureByte,
    savesNoKey,
    advancedKeyByte,
    keepsTheKeyInMemory,
    rejectsCSignatures,
    acceptsEverySignature,
    acceptsAChangedMessage,
    acceptsShortSignature,
    countsOneMoreRemaining,
}

/// A store that keeps nothing, for the inner signatures of a broken scheme.
struct DiscardingStore;

impl KeyStatePersisting for DiscardingStore {
    fn persist(&mut self, _: &[u8]) -> Result<(), OQSError> {
        Ok(())
    }
}

/// A C stateful scheme with one defect.
struct BrokenStatefulScheme {
    inner: OracleStatefulScheme,
    defect: StatefulDefect,
    /// The message of the last signature, for the defect that verifies it in place of the
    /// message that it gets.
    lastMessage: Mutex<Vec<u8>>,
}

impl BrokenStatefulScheme {
    fn new(name: &str, defect: StatefulDefect) -> Self {
        BrokenStatefulScheme {
            inner: statefulScheme(name),
            defect,
            lastMessage: Mutex::new(Vec::new()),
        }
    }
}

impl StatefulSigning for BrokenStatefulScheme {
    fn description(&self) -> &'static StatefulSignatureDescription {
        self.inner.description()
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        if self.defect == StatefulDefect::keyPairFails {
            return Err(OQSError::operationFailed);
        }
        let mut keyPair = self.inner.generateKeyPair(random)?;
        match self.defect {
            StatefulDefect::publicKeyByte => keyPair.publicKey[3] ^= 0x10,
            StatefulDefect::secretKeyByte => {
                let last = keyPair.secretKey.bytes().len() - 1;
                keyPair.secretKey.mutableBytes()[last] ^= 1;
            }
            _ => {}
        }
        Ok(keyPair)
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &mut SecretBytes,
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        *self.lastMessage.lock().expect("the last message") = message.to_vec();
        match self.defect {
            StatefulDefect::signingFails => Err(OQSError::operationFailed),
            StatefulDefect::signatureByte => {
                let mut signature = self.inner.sign(message, secretKey, persisting)?;
                signature[0] ^= 4;
                Ok(signature)
            }
            StatefulDefect::savesNoKey => self.inner.sign(message, secretKey, &mut DiscardingStore),
            StatefulDefect::advancedKeyByte => {
                let signature = self.inner.sign(message, secretKey, &mut DiscardingStore)?;
                let last = secretKey.bytes().len() - 1;
                secretKey.mutableBytes()[last] ^= 1;
                self.releaseSignature(signature, secretKey.bytes(), persisting)
            }
            StatefulDefect::keepsTheKeyInMemory => {
                // The scheme saves the advanced key, but the key of the caller stays as it was.
                let mut advanced = secretKey.clone();
                self.inner.sign(message, &mut advanced, persisting)
            }
            _ => self.inner.sign(message, secretKey, persisting),
        }
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        let isShort = signature.len() + 1 == self.description().signatureLength;
        match self.defect {
            StatefulDefect::rejectsCSignatures => false,
            StatefulDefect::acceptsEverySignature => true,
            StatefulDefect::acceptsShortSignature if isShort => true,
            StatefulDefect::acceptsAChangedMessage => {
                let lastMessage = self.lastMessage.lock().expect("the last message").clone();
                self.inner
                    .isValidSignature(signature, &lastMessage, publicKey)
            }
            _ => self.inner.isValidSignature(signature, message, publicKey),
        }
    }

    fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        let remaining = self.inner.remainingSignatureCount(secretKey)?;
        if self.defect == StatefulDefect::countsOneMoreRemaining {
            return Ok(remaining + 1);
        }
        Ok(remaining)
    }

    fn totalSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        let total = self.inner.totalSignatureCount(secretKey)?;
        if self.defect == StatefulDefect::totalCountsOneMore {
            return Ok(total + 1);
        }
        Ok(total)
    }
}

/// The first mismatch of a broken LMS_SHA256_H5_W1 over a few cases.
fn firstStatefulMismatch(defect: StatefulDefect) -> ParityMismatch {
    LargeStack::run(|| {
        let broken = BrokenStatefulScheme::new("LMS_SHA256_H5_W1", defect);
        let mismatch = StatefulParity::new(&broken, ParitySettings::defaultSeed)
            .checkEveryCase(caseCount)
            .expect_err("a broken scheme fails");
        assert_eq!(mismatch.algorithm, "LMS_SHA256_H5_W1");
        mismatch
    })
}

#[test]
fn theRustWorkingKeyOfLMSSignsInPlaceOfTheSchemeOnlyWhenTheCheckAsksForIt() {
    LargeStack::run(|| {
        // The registered set signs every case of a whole key with one working key.
        let registered = OQSNative::Registry::statefulSignatureScheme("LMS_SHA256_H5_W8")
            .expect("a registered set");
        assert_eq!(
            StatefulParity::new(registered, ParitySettings::defaultSeed)
                .signingLMSWithAWorkingKey()
                .checkEveryCase(1000),
            Ok(31)
        );
        // A scheme with a wrong signature byte fails the plain check, and the working key of
        // the registered set of its name signs in its place, so the defect does not show.
        let broken = BrokenStatefulScheme::new("LMS_SHA256_H5_W1", StatefulDefect::signatureByte);
        let plain = StatefulParity::new(&broken, ParitySettings::defaultSeed)
            .checkEveryCase(caseCount)
            .expect_err("a broken scheme fails");
        assert_eq!((plain.case, plain.step), (Some(0), "signature"));
        assert_eq!(
            StatefulParity::new(&broken, ParitySettings::defaultSeed)
                .signingLMSWithAWorkingKey()
                .checkEveryCase(caseCount),
            Ok(caseCount)
        );
    });
}

#[test]
fn eachStatefulDefectIsReportedAtItsStep() {
    let step = |defect| {
        let mismatch = firstStatefulMismatch(defect);
        (mismatch.case, mismatch.step)
    };
    assert_eq!(step(StatefulDefect::keyPairFails), (None, "Rust base case"));
    assert_eq!(step(StatefulDefect::publicKeyByte), (None, "pk"));
    assert_eq!(step(StatefulDefect::secretKeyByte), (None, "sk"));
    assert_eq!(
        step(StatefulDefect::totalCountsOneMore),
        (None, "total count")
    );
    assert_eq!(step(StatefulDefect::signingFails), (Some(0), "signature"));
    assert_eq!(step(StatefulDefect::signatureByte), (Some(0), "signature"));
    assert_eq!(step(StatefulDefect::savesNoKey), (Some(0), "advanced key"));
    assert_eq!(
        step(StatefulDefect::advancedKeyByte),
        (Some(0), "advanced key")
    );
    assert_eq!(
        step(StatefulDefect::keepsTheKeyInMemory),
        (Some(0), "key in memory")
    );
    assert_eq!(
        step(StatefulDefect::rejectsCSignatures),
        (Some(0), "Rust verification of the C signature")
    );
    assert_eq!(
        step(StatefulDefect::acceptsEverySignature),
        (Some(0), "verification of a changed signature")
    );
    assert_eq!(
        step(StatefulDefect::acceptsAChangedMessage),
        (Some(0), "verification of a changed message")
    );
    assert_eq!(
        step(StatefulDefect::acceptsShortSignature),
        (Some(0), "verification of a short signature")
    );
    assert_eq!(
        step(StatefulDefect::countsOneMoreRemaining),
        (Some(0), "remaining count")
    );
}

#[test]
fn aStatefulMismatchNamesTheFailingSideAndTheCounts() {
    assert_eq!(
        firstStatefulMismatch(StatefulDefect::signingFails).detail,
        "C succeeds and Rust fails: the operation failed"
    );
    assert_eq!(
        firstStatefulMismatch(StatefulDefect::savesNoKey).detail,
        "Rust released the signature and saved no key"
    );
    assert_eq!(
        firstStatefulMismatch(StatefulDefect::totalCountsOneMore).detail,
        "C counts 31 and Rust counts 32"
    );
    assert_eq!(
        firstStatefulMismatch(StatefulDefect::countsOneMoreRemaining).detail,
        "C counts 30 and Rust counts 31"
    );
}

#[test]
fn knownAnswerHarnessReproducesTheDigestsOfLiboqsForEachForm() {
    // One KEM of each generator and one scheme of each signed-message form. The `parity
    // known-answers` program runs every algorithm of the files.
    LargeStack::run(|| {
        let kemDigests = KnownAnswerDigests::kem();
        for name in ["ML-KEM-768", "HQC-1", "Classic-McEliece-348864"] {
            assert_eq!(
                KEMKnownAnswerTest::digest(&mechanism(name), false).as_deref(),
                Ok(kemDigests.singleDigest(name).expect("a digest")),
                "{name}"
            );
        }
        let signatureDigests = KnownAnswerDigests::signature();
        for name in [
            "ML-DSA-44",
            "Falcon-512",
            "Falcon-1024",
            "cross-rsdp-128-fast",
        ] {
            assert_eq!(
                SignatureKnownAnswerTest::digest(&scheme(name), false).as_deref(),
                Ok(signatureDigests.singleDigest(name).expect("a digest")),
                "{name}"
            );
        }
    });
}

#[test]
fn parityJobsReportExactlyTheBrokenAlgorithms() {
    let correctMechanism = mechanism("ML-KEM-512");
    let brokenMechanism = BrokenMechanism::new("ML-KEM-768", KEMDefect::ciphertextByte);
    let correctScheme = scheme("ML-DSA-44");
    let brokenScheme = BrokenScheme {
        inner: scheme("Falcon-512"),
        defect: SignatureDefect::signatureByte,
    };
    let correctStatefulScheme = statefulScheme("LMS_SHA256_H5_W1");
    let brokenStatefulScheme =
        BrokenStatefulScheme::new("LMS_SHA256_H5_W2", StatefulDefect::advancedKeyByte);
    let mechanisms: [&dyn KeyEncapsulating; 2] = [&correctMechanism, &brokenMechanism];
    let schemes: [&dyn Signing; 2] = [&correctScheme, &brokenScheme];
    let statefulSchemes: [&dyn StatefulSigning; 2] =
        [&correctStatefulScheme, &brokenStatefulScheme];
    let options = ParityOptions::parse(&["--cases".to_string(), "1".to_string()]).expect("valid");
    let jobs = ParityJob::parityJobs(&mechanisms, &schemes, &statefulSchemes, &options);
    let names: Vec<&str> = jobs.iter().map(|job| job.name).collect();
    assert_eq!(
        names,
        vec![
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-DSA-44",
            "Falcon-512",
            "LMS_SHA256_H5_W1",
            "LMS_SHA256_H5_W2"
        ]
    );
    let lines = Mutex::new(Vec::new());
    let failures = ParityJob::runAll(jobs, &|line| lines.lock().expect("lines").push(line));
    assert_eq!(failures, 3);
    let mut lines = lines.into_inner().expect("lines");
    lines.sort();
    assert!(
        lines[0].starts_with("FAIL  Falcon-512: Falcon-512, base case: sig: "),
        "{lines:?}"
    );
    assert!(
        lines[1].starts_with(&format!(
            "FAIL  LMS_SHA256_H5_W2: LMS_SHA256_H5_W2, case 0 of seed {:#x}: advanced key: ",
            ParitySettings::defaultSeed
        )),
        "{lines:?}"
    );
    assert!(
        lines[2].starts_with("FAIL  ML-KEM-768: ML-KEM-768, base case: ct: "),
        "{lines:?}"
    );
    assert!(
        lines[3].starts_with("ok    LMS_SHA256_H5_W1 (base case and 1 variations identical, "),
        "{lines:?}"
    );
    assert!(lines[4].starts_with("ok    ML-DSA-44 (base case and 1 variations identical, "));
    assert!(lines[5].starts_with("ok    ML-KEM-512 (base case and 1 variations identical, "));
}

/// A C mechanism that counts its key pairs. The base case and each variation make one.
struct CountingMechanism {
    inner: OracleMechanism,
    keyPairCount: AtomicUsize,
}

impl KeyEncapsulating for CountingMechanism {
    fn description(&self) -> &'static KEMDescription {
        self.inner.description()
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        self.keyPairCount.fetch_add(1, Ordering::SeqCst);
        self.inner.generateKeyPair(random)
    }

    fn generateKeyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, OQSError> {
        self.inner.generateKeyPairFromSeed(seed)
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        self.inner.encapsulate(publicKey, random)
    }

    fn encapsulateWithSeed(
        &self,
        publicKey: &[u8],
        seed: &[u8],
    ) -> Result<Encapsulation, OQSError> {
        self.inner.encapsulateWithSeed(publicKey, seed)
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        self.inner.decapsulate(ciphertext, secretKey)
    }
}

/// A C scheme that counts its key pairs. The base case and each variation make one.
struct CountingScheme {
    inner: OracleSignatureScheme,
    keyPairCount: AtomicUsize,
}

impl Signing for CountingScheme {
    fn description(&self) -> &'static SignatureDescription {
        self.inner.description()
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        self.keyPairCount.fetch_add(1, Ordering::SeqCst);
        self.inner.generateKeyPair(random)
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        self.inner.sign(message, secretKey, random)
    }

    fn signWithContext(
        &self,
        message: &[u8],
        context: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        self.inner
            .signWithContext(message, context, secretKey, random)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        self.inner.isValidSignature(signature, message, publicKey)
    }

    fn isValidSignatureWithContext(
        &self,
        signature: &[u8],
        message: &[u8],
        context: &[u8],
        publicKey: &[u8],
    ) -> bool {
        self.inner
            .isValidSignatureWithContext(signature, message, context, publicKey)
    }
}

#[test]
fn parityJobsSplitTheVariationsOfEachAlgorithmIntoBlocksThatTheShardsSplit() {
    let countingMechanism = CountingMechanism {
        inner: mechanism("ML-KEM-512"),
        keyPairCount: AtomicUsize::new(0),
    };
    let countingScheme = CountingScheme {
        inner: scheme("ML-DSA-44"),
        keyPairCount: AtomicUsize::new(0),
    };
    let mechanisms: [&dyn KeyEncapsulating; 1] = [&countingMechanism];
    let schemes: [&dyn Signing; 1] = [&countingScheme];
    let keyPairs = || {
        countingMechanism.keyPairCount.load(Ordering::SeqCst)
            + countingScheme.keyPairCount.load(Ordering::SeqCst)
    };
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_string).collect() };
    let options = ParityOptions::parse(&words("--cases 5 --block-size 2")).expect("valid");
    let jobs = ParityJob::parityJobs(&mechanisms, &schemes, &[], &options);
    let names: Vec<&str> = jobs.iter().map(|job| job.name).collect();
    assert_eq!(
        names,
        vec![
            "ML-KEM-512",
            "ML-KEM-512",
            "ML-KEM-512",
            "ML-DSA-44",
            "ML-DSA-44",
            "ML-DSA-44"
        ]
    );
    // The first block checks the base case and its two cases, so it makes three key pairs.
    let (summaries, keyPairCounts): (Vec<String>, Vec<usize>) = LargeStack::run(|| {
        jobs.iter()
            .map(|job| {
                let before = keyPairs();
                let summary = (job.check)().expect("the C algorithms are identical");
                (summary, keyPairs() - before)
            })
            .unzip()
    });
    let blockSummaries = [
        "base case and variations 0 to 1 identical",
        "variations 2 to 3 identical",
        "variations 4 to 4 identical",
    ];
    assert_eq!(summaries, blockSummaries.repeat(2));
    assert_eq!(keyPairCounts, vec![3, 2, 1, 3, 2, 1]);
    // The shards take blocks, so the blocks of one algorithm go to different shards.
    let shard =
        ParityOptions::parse(&words("--cases 5 --block-size 2 --shard 1/2")).expect("valid");
    let shardSummaries: Vec<String> = LargeStack::run(|| {
        ParityJob::parityJobs(&mechanisms, &schemes, &[], &shard)
            .iter()
            .map(|job| (job.check)().expect("the C algorithms are identical"))
            .collect()
    });
    assert_eq!(
        shardSummaries,
        vec![blockSummaries[1], blockSummaries[0], blockSummaries[2]]
    );
}

#[test]
fn aStatefulSchemeIsOneJobInARunInBlocks() {
    // The signatures of a key depend on each other, so the stateful job comes after the blocks
    // of the other algorithms, checks every case and is never split.
    let first = mechanism("ML-KEM-512");
    let stateful = statefulScheme("LMS_SHA256_H5_W1");
    let mechanisms: [&dyn KeyEncapsulating; 1] = [&first];
    let statefulSchemes: [&dyn StatefulSigning; 1] = [&stateful];
    let options = ParityOptions::parse(&["--cases", "5", "--block-size", "2"].map(String::from))
        .expect("valid");
    let jobs = ParityJob::parityJobs(&mechanisms, &[], &statefulSchemes, &options);
    let names: Vec<&str> = jobs.iter().map(|job| job.name).collect();
    assert_eq!(
        names,
        vec!["ML-KEM-512", "ML-KEM-512", "ML-KEM-512", "LMS_SHA256_H5_W1"]
    );
    let summary = LargeStack::run(|| (jobs[3].check)());
    assert_eq!(
        summary,
        Ok("base case and 5 variations identical".to_string())
    );
}

#[test]
fn aRunSkipsTheStatefulSetsOfLargeTreesUnlessTheOptionIncludesThem() {
    // The jobs are built and not run, because a key generation of a large tree takes minutes.
    let small = statefulScheme("LMS_SHA256_H5_W1");
    let medium = statefulScheme("XMSS-SHA2_16_256");
    let large = statefulScheme("XMSS-SHA2_20_256");
    let largest = statefulScheme("LMS_SHA256_H25_W8");
    let statefulSchemes: [&dyn StatefulSigning; 4] = [&small, &medium, &large, &largest];
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_string).collect() };
    let run = |arguments: &str| {
        let options = ParityOptions::parse(&words(arguments)).expect("valid");
        let names: Vec<&str> = ParityJob::parityJobs(&[], &[], &statefulSchemes, &options)
            .iter()
            .map(|job| job.name)
            .collect();
        (names, ParityJob::skippedLines(&statefulSchemes, &options))
    };
    let skipLine = |name: &str, height: u32| {
        format!("skip  {name} (a tree of height {height}, which --large-trees includes)")
    };
    assert_eq!(
        run(""),
        (
            vec!["LMS_SHA256_H5_W1", "XMSS-SHA2_16_256"],
            vec![
                skipLine("XMSS-SHA2_20_256", 20),
                skipLine("LMS_SHA256_H25_W8", 25)
            ]
        )
    );
    assert_eq!(
        run("--large-trees"),
        (
            vec![
                "LMS_SHA256_H5_W1",
                "XMSS-SHA2_16_256",
                "XMSS-SHA2_20_256",
                "LMS_SHA256_H25_W8"
            ],
            Vec::new()
        )
    );
    assert_eq!(
        run("--only XMSS-SHA2_20_256"),
        (Vec::new(), vec![skipLine("XMSS-SHA2_20_256", 20)])
    );
    assert_eq!(
        run("--only XMSS-SHA2_20_256 --large-trees"),
        (vec!["XMSS-SHA2_20_256"], Vec::new())
    );
    // Every shard skips the same sets, so only the first shard names them.
    assert_eq!(run("--shard 0/2").1.len(), 2);
    assert!(run("--shard 1/2").1.is_empty());
}

#[test]
fn everyStatefulSetOfTheCLibraryHasTheTreeHeightOfItsName() {
    let names = COracle::new(OracleRandomness::nist([0; 48])).statefulSignatureNames();
    let heights: Vec<u32> = names
        .iter()
        .map(|name| {
            StatefulTreeHeight::largest(name).unwrap_or_else(|| panic!("{name} has no height"))
        })
        .collect();
    let count =
        |isCounted: fn(u32) -> bool| heights.iter().filter(|height| isCounted(**height)).count();
    // Of the 70 sets, the default suite takes the 33 of trees of height 10 or less, and a run
    // skips the 23 of a tree of height 20 or more.
    assert_eq!(names.len(), 70);
    assert_eq!(
        count(|height| height <= SuiteSample::largestStatefulTreeHeight),
        33
    );
    assert_eq!(
        names
            .iter()
            .filter(|name| SuiteSample::contains(name))
            .count(),
        33
    );
    assert_eq!(count(|height| height >= ParityJob::largeTreeHeight), 23);
}

#[test]
fn parityJobsTakeOnlyTheSelectedAlgorithms() {
    let first = mechanism("ML-KEM-512");
    let second = mechanism("ML-KEM-768");
    let third = scheme("ML-DSA-44");
    let fourth = statefulScheme("LMS_SHA256_H5_W1");
    let mechanisms: [&dyn KeyEncapsulating; 2] = [&first, &second];
    let schemes: [&dyn Signing; 1] = [&third];
    let statefulSchemes: [&dyn StatefulSigning; 1] = [&fourth];
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_string).collect() };
    let names = |options: &str| -> Vec<&str> {
        ParityJob::parityJobs(
            &mechanisms,
            &schemes,
            &statefulSchemes,
            &ParityOptions::parse(&words(options)).expect("valid"),
        )
        .iter()
        .map(|job| job.name)
        .collect()
    };
    // The positions of the shard count over the three lists, so the stateful scheme is at 3.
    assert_eq!(names("--shard 1/2"), vec!["ML-KEM-768", "LMS_SHA256_H5_W1"]);
    assert_eq!(names("--shard 0/2"), vec!["ML-KEM-512", "ML-DSA-44"]);
    assert_eq!(names("--shard 0/4"), vec!["ML-KEM-512"]);
    assert_eq!(names("--only ML-DSA-44"), vec!["ML-DSA-44"]);
    assert_eq!(names("--only LMS_SHA256_H5_W1"), vec!["LMS_SHA256_H5_W1"]);
    assert!(names("--only nothing").is_empty());
}

#[test]
fn cSnapshotGivesTheFrozenLinesOfTheSelectedAlgorithms() {
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_string).collect() };
    let (snapshot, failures) = ParityJob::cSnapshot(
        &ParityOptions::parse(&words("--only ML-KEM-512 --only ML-DSA-44")).expect("valid"),
    );
    assert!(failures.is_empty());
    assert_eq!(snapshot.names(), vec!["ML-DSA-44", "ML-KEM-512"]);
    let frozen = OQSNativeParity::Snapshot::parse(include_str!(concat!(
        "../Snapshots/",
        env!("CARGO_PKG_VERSION"),
        ".txt"
    )))
    .expect("well formed");
    for name in snapshot.names() {
        assert_eq!(snapshot.digestOf(name), frozen.digestOf(name), "{name}");
    }
}
