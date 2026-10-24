//! Validation of the parity harness and of the known-answer harness, before any Rust family
//! depends on them.
//!
//! False positive validation: the C algorithms themselves, behind the Rust interfaces, pass
//! every check. False negative validation: each kind of defect in a mechanism or a scheme is
//! reported at its own step.

use OQSNativeAlgorithmTests::{KEMKnownAnswerTest, KnownAnswerDigests, SignatureKnownAnswerTest};
use OQSNativeCOracle::{OracleMechanism, OracleSignatureScheme};
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating, Signing};
use OQSNativeEntities::{
    Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes, SignatureDescription,
};
use OQSNativeParity::{
    KEMParity, LargeStack, ParityJob, ParityOptions, ParitySettings, SignatureParity,
};
use std::sync::Mutex;

const caseCount: u64 = 3;

fn mechanism(name: &str) -> OracleMechanism {
    OracleMechanism::named(name).unwrap_or_else(|| panic!("the C library has {name}"))
}

fn scheme(name: &str) -> OracleSignatureScheme {
    OracleSignatureScheme::named(name).unwrap_or_else(|| panic!("the C library has {name}"))
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
    let mechanisms: [&dyn KeyEncapsulating; 2] = [&correctMechanism, &brokenMechanism];
    let schemes: [&dyn Signing; 2] = [&correctScheme, &brokenScheme];
    let options = ParityOptions::parse(&["--cases".to_string(), "1".to_string()]).expect("valid");
    let jobs = ParityJob::parityJobs(&mechanisms, &schemes, &options);
    let names: Vec<&str> = jobs.iter().map(|job| job.name).collect();
    assert_eq!(
        names,
        vec!["ML-KEM-512", "ML-KEM-768", "ML-DSA-44", "Falcon-512"]
    );
    let lines = Mutex::new(Vec::new());
    let failures = ParityJob::runAll(jobs, &|line| lines.lock().expect("lines").push(line));
    assert_eq!(failures, 2);
    let mut lines = lines.into_inner().expect("lines");
    lines.sort();
    assert!(
        lines[0].starts_with("FAIL  Falcon-512: Falcon-512, base case: sig: "),
        "{lines:?}"
    );
    assert!(
        lines[1].starts_with("FAIL  ML-KEM-768: ML-KEM-768, base case: ct: "),
        "{lines:?}"
    );
    assert!(lines[2].starts_with("ok    ML-DSA-44 (base case and 1 variations identical, "));
    assert!(lines[3].starts_with("ok    ML-KEM-512 (base case and 1 variations identical, "));
}

#[test]
fn parityJobsTakeOnlyTheSelectedAlgorithms() {
    let first = mechanism("ML-KEM-512");
    let second = mechanism("ML-KEM-768");
    let third = scheme("ML-DSA-44");
    let mechanisms: [&dyn KeyEncapsulating; 2] = [&first, &second];
    let schemes: [&dyn Signing; 1] = [&third];
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_string).collect() };
    let names = |options: &str| -> Vec<&str> {
        ParityJob::parityJobs(
            &mechanisms,
            &schemes,
            &ParityOptions::parse(&words(options)).expect("valid"),
        )
        .iter()
        .map(|job| job.name)
        .collect()
    };
    assert_eq!(names("--shard 1/2"), vec!["ML-KEM-768"]);
    assert_eq!(names("--shard 0/2"), vec!["ML-KEM-512", "ML-DSA-44"]);
    assert_eq!(names("--only ML-DSA-44"), vec!["ML-DSA-44"]);
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
