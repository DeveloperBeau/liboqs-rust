use crate::kemParity::{agree, countingEntropy};
use crate::{ParityMismatch, VariationGenerator};
use OQSNative::{LMS, LMSWorkingKey};
use OQSNativeCOracle::{COracle, OracleRandomness, OracleWorkingKey};
use OQSNativeDomain::{KeyStatePersisting, StatefulSigning};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes};
use OQSNativeKATRandom::NISTKATRandom;

/// The parity check of a Rust stateful signature scheme with the C scheme of the same name.
///
/// The base case is the scheme of the other kinds: the NIST KAT generator, seeded with the
/// bytes 0 to 47, before the key pair. Both sides give the same public key, the same serialized
/// secret key and the same total count. The variations are the signatures of that key: case `n`
/// is signature number `n`, with a message from `VariationGenerator::forCase`. Each side signs
/// with its own key, and both give the same signature, the same advanced key and the same
/// remaining count. Each side verifies the signature of the other side, and both sides give the
/// same verdict on a changed signature, a changed message and a short signature.
///
/// A case needs the key of the case before it, so a scheme is one check from its base case to
/// its last variation, and the run signs at most the remaining count of the key. The C side
/// signs LMS with an `OracleWorkingKey`, because `OQS_SIG_STFL_sign` loads a new working key for
/// each LMS signature at the cost of about one key generation. The Rust side signs with
/// `StatefulSigning::sign`, or, after `signingLMSWithAWorkingKey`, signs a registered LMS set with
/// an `LMSWorkingKey` for the same reason.
pub struct StatefulParity<'scheme> {
    scheme: &'scheme dyn StatefulSigning,
    seed: u64,
    workingKeyScheme: Option<LMS>,
}

impl<'scheme> StatefulParity<'scheme> {
    /// Makes the check of a scheme with the seed of a run.
    pub fn new(scheme: &'scheme dyn StatefulSigning, seed: u64) -> Self {
        StatefulParity {
            scheme,
            seed,
            workingKeyScheme: None,
        }
    }

    /// The same check, in which the Rust side signs an LMS set with an `LMSWorkingKey` of the
    /// registered set of the name of the scheme, loaded once from the key of the base case.
    /// `StatefulSigning::sign` of LMS loads the key for each signature at the cost of about one
    /// key generation, and the tests of the LMS crate prove that both give the same signature
    /// and the same advanced key at each count. A scheme of any other name signs as before. Use
    /// it only for the registered schemes: a scheme under test with a defect would sign through
    /// the registered set and hide the defect.
    pub fn signingLMSWithAWorkingKey(mut self) -> Self {
        self.workingKeyScheme = LMS::named(self.scheme.description().name);
        self
    }

    /// The key pair of the base case of the C scheme of a name.
    pub fn cBaseCase(name: &str) -> Result<KeyPair, OQSError> {
        COracle::new(OracleRandomness::nist(countingEntropy())).generateStatefulKeyPair(name)
    }

    /// The key pair of the base case of the Rust scheme.
    pub fn rustBaseCase(&self) -> Result<KeyPair, OQSError> {
        self.scheme
            .generateKeyPair(&mut NISTKATRandom::new(&countingEntropy(), None))
    }

    /// Checks the base case and then the variations `0..caseCount`, or the remaining count of
    /// the key when it is smaller. Returns the number of variations that the check signed.
    pub fn checkEveryCase(&self, caseCount: u64) -> Result<u64, ParityMismatch> {
        let name = self.scheme.description().name;
        let mismatch = |step: &'static str, detail: String| ParityMismatch {
            algorithm: name.to_string(),
            case: None,
            seed: self.seed,
            step,
            detail,
        };
        let compare =
            |step: &'static str, cBytes: &[u8], rustBytes: &[u8]| match ParityMismatch::difference(
                cBytes, rustBytes,
            ) {
                Some(detail) => Err(mismatch(step, detail)),
                None => Ok(()),
            };
        let cKeys =
            Self::cBaseCase(name).map_err(|error| mismatch("C base case", error.to_string()))?;
        let rustKeys = self
            .rustBaseCase()
            .map_err(|error| mismatch("Rust base case", error.to_string()))?;
        compare("pk", &cKeys.publicKey, &rustKeys.publicKey)?;
        compare("sk", cKeys.secretKey.bytes(), rustKeys.secretKey.bytes())?;
        let mut cSigner = CSigner::new(name, &cKeys.publicKey, cKeys.secretKey.bytes())
            .map_err(|error| mismatch("C base case", error.to_string()))?;
        let cTotal = cSigner.totalSignatureCount();
        let rustTotal = self.scheme.totalSignatureCount(rustKeys.secretKey.bytes());
        agreeOnCount(&cTotal, &rustTotal).map_err(|detail| mismatch("total count", detail))?;
        let remaining = cSigner
            .remainingSignatureCount()
            .map_err(|error| mismatch("C base case", error.to_string()))?;
        let variationCount = caseCount.min(remaining);
        let mut rustSigner =
            RustSigner::new(self.scheme, self.workingKeyScheme, rustKeys.secretKey)
                .map_err(|error| mismatch("Rust base case", error.to_string()))?;
        for case in 0..variationCount {
            self.checkCase(case, &mut cSigner, &mut rustSigner, &cKeys.publicKey)?;
        }
        Ok(variationCount)
    }

    /// Checks signature number `case` of the key: the C signer and the Rust key hold the keys
    /// after the signatures before it.
    fn checkCase(
        &self,
        case: u64,
        cSigner: &mut CSigner,
        rustSigner: &mut RustSigner,
        publicKey: &[u8],
    ) -> Result<(), ParityMismatch> {
        let name = self.scheme.description().name;
        let mismatch = |step: &'static str, detail: String| ParityMismatch {
            algorithm: name.to_string(),
            case: Some(case),
            seed: self.seed,
            step,
            detail,
        };
        let compare =
            |step: &'static str, cBytes: &[u8], rustBytes: &[u8]| match ParityMismatch::difference(
                cBytes, rustBytes,
            ) {
                Some(detail) => Err(mismatch(step, detail)),
                None => Ok(()),
            };
        let mut generator = VariationGenerator::forCase(self.seed, name, case);
        let length = generator.messageLength();
        let message = generator.bytes(length);

        let cSignature = cSigner.sign(&message);
        let mut saved = SavedKeys::default();
        let rustSignature = rustSigner.sign(&message, &mut saved);
        let (cSignature, rustSignature) = match (cSignature, rustSignature) {
            (Ok(cSignature), Ok(rustSignature)) => (cSignature, rustSignature),
            (cResult, rustResult) => {
                return agree(&cResult, &rustResult, |signature| signature)
                    .map_err(|detail| mismatch("signature", detail));
            }
        };
        compare("signature", &cSignature, &rustSignature)?;
        let Some(savedKey) = saved.keys.last() else {
            return Err(mismatch(
                "advanced key",
                "Rust released the signature and saved no key".to_string(),
            ));
        };
        compare("advanced key", cSigner.secretKey(), savedKey)?;
        compare(
            "key in memory",
            cSigner.secretKey(),
            rustSigner.secretKey().bytes(),
        )?;

        let cVerifies = |signature: &[u8], message: &[u8]| {
            COracle::new(OracleRandomness::nist([0; 48]))
                .isValidStatefulSignature(name, signature, message, publicKey)
        };
        let rustVerifies = |signature: &[u8], message: &[u8]| {
            self.scheme.isValidSignature(signature, message, publicKey)
        };
        if !cVerifies(&rustSignature, &message) {
            return Err(mismatch(
                "C verification of the Rust signature",
                "C rejects it".to_string(),
            ));
        }
        if !rustVerifies(&cSignature, &message) {
            return Err(mismatch(
                "Rust verification of the C signature",
                "Rust rejects it".to_string(),
            ));
        }
        let changedSignature = generator.withChangedBit(&cSignature);
        let changedMessage = if message.is_empty() {
            vec![0]
        } else {
            generator.withChangedBit(&message)
        };
        let shortSignature = &cSignature[..cSignature.len() - 1];
        for (step, signature, message) in [
            (
                "verification of a changed signature",
                &changedSignature[..],
                &message[..],
            ),
            (
                "verification of a changed message",
                &cSignature[..],
                &changedMessage[..],
            ),
            (
                "verification of a short signature",
                shortSignature,
                &message[..],
            ),
        ] {
            let cVerdict = cVerifies(signature, message);
            let rustVerdict = rustVerifies(signature, message);
            if cVerdict != rustVerdict {
                return Err(mismatch(
                    step,
                    format!("C says {cVerdict} and Rust says {rustVerdict}"),
                ));
            }
        }

        let cRemaining = cSigner.remainingSignatureCount();
        let rustRemaining = self
            .scheme
            .remainingSignatureCount(rustSigner.secretKey().bytes());
        agreeOnCount(&cRemaining, &rustRemaining)
            .map_err(|detail| mismatch("remaining count", detail))
    }
}

/// The C side of the variations of a key.
///
/// An LMS key signs with a working key of the oracle, which loads once. Any other key signs from
/// its serialized form with `OQS_SIG_STFL_sign`, which is fast for XMSS and XMSS^MT, because
/// their secret key holds the state of the tree traversal.
enum CSigner {
    workingKey(OracleWorkingKey),
    serializedKey {
        name: String,
        secretKey: SecretBytes,
    },
}

impl CSigner {
    fn new(name: &str, publicKey: &[u8], secretKey: &[u8]) -> Result<Self, OQSError> {
        if name.starts_with("LMS") {
            let workingKey = COracle::new(OracleRandomness::nist([0; 48]))
                .loadLMSWorkingKey(name, publicKey, secretKey)?;
            Ok(CSigner::workingKey(workingKey))
        } else {
            Ok(CSigner::serializedKey {
                name: name.to_string(),
                secretKey: SecretBytes::new(secretKey.to_vec()),
            })
        }
    }

    /// Signs a message and advances the key, or keeps the key when the signature fails.
    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, OQSError> {
        let mut oracle = COracle::new(OracleRandomness::nist([0; 48]));
        match self {
            CSigner::workingKey(workingKey) => oracle.signWithWorkingKey(workingKey, message),
            CSigner::serializedKey { name, secretKey } => {
                let (signature, advanced) =
                    oracle.signStateful(name, message, secretKey.bytes())?;
                *secretKey = advanced;
                Ok(signature)
            }
        }
    }

    /// The serialized key after the last signature.
    fn secretKey(&self) -> &[u8] {
        match self {
            CSigner::workingKey(workingKey) => workingKey.secretKey(),
            CSigner::serializedKey { secretKey, .. } => secretKey.bytes(),
        }
    }

    fn remainingSignatureCount(&self) -> Result<u64, OQSError> {
        let mut oracle = COracle::new(OracleRandomness::nist([0; 48]));
        match self {
            CSigner::workingKey(workingKey) => {
                oracle.remainingSignatureCountOfWorkingKey(workingKey)
            }
            CSigner::serializedKey { name, secretKey } => {
                oracle.remainingSignatureCount(name, secretKey.bytes())
            }
        }
    }

    fn totalSignatureCount(&self) -> Result<u64, OQSError> {
        let mut oracle = COracle::new(OracleRandomness::nist([0; 48]));
        match self {
            CSigner::workingKey(workingKey) => oracle.totalSignatureCountOfWorkingKey(workingKey),
            CSigner::serializedKey { name, secretKey } => {
                oracle.totalSignatureCount(name, secretKey.bytes())
            }
        }
    }
}

/// The Rust side of the variations of a key.
///
/// With a working key scheme, an LMS key signs with an `LMSWorkingKey`, which loads once. Its
/// signature at each count is the signature of `StatefulSigning::sign` at that count, which loads
/// the key for each signature. Any other key signs with `StatefulSigning::sign`.
enum RustSigner<'scheme> {
    workingKey(LMSWorkingKey),
    serializedKey {
        scheme: &'scheme dyn StatefulSigning,
        secretKey: SecretBytes,
    },
}

impl<'scheme> RustSigner<'scheme> {
    fn new(
        scheme: &'scheme dyn StatefulSigning,
        workingKeyScheme: Option<LMS>,
        secretKey: SecretBytes,
    ) -> Result<Self, OQSError> {
        match workingKeyScheme {
            Some(lms) => Ok(RustSigner::workingKey(lms.workingKey(secretKey.bytes())?)),
            None => Ok(RustSigner::serializedKey { scheme, secretKey }),
        }
    }

    /// Signs a message, saves the advanced key and then releases the signature.
    fn sign(
        &mut self,
        message: &[u8],
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        match self {
            RustSigner::workingKey(workingKey) => workingKey.sign(message, persisting),
            RustSigner::serializedKey { scheme, secretKey } => {
                scheme.sign(message, secretKey, persisting)
            }
        }
    }

    /// The serialized key after the last signature.
    fn secretKey(&self) -> SecretBytes {
        match self {
            RustSigner::workingKey(workingKey) => workingKey.secretKey(),
            RustSigner::serializedKey { secretKey, .. } => secretKey.clone(),
        }
    }
}

/// Agreement of two counts: the same count, or a failure on both sides.
fn agreeOnCount(
    cResult: &Result<u64, OQSError>,
    rustResult: &Result<u64, OQSError>,
) -> Result<(), String> {
    match (cResult, rustResult) {
        (Ok(cCount), Ok(rustCount)) if cCount == rustCount => Ok(()),
        (Ok(cCount), Ok(rustCount)) => {
            Err(format!("C counts {cCount} and Rust counts {rustCount}"))
        }
        (Err(_), Err(_)) => Ok(()),
        (Ok(_), Err(error)) => Err(format!("C succeeds and Rust fails: {error}")),
        (Err(error), Ok(_)) => Err(format!("Rust succeeds and C fails: {error}")),
    }
}

/// The store of the Rust side: it keeps each key that the scheme saves.
#[derive(Default)]
struct SavedKeys {
    keys: Vec<Vec<u8>>,
}

impl KeyStatePersisting for SavedKeys {
    fn persist(&mut self, secretKey: &[u8]) -> Result<(), OQSError> {
        self.keys.push(secretKey.to_vec());
        Ok(())
    }
}
