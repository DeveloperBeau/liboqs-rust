use crate::kemParity::{agree, agreeOnFailure, countingEntropy};
use crate::{ParityMismatch, VariationGenerator};
use OQSNativeAlgorithmTests::KnownAnswerRandom;
use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeDomain::Signing;
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;

/// The parity check of a Rust signature scheme with the C scheme of the same name.
///
/// The base case is the scheme of the Swift and Zig ports: the NIST KAT generator, seeded with
/// the bytes 0 to 47, before the key pair and again before the signature of the message
/// `the quick brown fox`. Each variation draws its own entropy inputs, message and context
/// string and checks the key pair, the signature, the verification of each side by the other
/// side, and changed signatures, messages and contexts.
pub struct SignatureParity<'scheme> {
    scheme: &'scheme dyn Signing,
    seed: u64,
}

/// The snapshot fields of a signature base case, in the sorted order of their names.
pub type SignatureBaseCase = Vec<(&'static str, Vec<u8>)>;

/// The message of the base case.
pub const baseCaseMessage: &[u8] = b"the quick brown fox";

impl<'scheme> SignatureParity<'scheme> {
    /// Makes the check of a scheme with the seed of a run.
    pub fn new(scheme: &'scheme dyn Signing, seed: u64) -> Self {
        SignatureParity { scheme, seed }
    }

    /// Checks the base case and the variations `0..caseCount`.
    pub fn checkEveryCase(&self, caseCount: u64) -> Result<(), ParityMismatch> {
        self.checkBaseCase()?;
        (0..caseCount).try_for_each(|case| self.checkCase(case))
    }

    /// The base case of the C scheme of a name: `pk`, `sig` and `sk`.
    pub fn cBaseCase(name: &str) -> Result<SignatureBaseCase, OQSError> {
        let keyPair = COracle::new(OracleRandomness::nist(countingEntropy()))
            .generateSignatureKeyPair(name)?;
        let signature = COracle::new(OracleRandomness::nist(countingEntropy())).sign(
            name,
            baseCaseMessage,
            keyPair.secretKey.bytes(),
        )?;
        Ok(vec![
            ("pk", keyPair.publicKey),
            ("sig", signature),
            ("sk", keyPair.secretKey.bytes().to_vec()),
        ])
    }

    /// The base case of the Rust scheme, with the fields of `cBaseCase`.
    pub fn rustBaseCase(&self) -> Result<SignatureBaseCase, OQSError> {
        let keyPair = self
            .scheme
            .generateKeyPair(&mut NISTKATRandom::new(&countingEntropy(), None))?;
        let signature = self.scheme.sign(
            baseCaseMessage,
            keyPair.secretKey.bytes(),
            &mut NISTKATRandom::new(&countingEntropy(), None),
        )?;
        Ok(vec![
            ("pk", keyPair.publicKey),
            ("sig", signature),
            ("sk", keyPair.secretKey.bytes().to_vec()),
        ])
    }

    /// Checks the base case.
    pub fn checkBaseCase(&self) -> Result<(), ParityMismatch> {
        let name = self.scheme.description().name;
        let mismatch = |step: &'static str, detail: String| ParityMismatch {
            algorithm: name.to_string(),
            case: None,
            seed: self.seed,
            step,
            detail,
        };
        let cFields =
            Self::cBaseCase(name).map_err(|error| mismatch("C base case", error.to_string()))?;
        let rustFields = self
            .rustBaseCase()
            .map_err(|error| mismatch("Rust base case", error.to_string()))?;
        for ((field, cBytes), (_, rustBytes)) in cFields.iter().zip(&rustFields) {
            if let Some(detail) = ParityMismatch::difference(cBytes, rustBytes) {
                return Err(mismatch(field, detail));
            }
        }
        Ok(())
    }

    /// Checks one variation.
    pub fn checkCase(&self, case: u64) -> Result<(), ParityMismatch> {
        let description = self.scheme.description();
        let name = description.name;
        let mismatch = |step: &'static str, detail: String| ParityMismatch {
            algorithm: name.to_string(),
            case: Some(case),
            seed: self.seed,
            step,
            detail,
        };
        let mut generator = VariationGenerator::forCase(self.seed, name, case);
        let keyPairEntropy = generator.entropy();
        let signingEntropy = generator.entropy();
        let length = generator.messageLength();
        let message = generator.bytes(length);
        let contextLength = generator.contextLength(description.supportsContext);
        let context = generator.bytes(contextLength);
        let usesContextForm = generator.usesContextForm(contextLength);

        let cKeys = COracle::new(OracleRandomness::knownAnswer {
            algorithm: name,
            entropy: keyPairEntropy,
        })
        .generateSignatureKeyPair(name);
        let rustKeys = self
            .scheme
            .generateKeyPair(KnownAnswerRandom::generator(name, &keyPairEntropy).as_mut());
        let (cKeys, rustKeys) = match (cKeys, rustKeys) {
            (Ok(cKeys), Ok(rustKeys)) => (cKeys, rustKeys),
            (cKeys, rustKeys) => {
                return agreeOnFailure("key pair", &cKeys, &rustKeys)
                    .map_err(|detail| mismatch("key pair", detail));
            }
        };
        if let Some(detail) = ParityMismatch::difference(&cKeys.publicKey, &rustKeys.publicKey) {
            return Err(mismatch("public key", detail));
        }
        if let Some(detail) =
            ParityMismatch::difference(cKeys.secretKey.bytes(), rustKeys.secretKey.bytes())
        {
            return Err(mismatch("secret key", detail));
        }

        let mut cOracle = COracle::new(OracleRandomness::knownAnswer {
            algorithm: name,
            entropy: signingEntropy,
        });
        let cSignature = if usesContextForm {
            cOracle.signWithContext(name, &message, &context, cKeys.secretKey.bytes())
        } else {
            cOracle.sign(name, &message, cKeys.secretKey.bytes())
        };
        drop(cOracle);
        let mut rustRandom = KnownAnswerRandom::generator(name, &signingEntropy);
        let rustSignature = if usesContextForm {
            self.scheme.signWithContext(
                &message,
                &context,
                rustKeys.secretKey.bytes(),
                rustRandom.as_mut(),
            )
        } else {
            self.scheme
                .sign(&message, rustKeys.secretKey.bytes(), rustRandom.as_mut())
        };
        let (cSignature, rustSignature) = match (cSignature, rustSignature) {
            (Ok(cSignature), Ok(rustSignature)) => (cSignature, rustSignature),
            (cResult, rustResult) => {
                return agree(&cResult, &rustResult, |signature| signature)
                    .map_err(|detail| mismatch("signature", detail));
            }
        };
        if let Some(detail) = ParityMismatch::difference(&cSignature, &rustSignature) {
            return Err(mismatch("signature", detail));
        }

        let cVerifies = |signature: &[u8], message: &[u8], context: &[u8]| {
            let mut oracle = COracle::new(OracleRandomness::nist([0; 48]));
            if usesContextForm {
                oracle.isValidSignatureWithContext(
                    name,
                    signature,
                    message,
                    context,
                    &cKeys.publicKey,
                )
            } else {
                oracle.isValidSignature(name, signature, message, &cKeys.publicKey)
            }
        };
        let rustVerifies = |signature: &[u8], message: &[u8], context: &[u8]| {
            if usesContextForm {
                self.scheme.isValidSignatureWithContext(
                    signature,
                    message,
                    context,
                    &cKeys.publicKey,
                )
            } else {
                self.scheme
                    .isValidSignature(signature, message, &cKeys.publicKey)
            }
        };
        // Each side verifies the signature of the other side.
        if !cVerifies(&rustSignature, &message, &context) {
            return Err(mismatch(
                "C verification of the Rust signature",
                "C rejects it".to_string(),
            ));
        }
        if !rustVerifies(&cSignature, &message, &context) {
            return Err(mismatch(
                "Rust verification of the C signature",
                "Rust rejects it".to_string(),
            ));
        }

        // Changed inputs: both sides give the same verdict.
        let changedSignature = generator.withChangedBit(&cSignature);
        let changedMessage = if message.is_empty() {
            vec![0]
        } else {
            generator.withChangedBit(&message)
        };
        let mut longerContext = context.clone();
        longerContext.push(generator.below(256) as u8);
        let changes: [ChangedInput<'_>; 4] = [
            (
                "verification of a changed signature",
                &changedSignature,
                &message,
                &context,
            ),
            (
                "verification of a changed message",
                &cSignature,
                &changedMessage,
                &context,
            ),
            (
                "verification under a longer context",
                &cSignature,
                &message,
                &longerContext,
            ),
            (
                "verification of a short signature",
                &cSignature[..cSignature.len() - 1],
                &message,
                &context,
            ),
        ];
        for (step, signature, message, context) in changes {
            let cVerdict = cVerifies(signature, message, context);
            let rustVerdict = rustVerifies(signature, message, context);
            if cVerdict != rustVerdict {
                return Err(mismatch(
                    step,
                    format!("C says {cVerdict} and Rust says {rustVerdict}"),
                ));
            }
        }
        Ok(())
    }
}

/// A changed input of a verification: the step name, the signature, the message and the
/// context.
type ChangedInput<'input> = (&'static str, &'input [u8], &'input [u8], &'input [u8]);
