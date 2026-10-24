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

        // A context of `None` verifies in the plain form, and a context of `Some` in the
        // context form.
        let cVerifies = |signature: &[u8], message: &[u8], context: Option<&[u8]>| {
            let mut oracle = COracle::new(OracleRandomness::nist([0; 48]));
            match context {
                Some(context) => oracle.isValidSignatureWithContext(
                    name,
                    signature,
                    message,
                    context,
                    &cKeys.publicKey,
                ),
                None => oracle.isValidSignature(name, signature, message, &cKeys.publicKey),
            }
        };
        let rustVerifies = |signature: &[u8], message: &[u8], context: Option<&[u8]>| match context
        {
            Some(context) => self.scheme.isValidSignatureWithContext(
                signature,
                message,
                context,
                &cKeys.publicKey,
            ),
            None => self
                .scheme
                .isValidSignature(signature, message, &cKeys.publicKey),
        };
        let signedContext = usesContextForm.then_some(context.as_slice());
        // Each side verifies the signature of the other side.
        if !cVerifies(&rustSignature, &message, signedContext) {
            return Err(mismatch(
                "C verification of the Rust signature",
                "C rejects it".to_string(),
            ));
        }
        if !rustVerifies(&cSignature, &message, signedContext) {
            return Err(mismatch(
                "Rust verification of the C signature",
                "Rust rejects it".to_string(),
            ));
        }

        // Changed inputs: both sides give the same verdict.
        for change in Self::changedInputs(&mut generator, &cSignature, &message, signedContext) {
            let cVerdict = cVerifies(
                &change.signature,
                &change.message,
                change.context.as_deref(),
            );
            let rustVerdict = rustVerifies(
                &change.signature,
                &change.message,
                change.context.as_deref(),
            );
            if cVerdict != rustVerdict {
                return Err(mismatch(
                    change.step,
                    format!("C says {cVerdict} and Rust says {rustVerdict}"),
                ));
            }
        }
        Ok(())
    }

    /// The changed inputs of the verification of a signature: a changed signature, a changed
    /// message, a context one byte longer and a signature one byte short.
    ///
    /// Each input keeps the form of the signature, except the longer context, which always
    /// takes the context form. A plain signature then also meets a context that it was not
    /// made under.
    fn changedInputs(
        generator: &mut VariationGenerator,
        signature: &[u8],
        message: &[u8],
        signedContext: Option<&[u8]>,
    ) -> [ChangedInput; 4] {
        let changedSignature = generator.withChangedBit(signature);
        let changedMessage = if message.is_empty() {
            vec![0]
        } else {
            generator.withChangedBit(message)
        };
        let mut longerContext = signedContext.unwrap_or_default().to_vec();
        longerContext.push(generator.below(256) as u8);
        let change =
            |step, signature: &[u8], message: &[u8], context: Option<&[u8]>| ChangedInput {
                step,
                signature: signature.to_vec(),
                message: message.to_vec(),
                context: context.map(<[u8]>::to_vec),
            };
        [
            change(
                "verification of a changed signature",
                &changedSignature,
                message,
                signedContext,
            ),
            change(
                "verification of a changed message",
                signature,
                &changedMessage,
                signedContext,
            ),
            change(
                "verification under a longer context",
                signature,
                message,
                Some(&longerContext),
            ),
            change(
                "verification of a short signature",
                &signature[..signature.len() - 1],
                message,
                signedContext,
            ),
        ]
    }
}

/// A changed input of a verification, which both sides must judge alike.
struct ChangedInput {
    /// The name of the step in a mismatch.
    step: &'static str,
    signature: Vec<u8>,
    message: Vec<u8>,
    /// The context of the context form, or `None` for the plain form.
    context: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::SignatureParity;
    use crate::VariationGenerator;

    #[test]
    fn theLongerContextIsAlwaysVerifiedInTheContextForm() {
        let mut generator = VariationGenerator::new(7);
        let plain = SignatureParity::changedInputs(&mut generator, &[1, 2, 3], b"message", None);
        let longer = &plain[2];
        assert_eq!(longer.step, "verification under a longer context");
        assert_eq!(longer.context.as_ref().map(Vec::len), Some(1));
        assert!(
            [&plain[0], &plain[1], &plain[3]]
                .iter()
                .all(|change| change.context.is_none())
        );

        let signedContext: &[u8] = b"context";
        let withContext = SignatureParity::changedInputs(
            &mut generator,
            &[1, 2, 3],
            b"message",
            Some(signedContext),
        );
        let longer = withContext[2].context.as_deref().expect("the context form");
        assert_eq!(longer.len(), signedContext.len() + 1);
        assert_eq!(&longer[..signedContext.len()], signedContext);
        assert!(
            [&withContext[0], &withContext[1], &withContext[3]]
                .iter()
                .all(|change| change.context.as_deref() == Some(signedContext))
        );
    }

    #[test]
    fn eachOtherChangeChangesOnlyItsOwnInput() {
        let mut generator = VariationGenerator::new(11);
        let signature = [0x5A; 40];
        let changes = SignatureParity::changedInputs(&mut generator, &signature, b"message", None);
        assert_ne!(changes[0].signature, signature);
        assert_eq!(changes[0].message, b"message");
        assert_eq!(changes[1].signature, signature);
        assert_ne!(changes[1].message, b"message");
        assert_eq!(changes[2].signature, signature);
        assert_eq!(changes[2].message, b"message");
        assert_eq!(changes[3].signature, signature[..39]);
        assert_eq!(changes[3].message, b"message");
        let emptyMessage = SignatureParity::changedInputs(&mut generator, &signature, b"", None);
        assert_eq!(emptyMessage[1].message, [0]);
    }
}
