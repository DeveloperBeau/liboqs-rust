use crate::kemKnownAnswerTest::lowerHex;
use crate::{KnownAnswerRandom, KnownAnswerText, ResponseFile};
use OQSNativeDomain::{KeyStatePersisting, StatefulSigning};
use OQSNativeEntities::{OQSError, SecretBytes, StatefulSignatureDescription};
use OQSNativeSHA2::SHA256;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The known-answer program of liboqs for stateful signature schemes, `tests/kat_sig_stfl.c`,
/// on a Rust scheme.
///
/// For XMSS and XMSS^MT the program reads the public key, the secret key, the seed, the message
/// and the signature of the response file of the scheme. It checks that the known-answer
/// generator of the seed gives the message, signs the message with the secret key, compares
/// the signature with the file, verifies it, and prints the values with the signature counts
/// of the advanced key. For LMS it verifies the signature of the file and prints the message,
/// the signature and the public key.
pub struct StatefulKnownAnswerTest;

impl StatefulKnownAnswerTest {
    /// The length of the message of the response files, `33 * (0 + 1)` as the C program
    /// writes it.
    const messageLength: usize = 33;

    /// The text that `kat_sig_stfl` prints for a scheme and the text of its response file.
    ///
    /// The run fails, as the C program does, when a value is missing or when the check of a
    /// value fails.
    pub fn text(scheme: &dyn StatefulSigning, responseFile: &str) -> Result<String, String> {
        let file = ResponseFile::new(responseFile);
        if scheme.description().name.starts_with("LMS") {
            Self::verifiedText(scheme, &file)
        } else {
            Self::signedText(scheme, &file)
        }
    }

    /// The SHA-256 of the text in lower-case hexadecimal, as `tests/KATs/sig_stfl/kats.json`
    /// holds it.
    pub fn digest(scheme: &dyn StatefulSigning, responseFile: &str) -> Result<String, String> {
        Ok(lowerHex(&SHA256::hash(
            Self::text(scheme, responseFile)?.as_bytes(),
        )))
    }

    /// The run of `sig_stfl_kat`, for XMSS and XMSS^MT.
    fn signedText(scheme: &dyn StatefulSigning, file: &ResponseFile<'_>) -> Result<String, String> {
        let description = scheme.description();
        let name = description.name;
        let missing =
            |what: &str| format!("{name}: unable to read '{what}' from the response file");
        let (publicKey, position) = file
            .value("pk = ", 0, description.publicKeyLength)
            .ok_or_else(|| missing("pk"))?;
        let (secretKey, position) = file
            .value("sk = ", position, description.secretKeyLength)
            .ok_or_else(|| missing("sk"))?;
        let mut text = KnownAnswerText::new();
        text.appendBytes("pk", &publicKey);
        text.appendBytes("sk", &secretKey);
        text.appendBlankLine();
        text.appendBlankLine();
        text.appendNumber("count", 0);
        let (seed, position) = file
            .value("seed = ", position, 48)
            .ok_or_else(|| missing("seed"))?;
        text.appendBytes("seed", &seed);
        text.appendNumber("mlen", Self::messageLength);
        let (message, position) = file
            .value("msg = ", position, Self::messageLength)
            .ok_or_else(|| missing("msg"))?;
        let mut drawn = [0u8; Self::messageLength];
        let seed: [u8; 48] = seed.try_into().expect("48 bytes");
        KnownAnswerRandom::generator(name, &seed).fillRandomBytes(&mut drawn);
        if drawn[..] != message[..] {
            return Err(format!(
                "{name}: the generator of the seed does not give the message of the file"
            ));
        }
        text.appendBytes("msg", &message);
        let mut secretKey = SecretBytes::new(secretKey);
        let signature = scheme
            .sign(&message, &mut secretKey, &mut DiscardingStore)
            .map_err(|error| format!("{name}: signature: {error}"))?;
        text.appendNumber("smlen", signature.len());
        text.appendBytes("sm", &signature);
        if signature.len() != description.signatureLength {
            return Err(format!(
                "{name}: the signature has {} bytes, not {}",
                signature.len(),
                description.signatureLength
            ));
        }
        let (expected, _) = file
            .value("sm = ", position, signature.len())
            .ok_or_else(|| missing("sm"))?;
        if signature != expected {
            return Err(format!(
                "{name}: the signature differs from the signature of the file"
            ));
        }
        if !scheme.isValidSignature(&signature, &message, &publicKey) {
            return Err(format!("{name}: the signature does not verify"));
        }
        let remaining = scheme
            .remainingSignatureCount(secretKey.bytes())
            .map_err(|error| format!("{name}: remaining signatures: {error}"))?;
        text.appendNumber("remain", remaining);
        let total = scheme
            .totalSignatureCount(secretKey.bytes())
            .map_err(|error| format!("{name}: total signatures: {error}"))?;
        text.appendNumber("max", total);
        Ok(text.text().to_string())
    }

    /// The message, the signature and the public key of a response file, read as `test_lms_kat`
    /// reads them: the message and the public key take the length of their line, which for a
    /// public key may be shorter than the length of the scheme, and the signature takes the
    /// length of the scheme. The values of an XMSS file read the same way.
    pub(crate) fn verificationValues(
        description: &StatefulSignatureDescription,
        file: &ResponseFile<'_>,
    ) -> Result<VerificationValues, String> {
        let name = description.name;
        let missing =
            |what: &str| format!("{name}: unable to read '{what}' from the response file");
        let messageLength = file.valueLength("msg = ");
        if messageLength == 0 {
            return Err(format!("{name}: the response file has no msg"));
        }
        let publicKeyLength = file.valueLength("pk = ");
        if publicKeyLength == 0 {
            return Err(format!("{name}: the response file has no pk"));
        }
        if publicKeyLength > description.publicKeyLength {
            return Err(missing("pk"));
        }
        let (publicKey, _) = file
            .value("pk = ", 0, publicKeyLength)
            .ok_or_else(|| missing("pk"))?;
        let (message, _) = file
            .value("msg = ", 0, messageLength)
            .ok_or_else(|| missing("msg"))?;
        let (signature, _) = file
            .value("sm = ", 0, description.signatureLength)
            .ok_or_else(|| missing("sm"))?;
        Ok(VerificationValues {
            message,
            signature,
            publicKey,
        })
    }

    /// The run of `test_lms_kat`, for LMS: the file has no secret key, so the program only
    /// verifies the signature of the file.
    fn verifiedText(
        scheme: &dyn StatefulSigning,
        file: &ResponseFile<'_>,
    ) -> Result<String, String> {
        let description = scheme.description();
        let name = description.name;
        let VerificationValues {
            message,
            signature,
            publicKey,
        } = Self::verificationValues(description, file)?;
        if !scheme.isValidSignature(&signature, &message, &publicKey) {
            return Err(format!(
                "{name}: the signature of the response file does not verify"
            ));
        }
        let mut text = KnownAnswerText::new();
        for (label, value) in [("msg", &message), ("sm", &signature), ("pk", &publicKey)] {
            text.appendLowerCaseBytes(label, value);
            text.appendBlankLine();
        }
        Ok(text.text().to_string())
    }
}

/// The message, the signature and the public key of a response file, which the signature
/// verifies.
pub(crate) struct VerificationValues {
    /// The signed message.
    pub(crate) message: Vec<u8>,
    /// The signature of the message.
    pub(crate) signature: Vec<u8>,
    /// The public key of the signature.
    pub(crate) publicKey: Vec<u8>,
}

/// The store of `do_nothing_save` of the C program: it accepts the advanced key and keeps
/// nothing.
struct DiscardingStore;

impl KeyStatePersisting for DiscardingStore {
    fn persist(&mut self, _: &[u8]) -> Result<(), OQSError> {
        Ok(())
    }
}
