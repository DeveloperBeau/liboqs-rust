use crate::kemKnownAnswerTest::lowerHex;
use crate::{KnownAnswerRandom, KnownAnswerText, SignedMessageForm};
use OQSNativeDomain::Signing;
use OQSNativeSHA2::SHA256;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;

/// The known-answer program of liboqs for signature schemes, `tests/kat_sig.c`, on a Rust
/// scheme.
///
/// The program seeds a generator with the bytes 0 to 47. For each count it draws a 48-byte seed
/// and a message of `33 * (count + 1)` bytes, seeds a second generator with the seed, and
/// generates a key pair and a signature from the second generator.
pub struct SignatureKnownAnswerTest;

impl SignatureKnownAnswerTest {
    /// The text that `kat_sig` prints for a scheme: count 0, or every count when `isAll`.
    ///
    /// The run fails, as the C program does, when the scheme has no signed-message form, when
    /// an operation fails or when the signature does not verify.
    pub fn text(scheme: &dyn Signing, isAll: bool) -> Result<String, String> {
        let name = scheme.description().name;
        let form = SignedMessageForm::of(name)
            .ok_or_else(|| format!("{name} has no known-answer run in kat_sig"))?;
        let entropy: [u8; 48] = core::array::from_fn(|index| index as u8);
        let mut outer = KnownAnswerRandom::generator(name, &entropy);
        let countLimit = if isAll {
            KnownAnswerRandom::allCount(name)
        } else {
            1
        };
        let mut text = KnownAnswerText::new();
        for count in 0..countLimit {
            text.appendNumber("count", count);
            let mut seed = [0u8; 48];
            outer.fillRandomBytes(&mut seed);
            text.appendBytes("seed", &seed);
            let messageLength = 33 * (count + 1);
            text.appendNumber("mlen", messageLength);
            let mut message = vec![0u8; messageLength];
            outer.fillRandomBytes(&mut message);
            text.appendBytes("msg", &message);
            let mut inner = KnownAnswerRandom::generator(name, &seed);
            let keyPair = scheme
                .generateKeyPair(inner.as_mut())
                .map_err(|error| format!("{name}, count {count}: key pair: {error}"))?;
            text.appendBytes("pk", &keyPair.publicKey);
            text.appendBytes("sk", keyPair.secretKey.bytes());
            let signature = scheme
                .sign(&message, keyPair.secretKey.bytes(), inner.as_mut())
                .map_err(|error| format!("{name}, count {count}: signature: {error}"))?;
            let signedMessage = form.signedMessage(&message, &signature);
            text.appendNumber("smlen", signedMessage.len());
            text.appendBytes("sm", &signedMessage);
            if count != countLimit - 1 {
                text.appendBlankLine();
            }
            if !scheme.isValidSignature(&signature, &message, &keyPair.publicKey) {
                return Err(format!(
                    "{name}, count {count}: the signature does not verify"
                ));
            }
        }
        Ok(text.text().to_string())
    }

    /// The SHA-256 of the text in lower-case hexadecimal, as `tests/test_kat.py` computes it.
    pub fn digest(scheme: &dyn Signing, isAll: bool) -> Result<String, String> {
        Ok(lowerHex(&SHA256::hash(
            Self::text(scheme, isAll)?.as_bytes(),
        )))
    }
}
