use crate::{KnownAnswerRandom, KnownAnswerText};
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeSHA2::SHA256;
use alloc::format;
use alloc::string::{String, ToString};

/// The known-answer program of liboqs for KEMs, `tests/kat_kem.c`, on a Rust mechanism.
///
/// The program seeds a generator with the bytes 0 to 47. For each count it draws a 48-byte seed,
/// seeds a second generator with it, and generates a key pair and an encapsulation from the
/// second generator. It prints each value in the layout of the NIST KAT response files.
pub struct KEMKnownAnswerTest;

impl KEMKnownAnswerTest {
    /// The text that `kat_kem` prints for a mechanism: count 0, or every count when `isAll`.
    ///
    /// The run fails, as the C program does, when an operation fails or when decapsulation does
    /// not recover the shared secret.
    pub fn text(mechanism: &dyn KeyEncapsulating, isAll: bool) -> Result<String, String> {
        let name = mechanism.description().name;
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
            let mut inner = KnownAnswerRandom::generator(name, &seed);
            let keyPair = mechanism
                .generateKeyPair(inner.as_mut())
                .map_err(|error| format!("{name}, count {count}: key pair: {error}"))?;
            text.appendBytes("pk", &keyPair.publicKey);
            text.appendBytes("sk", keyPair.secretKey.bytes());
            let encapsulation = mechanism
                .encapsulate(&keyPair.publicKey, inner.as_mut())
                .map_err(|error| format!("{name}, count {count}: encapsulation: {error}"))?;
            text.appendBytes("ct", &encapsulation.ciphertext);
            text.appendBytes("ss", encapsulation.sharedSecret.bytes());
            if count != countLimit - 1 {
                text.appendBlankLine();
            }
            let recovered = mechanism
                .decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())
                .map_err(|error| format!("{name}, count {count}: decapsulation: {error}"))?;
            if recovered.bytes() != encapsulation.sharedSecret.bytes() {
                return Err(format!(
                    "{name}, count {count}: the shared secrets are not equal"
                ));
            }
        }
        Ok(text.text().to_string())
    }

    /// The SHA-256 of the text in lower-case hexadecimal, as `tests/test_kat.py` computes it.
    pub fn digest(mechanism: &dyn KeyEncapsulating, isAll: bool) -> Result<String, String> {
        Ok(lowerHex(&SHA256::hash(
            Self::text(mechanism, isAll)?.as_bytes(),
        )))
    }
}

/// Lower-case hexadecimal, the form of the digests in `kats.json`.
pub(crate) fn lowerHex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
