use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::OQSError;
use alloc::format;
use alloc::string::String;
use alloc::vec;

/// The correctness test of liboqs for KEMs, `tests/test_kem.c`, on a Rust mechanism.
///
/// The test runs `kem_test_correctness` twice, as the C program does: once with the random
/// forms and once with the seeded forms. The guard bytes of the C test around each buffer have
/// no Rust counterpart, because a slice cannot be written past its end.
pub struct KEMCorrectnessTest;

impl KEMCorrectnessTest {
    /// Runs both passes with random bytes from a source. Returns the first failure.
    pub fn run(
        mechanism: &dyn KeyEncapsulating,
        random: &mut dyn RandomGenerating,
    ) -> Result<(), String> {
        Self::runPass(mechanism, random, false)?;
        Self::runPass(mechanism, random, true)
    }

    /// One pass of `kem_test_correctness`, with the seeded forms when `isSeeded`.
    pub fn runPass(
        mechanism: &dyn KeyEncapsulating,
        random: &mut dyn RandomGenerating,
        isSeeded: bool,
    ) -> Result<(), String> {
        let description = mechanism.description();
        let name = description.name;
        let fail = |step: &str, error: OQSError| format!("{name}: {step} failed: {error}");
        let keyPair = if isSeeded {
            let mut seed = vec![0u8; description.keyPairSeedLength];
            random.fillRandomBytes(&mut seed);
            let result = mechanism.generateKeyPairFromSeed(&seed);
            if description.keyPairSeedLength == 0 {
                // A mechanism without a seeded form must refuse it.
                return match result {
                    Err(_) => Ok(()),
                    Ok(_) => Err(format!(
                        "{name}: the seeded key pair must fail without a seed length"
                    )),
                };
            }
            result.map_err(|error| fail("the seeded key pair", error))?
        } else {
            mechanism
                .generateKeyPair(random)
                .map_err(|error| fail("the key pair", error))?
        };
        let encapsulation = if isSeeded {
            let mut seed = vec![0u8; description.encapsulationSeedLength];
            random.fillRandomBytes(&mut seed);
            let result = mechanism.encapsulateWithSeed(&keyPair.publicKey, &seed);
            if description.encapsulationSeedLength == 0 {
                return match result {
                    Err(_) => Ok(()),
                    Ok(_) => Err(format!(
                        "{name}: the seeded encapsulation must fail without a seed length"
                    )),
                };
            }
            result.map_err(|error| fail("the seeded encapsulation", error))?
        } else {
            mechanism
                .encapsulate(&keyPair.publicKey, random)
                .map_err(|error| fail("the encapsulation", error))?
        };
        let recovered = mechanism
            .decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())
            .map_err(|error| fail("the decapsulation", error))?;
        if recovered.bytes() != encapsulation.sharedSecret.bytes() {
            return Err(format!("{name}: the shared secrets are not equal"));
        }
        // An invalid ciphertext must fail or give another shared secret.
        let mut randomCiphertext = vec![0u8; description.ciphertextLength];
        random.fillRandomBytes(&mut randomCiphertext);
        match mechanism.decapsulate(&randomCiphertext, keyPair.secretKey.bytes()) {
            Ok(secret) if secret.bytes() == encapsulation.sharedSecret.bytes() => {
                Err(format!("{name}: decapsulation succeeded on wrong input"))
            }
            _ => Ok(()),
        }
    }
}
