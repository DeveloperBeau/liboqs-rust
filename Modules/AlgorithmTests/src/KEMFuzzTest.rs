use crate::FuzzRandom;
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeEntities::OQSError;
use alloc::format;
use alloc::string::String;
use alloc::vec;

/// The fuzz program of liboqs for KEMs, `tests/fuzz_test_kem.c`, on a Rust mechanism, with
/// seeded cases in place of the inputs of the fuzzer, and with hostile inputs.
///
/// In each case a `FuzzRandom` source drives the key pair and the encapsulation, and the
/// decapsulation must recover the shared secret, as in the C program. Each case then gives
/// hostile inputs of the right length and of wrong lengths. They must give a result or an
/// error, and never a panic, and a wrong length must give `OQSError::invalidLength`.
pub struct KEMFuzzTest;

impl KEMFuzzTest {
    /// Runs the cases `0..caseCount` from a seed. Returns the first failure, with the case
    /// and the seed.
    pub fn run(mechanism: &dyn KeyEncapsulating, seed: u64, caseCount: u64) -> Result<(), String> {
        Self::runCases(mechanism, seed, 0..caseCount)
    }

    /// Runs a range of cases from a seed. Returns the first failure, with the case and the
    /// seed.
    ///
    /// A mechanism whose key pair of the constant bytes of the cases 0 and 1 cannot
    /// decapsulate, as in its C code, runs the seeded cases from 2 up.
    pub fn runCases(
        mechanism: &dyn KeyEncapsulating,
        seed: u64,
        cases: core::ops::Range<u64>,
    ) -> Result<(), String> {
        let description = mechanism.description();
        let name = description.name;
        for case in cases {
            let failure =
                |text: String| format!("{name}, fuzz case {case} of seed {seed:#x}: {text}");
            let mut random = FuzzRandom::forCase(seed, case);
            let keyPair = mechanism
                .generateKeyPair(&mut random)
                .map_err(|error| failure(format!("the key pair failed: {error}")))?;
            let encapsulation = mechanism
                .encapsulate(&keyPair.publicKey, &mut random)
                .map_err(|error| failure(format!("the encapsulation failed: {error}")))?;
            let recovered = mechanism
                .decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())
                .map_err(|error| failure(format!("the decapsulation failed: {error}")))?;
            if recovered.bytes() != encapsulation.sharedSecret.bytes() {
                return Err(failure("the shared secrets are not equal".into()));
            }
            let mut hostile = FuzzRandom::hostile(seed, case);
            let mut bytes = |length: usize| {
                let mut buffer = vec![0u8; length];
                OQSNativeDomain::RandomGenerating::fillRandomBytes(&mut hostile, &mut buffer);
                buffer
            };
            // Hostile values of the right length give a result or an error.
            let _ = mechanism.decapsulate(
                &bytes(description.ciphertextLength),
                keyPair.secretKey.bytes(),
            );
            let _ = mechanism.decapsulate(
                &encapsulation.ciphertext,
                &bytes(description.secretKeyLength),
            );
            let _ = mechanism.encapsulate(&bytes(description.publicKeyLength), &mut random);
            // Wrong lengths give the length error.
            let wrongLength = |length: usize| FuzzRandom::wrongLength(case, length);
            let checks = [
                (
                    "a ciphertext",
                    description.ciphertextLength,
                    mechanism
                        .decapsulate(
                            &bytes(wrongLength(description.ciphertextLength)),
                            keyPair.secretKey.bytes(),
                        )
                        .map(|_| ()),
                ),
                (
                    "a secret key",
                    description.secretKeyLength,
                    mechanism
                        .decapsulate(
                            &encapsulation.ciphertext,
                            &bytes(wrongLength(description.secretKeyLength)),
                        )
                        .map(|_| ()),
                ),
                (
                    "a public key",
                    description.publicKeyLength,
                    mechanism
                        .encapsulate(
                            &bytes(wrongLength(description.publicKeyLength)),
                            &mut random,
                        )
                        .map(|_| ()),
                ),
            ];
            for (input, expected, result) in checks {
                match result {
                    Err(OQSError::invalidLength {
                        expected: reported, ..
                    }) if reported == expected => {}
                    other => {
                        return Err(failure(format!(
                            "{input} of a wrong length gives {other:?}, not the length error"
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}
