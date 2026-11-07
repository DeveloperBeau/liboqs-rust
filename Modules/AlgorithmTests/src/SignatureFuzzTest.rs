use crate::FuzzRandom;
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::OQSError;
use alloc::format;
use alloc::string::String;
use alloc::vec;

/// The fuzz program of liboqs for signature schemes, `tests/fuzz_test_sig.c`, on a Rust
/// scheme, with seeded cases in place of the inputs of the fuzzer, and with hostile inputs.
///
/// In each case a `FuzzRandom` source drives the key pair and the signature of a message of
/// `case` hostile bytes, and the verification must accept the signature, as in the C program.
/// Each case then verifies hostile signatures and public keys, of the right length and of a
/// wrong length, which must be refused without a panic. A secret key of a wrong length must
/// give `OQSError::invalidLength`.
pub struct SignatureFuzzTest;

impl SignatureFuzzTest {
    /// Runs the cases `0..caseCount` from a seed. Returns the first failure, with the case and
    /// the seed.
    pub fn run(scheme: &dyn Signing, seed: u64, caseCount: u64) -> Result<(), String> {
        let description = scheme.description();
        let name = description.name;
        for case in 0..caseCount {
            let failure =
                |text: String| format!("{name}, fuzz case {case} of seed {seed:#x}: {text}");
            let mut random = FuzzRandom::forCase(seed, case);
            let mut hostile = FuzzRandom::hostile(seed, case);
            let mut bytes = |length: usize| {
                let mut buffer = vec![0u8; length];
                hostile.fillRandomBytes(&mut buffer);
                buffer
            };
            let message = bytes(case as usize);
            let keyPair = scheme
                .generateKeyPair(&mut random)
                .map_err(|error| failure(format!("the key pair failed: {error}")))?;
            let signature = scheme
                .sign(&message, keyPair.secretKey.bytes(), &mut random)
                .map_err(|error| failure(format!("the signature failed: {error}")))?;
            if !scheme.isValidSignature(&signature, &message, &keyPair.publicKey) {
                return Err(failure("the signature does not verify".into()));
            }
            let wrongLength = |length: usize| FuzzRandom::wrongLength(case, length);
            for length in [
                description.signatureLength,
                wrongLength(description.signatureLength),
            ] {
                if scheme.isValidSignature(&bytes(length), &message, &keyPair.publicKey) {
                    return Err(failure(format!(
                        "the verification accepts a hostile signature of {length} bytes"
                    )));
                }
            }
            for length in [
                description.publicKeyLength,
                wrongLength(description.publicKeyLength),
            ] {
                if scheme.isValidSignature(&signature, &message, &bytes(length)) {
                    return Err(failure(format!(
                        "the verification accepts a hostile public key of {length} bytes"
                    )));
                }
            }
            let secretKey = bytes(wrongLength(description.secretKeyLength));
            match scheme.sign(&message, &secretKey, &mut random) {
                Err(OQSError::invalidLength { expected, .. })
                    if expected == description.secretKeyLength => {}
                other => {
                    return Err(failure(format!(
                        "a secret key of a wrong length gives {:?}, not the length error",
                        other.map(|_| ())
                    )));
                }
            }
        }
        Ok(())
    }
}
