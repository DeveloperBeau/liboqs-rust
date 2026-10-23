//! The fuzz test of liboqs `tests/fuzz_test_kem.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error.

use OQSNativeAlgorithmTests::{FuzzRandom, KEMFuzzTest};
use OQSNativeClassicMcEliece::ClassicMcEliece;
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::OQSError;
use OQSNativeSHA3::SHAKE256;
use core::ops::Range;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4B45_4D5F_4655_5A5A;

/// The fuzz cases of each parameter set. The case 0 gives only the bytes 0x00 and the case 1
/// only the bytes 0xFF, and with such bytes no attempt of the error vector succeeds, in the C
/// code too, so the encapsulation never ends. The cases start at 2. Each case makes a key pair, which takes
/// up to a few seconds for the large sets in the dev profile.
const fuzzCases: Range<u64> = 2..3;

const parameterSets: [&ClassicMcEliece; 10] = [
    &ClassicMcEliece::classicMcEliece348864,
    &ClassicMcEliece::classicMcEliece348864f,
    &ClassicMcEliece::classicMcEliece460896,
    &ClassicMcEliece::classicMcEliece460896f,
    &ClassicMcEliece::classicMcEliece6688128,
    &ClassicMcEliece::classicMcEliece6688128f,
    &ClassicMcEliece::classicMcEliece6960119,
    &ClassicMcEliece::classicMcEliece6960119f,
    &ClassicMcEliece::classicMcEliece8192128,
    &ClassicMcEliece::classicMcEliece8192128f,
];

/// The code length `n` of `params.h` of a set.
fn codeLength(mechanism: &ClassicMcEliece) -> usize {
    let name = mechanism.description().name;
    match name["Classic-McEliece-".len()..].trim_end_matches('f') {
        "348864" => 3488,
        "460896" => 4608,
        "6688128" => 6688,
        "6960119" => 6960,
        _ => 8192,
    }
}

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

/// The secret of the value `s` at the end of a secret key for a ciphertext:
/// `SHAKE256(0 || s || c)`, 32 bytes.
fn rejectionSecret(secretKey: &[u8], valueLength: usize, ciphertext: &[u8]) -> Vec<u8> {
    let mut sponge = SHAKE256::new();
    sponge.absorb(&[0]);
    sponge.absorb(&secretKey[secretKey.len() - valueLength..]);
    sponge.absorb(ciphertext);
    let mut secret = vec![0u8; 32];
    sponge.finalize().squeeze(&mut secret);
    secret
}

/// True when the padding bits of a ciphertext of a 6960119 set are not zero.
fn hasCiphertextPadding(mechanism: &ClassicMcEliece, ciphertext: &[u8]) -> bool {
    mechanism.description().name.contains("6960119") && ciphertext[ciphertext.len() - 1] >> 3 != 0
}

#[test]
fn fuzzTestKEMPassesForEveryParameterSet() {
    for mechanism in parameterSets {
        assert_eq!(
            KEMFuzzTest::runCases(mechanism, fuzzSeed, fuzzCases),
            Ok(())
        );
    }
}

#[test]
fn randomCiphertextsAndSecretKeysAreRejectedWithTheSecretOfS() {
    // Classic McEliece checks no key, and only the padding bits of a ciphertext of the 6960119
    // sets. A random secret key or a random ciphertext gives a decoded error vector that fails
    // the weight or the syndrome check, so the shared secret is the one of s.
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for mechanism in parameterSets {
        let description = mechanism.description();
        let valueLength = codeLength(mechanism) / 8;
        for case in 0..2 {
            let label = format!("{}, case {case} of seed {fuzzSeed:#x}", description.name);
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let ciphertext = randomBytes(&mut random, description.ciphertextLength);
            let result = mechanism.decapsulate(&ciphertext, &secretKey);
            if hasCiphertextPadding(mechanism, &ciphertext) {
                assert_eq!(
                    result.map(|_| ()),
                    Err(OQSError::operationFailed),
                    "{label}"
                );
            } else {
                let secret = result.unwrap_or_else(|error| panic!("{label}: {error}"));
                assert_eq!(
                    secret.bytes(),
                    rejectionSecret(&secretKey, valueLength, &ciphertext),
                    "{label}"
                );
            }
            let publicKey = randomBytes(&mut random, description.publicKeyLength);
            match mechanism.encapsulate(&publicKey, &mut random) {
                Ok(encapsulation) => {
                    assert!(!description.name.contains("6960119"), "{label}");
                    assert_eq!(encapsulation.ciphertext.len(), description.ciphertextLength);
                }
                // A random public key of the 6960119 sets has padding bits.
                Err(error) => {
                    assert!(description.name.contains("6960119"), "{label}");
                    assert_eq!(error, OQSError::operationFailed, "{label}");
                }
            }
        }
    }
}
