//! The fuzz test of liboqs `tests/fuzz_test_kem.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error.
//!
//! HQC checks no key, as its C code does, so every hostile key or ciphertext of the right length
//! gives a result: a ciphertext and a shared secret, or the rejection secret.

use OQSNativeAlgorithmTests::{FuzzRandom, KEMFuzzTest};
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeHQC::HQC;
use OQSNativeSHA3::SHA3256;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4851_435F_4655_5A5A;

const parameterSets: [&HQC; 3] = [&HQC::hqc1, &HQC::hqc3, &HQC::hqc5];

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestKEMPassesForEveryParameterSet() {
    for mechanism in parameterSets {
        assert_eq!(
            KEMFuzzTest::run(mechanism, fuzzSeed, 40),
            Ok(()),
            "seed {fuzzSeed:#x}"
        );
    }
}

#[test]
fn randomKeysAndCiphertextsGiveResultsAndNeverErrors() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for mechanism in parameterSets {
        let description = mechanism.description();
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        for case in 0..10 {
            let label = format!("{}, case {case} of seed {fuzzSeed:#x}", description.name);
            let ciphertext = randomBytes(&mut random, description.ciphertextLength);
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            assert!(
                mechanism.decapsulate(&ciphertext, &secretKey).is_ok(),
                "{label}"
            );
            // A random ciphertext under a real key is rejected with the secret `J`.
            let secret = mechanism
                .decapsulate(&ciphertext, keyPair.secretKey.bytes())
                .expect("no error");
            let secretKeyBytes = keyPair.secretKey.bytes();
            let publicKeyLength = description.publicKeyLength;
            let sigma = &secretKeyBytes[publicKeyLength + 32..secretKeyBytes.len() - 32];
            let publicKeyHash = SHA3256::hash(&[&secretKeyBytes[..publicKeyLength], &[1]].concat());
            let expected = SHA3256::hash(&[&publicKeyHash[..], sigma, &ciphertext, &[3]].concat());
            assert_eq!(secret.bytes(), expected, "{label}");
            let publicKey = randomBytes(&mut random, description.publicKeyLength);
            let encapsulation = mechanism
                .encapsulate(&publicKey, &mut random)
                .expect("no error");
            assert_eq!(
                encapsulation.ciphertext.len(),
                description.ciphertextLength,
                "{label}"
            );
        }
    }
}

#[test]
fn keysAndCiphertextsOfOnlyZerosOrOnlyOnesGiveResults() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        for byte in [0x00, 0xFF] {
            let publicKey = vec![byte; description.publicKeyLength];
            let secretKey = vec![byte; description.secretKeyLength];
            let ciphertext = vec![byte; description.ciphertextLength];
            let label = format!("{}, every byte {byte:#04x}", description.name);
            // A key of only ones has every bit of `s` above `n` set.
            let encapsulation = mechanism
                .encapsulate(&publicKey, &mut FuzzRandom::fixed(byte))
                .expect("no error");
            assert_eq!(
                encapsulation.ciphertext.len(),
                description.ciphertextLength,
                "{label}"
            );
            assert!(
                mechanism.decapsulate(&ciphertext, &secretKey).is_ok(),
                "{label}"
            );
            assert!(
                mechanism
                    .decapsulate(&encapsulation.ciphertext, &secretKey)
                    .is_ok(),
                "{label}"
            );
        }
    }
}
