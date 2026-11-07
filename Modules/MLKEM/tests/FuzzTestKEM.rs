//! The fuzz test of liboqs `tests/fuzz_test_kem.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error.

use OQSNativeAlgorithmTests::{FuzzRandom, KEMFuzzTest};
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::OQSError;
use OQSNativeMLKEM::{Kyber, MLKEM};

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4B45_4D5F_4655_5A5A;

fn mechanisms() -> [&'static dyn KeyEncapsulating; 6] {
    [
        &MLKEM::mlkem512,
        &MLKEM::mlkem768,
        &MLKEM::mlkem1024,
        &Kyber::kyber512,
        &Kyber::kyber768,
        &Kyber::kyber1024,
    ]
}

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestKEMPassesForEveryParameterSet() {
    for mechanism in mechanisms() {
        assert_eq!(KEMFuzzTest::run(mechanism, fuzzSeed, 40), Ok(()));
    }
}

#[test]
fn mlkemRefusesARandomSecretKeyAndKyberDecapsulatesWithIt() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for mechanism in mechanisms() {
        let description = mechanism.description();
        let isMLKEM = description.name.starts_with("ML-KEM");
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        for case in 0..30 {
            let ciphertext = randomBytes(&mut random, description.ciphertextLength);
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let result = mechanism.decapsulate(&ciphertext, &secretKey).map(|_| ());
            // The hash check of FIPS 203 refuses the key, and Kyber has no check.
            let expected = if isMLKEM {
                Err(OQSError::operationFailed)
            } else {
                Ok(())
            };
            assert_eq!(
                result, expected,
                "{}, case {case} of seed {fuzzSeed:#x}",
                description.name
            );
            assert!(
                mechanism
                    .decapsulate(&ciphertext, keyPair.secretKey.bytes())
                    .is_ok()
            );
            let publicKey = randomBytes(&mut random, description.publicKeyLength);
            let encapsulation = mechanism.encapsulate(&publicKey, &mut random);
            assert!(
                matches!(encapsulation, Ok(_) | Err(OQSError::operationFailed)),
                "{}, case {case} of seed {fuzzSeed:#x}",
                description.name
            );
            if !isMLKEM {
                assert!(encapsulation.is_ok());
            }
        }
    }
}
