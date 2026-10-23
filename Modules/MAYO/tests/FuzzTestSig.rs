//! The fuzz test of liboqs `tests/fuzz_test_sig.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error, a random
//! secret seed signs for its own public key, and a random signature or public key is never
//! valid.

use OQSNativeAlgorithmTests::{FuzzRandom, SignatureFuzzTest};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeMAYO::MAYO;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4D41_594F_4655_5A5A;

const parameterSets: [&MAYO; 4] = [&MAYO::mayo1, &MAYO::mayo2, &MAYO::mayo3, &MAYO::mayo5];

/// A random source that gives the same bytes to every request.
struct RepeatingRandom(Vec<u8>);

impl RandomGenerating for RepeatingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0[..bytes.len()]);
    }
}

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestSigPassesForEveryParameterSet() {
    for scheme in parameterSets {
        assert_eq!(SignatureFuzzTest::run(scheme, fuzzSeed, 12), Ok(()));
    }
}

#[test]
fn randomSeedsSignForTheirKeysAndRandomSignaturesAreRefused() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    // `salt_bytes` of each set in `mayo.h`.
    for (scheme, saltLength) in parameterSets.into_iter().zip([24, 24, 32, 40]) {
        let description = scheme.description();
        let name = description.name;
        let saltStart = description.signatureLength - saltLength;
        for case in 0..6 {
            let message = randomBytes(&mut random, case * 37);
            // Every seed is a secret key, and its public key is the public key of its key pair.
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let publicKey = scheme
                .generateKeyPair(&mut RepeatingRandom(secretKey.clone()))
                .expect("key pair")
                .publicKey;
            let signature = scheme
                .sign(&message, &secretKey, &mut random)
                .expect("signature");
            assert!(
                scheme.isValidSignature(&signature, &message, &publicKey),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            let hostileSignature = randomBytes(&mut random, description.signatureLength);
            assert!(
                !scheme.isValidSignature(&hostileSignature, &message, &publicKey),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            // Random vectors s_i with the salt of the valid signature, and the vectors of the
            // valid signature with a random salt.
            let mut withValidSalt = hostileSignature.clone();
            withValidSalt[saltStart..].copy_from_slice(&signature[saltStart..]);
            assert!(
                !scheme.isValidSignature(&withValidSalt, &message, &publicKey),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            let mut withRandomSalt = signature.clone();
            withRandomSalt[saltStart..].copy_from_slice(&hostileSignature[saltStart..]);
            assert!(
                !scheme.isValidSignature(&withRandomSalt, &message, &publicKey),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            let hostileKey = randomBytes(&mut random, description.publicKeyLength);
            assert!(
                !scheme.isValidSignature(&signature, &message, &hostileKey),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
        }
    }
}
