//! The fuzz test of liboqs `tests/fuzz_test_sig.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error, and a
//! random signature, public key or message representative is never valid.

use OQSNativeAlgorithmTests::{FuzzRandom, SignatureFuzzTest};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeMLDSA::{MLDSA, PreHashAlgorithm};

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x5349_475F_4655_5A5A;

const parameterSets: [&MLDSA; 3] = [&MLDSA::mldsa44, &MLDSA::mldsa65, &MLDSA::mldsa87];

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestSigPassesForEveryParameterSet() {
    for scheme in parameterSets {
        assert_eq!(SignatureFuzzTest::run(scheme, fuzzSeed, 24), Ok(()));
    }
}

#[test]
fn randomSecretKeysSignAndRandomSignaturesAreRefused() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for scheme in parameterSets {
        let description = scheme.description();
        let name = description.name;
        let keyPair = scheme.generateKeyPair(&mut random).expect("key pair");
        for case in 0..12 {
            let message = randomBytes(&mut random, case * 7);
            // mldsa-native signs with any secret key bytes, as the C code does.
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let signature = scheme.sign(&message, &secretKey, &mut random);
            assert!(
                signature
                    .as_ref()
                    .is_ok_and(|bytes| bytes.len() == description.signatureLength),
                "{name}, case {case} of seed {fuzzSeed:#x}: {signature:?}"
            );
            let hostileSignature = randomBytes(&mut random, description.signatureLength);
            assert!(
                !scheme.isValidSignature(&hostileSignature, &message, &keyPair.publicKey),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            // A random signature with an empty hint encoding passes the hint checks, so the
            // verification reaches the challenge comparison more often. The hint encoding is
            // the last omega + k bytes.
            let mut withZeroHints = hostileSignature.clone();
            let hintLength = match name {
                "ML-DSA-44" => 80 + 4,
                "ML-DSA-65" => 55 + 6,
                _ => 75 + 8,
            };
            let hintStart = description.signatureLength - hintLength;
            for byte in &mut withZeroHints[hintStart..] {
                *byte = 0;
            }
            assert!(
                !scheme.isValidSignature(&withZeroHints, &message, &keyPair.publicKey),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            let representative = randomBytes(&mut random, 64);
            assert!(
                !scheme.isValidInternalSignature(
                    &hostileSignature,
                    &representative,
                    &keyPair.publicKey,
                    true
                ),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            let hash = randomBytes(&mut random, 48);
            let context = randomBytes(&mut random, case * 20);
            assert!(
                !scheme.isValidPreHashSignature(
                    &hostileSignature,
                    &hash,
                    PreHashAlgorithm::sha384,
                    &context,
                    &keyPair.publicKey
                ),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            let hostileKey = randomBytes(&mut random, description.publicKeyLength);
            let validSignature = scheme
                .sign(&message, keyPair.secretKey.bytes(), &mut random)
                .expect("signature");
            assert!(scheme.isValidSignature(&validSignature, &message, &keyPair.publicKey));
            assert!(
                !scheme.isValidSignature(&validSignature, &message, &hostileKey),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
        }
    }
}
