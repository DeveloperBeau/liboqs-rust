//! The fuzz test of liboqs `tests/fuzz_test_sig.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error, any secret
//! key bytes sign, and a random signature or public key is never valid.

use OQSNativeAlgorithmTests::{FuzzRandom, SignatureFuzzTest};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeMQOM::MQOM;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4D51_4F4D_4655_5A5A;

const parameterSets: [&MQOM; 12] = [
    &MQOM::mqom2Cat1GF16FastR3,
    &MQOM::mqom2Cat1GF16FastR5,
    &MQOM::mqom2Cat1GF16ShortR3,
    &MQOM::mqom2Cat1GF16ShortR5,
    &MQOM::mqom2Cat3GF16FastR3,
    &MQOM::mqom2Cat3GF16FastR5,
    &MQOM::mqom2Cat3GF16ShortR3,
    &MQOM::mqom2Cat3GF16ShortR5,
    &MQOM::mqom2Cat5GF16FastR3,
    &MQOM::mqom2Cat5GF16FastR5,
    &MQOM::mqom2Cat5GF16ShortR3,
    &MQOM::mqom2Cat5GF16ShortR5,
];

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestSigPassesForEveryParameterSet() {
    for scheme in parameterSets {
        assert_eq!(SignatureFuzzTest::run(scheme, fuzzSeed, 4), Ok(()));
    }
}

#[test]
fn randomSecretKeysSignAndRandomSignaturesAreRefused() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for scheme in parameterSets {
        let description = scheme.description();
        let name = description.name;
        let keyPair = scheme.generateKeyPair(&mut random).expect("key pair");
        for case in 0..3 {
            let message = randomBytes(&mut random, case * 37);
            // The C code signs with any secret key bytes. The x of random bytes solves none of
            // the equations of the public key in the secret key, so the signature is refused.
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let signature = scheme
                .sign(&message, &secretKey, &mut random)
                .expect("signature");
            assert_eq!(signature.len(), description.signatureLength);
            assert!(
                !scheme.isValidSignature(
                    &signature,
                    &message,
                    &secretKey[..description.publicKeyLength]
                ),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            let hostileSignature = randomBytes(&mut random, description.signatureLength);
            assert!(
                !scheme.isValidSignature(&hostileSignature, &message, &keyPair.publicKey),
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
            // A random signature with a nonce of zero bytes still meets the proof of work for
            // a random hash in one case of 2^w, so it can reach the opening.
            let mut withZeroNonce = hostileSignature.clone();
            let nonceStart = withZeroNonce.len() - 4;
            withZeroNonce[nonceStart..].fill(0);
            assert!(
                !scheme.isValidSignature(&withZeroNonce, &message, &keyPair.publicKey),
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
