//! The fuzz test of liboqs `tests/fuzz_test_sig.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error.

use OQSNativeAlgorithmTests::{FuzzRandom, SignatureFuzzTest};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::OQSError;
use OQSNativeFalcon::Falcon;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4641_4C43_4F4E_465A;

const parameterSets: [&Falcon; 4] = [
    &Falcon::falcon512,
    &Falcon::falcon1024,
    &Falcon::falconPadded512,
    &Falcon::falconPadded1024,
];

/// A random source that counts the bytes that it gives, over a fuzz source.
struct CountingRandom {
    inner: FuzzRandom,
    count: usize,
}

impl RandomGenerating for CountingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.count += bytes.len();
        self.inner.fillRandomBytes(bytes);
    }
}

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestSigPassesForFalcon512() {
    assert_eq!(
        SignatureFuzzTest::run(&Falcon::falcon512, fuzzSeed, 25),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForFalcon1024() {
    assert_eq!(
        SignatureFuzzTest::run(&Falcon::falcon1024, fuzzSeed, 25),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForFalconPadded512() {
    assert_eq!(
        SignatureFuzzTest::run(&Falcon::falconPadded512, fuzzSeed, 25),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForFalconPadded1024() {
    assert_eq!(
        SignatureFuzzTest::run(&Falcon::falconPadded1024, fuzzSeed, 25),
        Ok(())
    );
}

#[test]
fn aRandomSecretKeyWithTheRightHeaderIsRefusedBeforeAnyRandomByte() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for scheme in parameterSets {
        let description = scheme.description();
        let header = scheme
            .generateKeyPair(&mut random)
            .expect("key pair")
            .secretKey
            .bytes()[0];
        for case in 0..20 {
            // A random key has a forbidden value in f, g or F, or a G outside the range.
            let mut secretKey = randomBytes(&mut random, description.secretKeyLength);
            secretKey[0] = header;
            let mut counting = CountingRandom {
                inner: FuzzRandom::seeded(case),
                count: 0,
            };
            assert_eq!(
                scheme.sign(b"message", &secretKey, &mut counting),
                Err(OQSError::operationFailed),
                "{}, case {case} of seed {fuzzSeed:#x}",
                description.name
            );
            assert_eq!(counting.count, 0);
        }
    }
}

#[test]
fn randomSignaturesAndKeysWithTheRightHeadersAreRefused() {
    let mut random = FuzzRandom::seeded(fuzzSeed ^ 1);
    for scheme in parameterSets {
        let description = scheme.description();
        let keyPair = scheme.generateKeyPair(&mut random).expect("key pair");
        let message = randomBytes(&mut random, 33);
        let signature = scheme
            .sign(&message, keyPair.secretKey.bytes(), &mut random)
            .expect("signature");
        for case in 0..30 {
            let failure = format!("{}, case {case} of seed {fuzzSeed:#x}", description.name);
            // A signature with the header and the nonce of the real one and a random value of
            // any length up to the full length.
            let length = 41 + random.nextWord() as usize % (description.signatureLength - 40);
            let mut hostile = randomBytes(&mut random, length);
            hostile[..41].copy_from_slice(&signature[..41]);
            assert!(
                !scheme.isValidSignature(&hostile, &message, &keyPair.publicKey),
                "{failure}"
            );
            // A public key with the header of the real one.
            let mut publicKey = randomBytes(&mut random, description.publicKeyLength);
            publicKey[0] = keyPair.publicKey[0];
            assert!(
                !scheme.isValidSignature(&signature, &message, &publicKey),
                "{failure}"
            );
            // A random message.
            let other = randomBytes(&mut random, case);
            assert!(
                !scheme.isValidSignature(&signature, &other, &keyPair.publicKey),
                "{failure}"
            );
        }
        assert!(scheme.isValidSignature(&signature, &message, &keyPair.publicKey));
    }
}
