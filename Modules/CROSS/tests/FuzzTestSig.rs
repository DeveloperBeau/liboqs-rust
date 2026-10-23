//! The fuzz test of liboqs `tests/fuzz_test_sig.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error, every byte
//! string of the length of a secret key signs, and a random signature or public key is refused.

use OQSNativeAlgorithmTests::{FuzzRandom, SignatureFuzzTest};
use OQSNativeCROSS::CROSS;
use OQSNativeDomain::{RandomGenerating, Signing};

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4352_4F53_535F_465A;

const parameterSets: [&CROSS; 18] = [
    &CROSS::crossRSDP128Balanced,
    &CROSS::crossRSDP128Fast,
    &CROSS::crossRSDP128Small,
    &CROSS::crossRSDP192Balanced,
    &CROSS::crossRSDP192Fast,
    &CROSS::crossRSDP192Small,
    &CROSS::crossRSDP256Balanced,
    &CROSS::crossRSDP256Fast,
    &CROSS::crossRSDP256Small,
    &CROSS::crossRSDPG128Balanced,
    &CROSS::crossRSDPG128Fast,
    &CROSS::crossRSDPG128Small,
    &CROSS::crossRSDPG192Balanced,
    &CROSS::crossRSDPG192Fast,
    &CROSS::crossRSDPG192Small,
    &CROSS::crossRSDPG256Balanced,
    &CROSS::crossRSDPG256Fast,
    &CROSS::crossRSDPG256Small,
];

/// A random source that gives its bytes to the first request and the bytes of a fuzz source to
/// every later request, so a key pair takes a chosen seed.
struct SeededKeyRandom {
    seed: Option<Vec<u8>>,
    inner: FuzzRandom,
}

impl RandomGenerating for SeededKeyRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        match self.seed.take() {
            Some(seed) => bytes.copy_from_slice(&seed),
            None => self.inner.fillRandomBytes(bytes),
        }
    }
}

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestSigPassesForTheRSDPSets() {
    for scheme in &parameterSets[..9] {
        assert_eq!(SignatureFuzzTest::run(*scheme, fuzzSeed, 6), Ok(()));
    }
}

#[test]
fn fuzzTestSigPassesForTheRSDPGSets() {
    for scheme in &parameterSets[9..] {
        assert_eq!(SignatureFuzzTest::run(*scheme, fuzzSeed, 6), Ok(()));
    }
}

#[test]
fn aRandomSecretKeySignsForThePublicKeyOfItsSeed() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for scheme in parameterSets {
        let name = scheme.description().name;
        let length = scheme.description().secretKeyLength;
        for case in 0..3 {
            let failure = format!("{name}, case {case} of seed {fuzzSeed:#x}");
            let seed = randomBytes(&mut random, length);
            let mut keyRandom = SeededKeyRandom {
                seed: Some(seed.clone()),
                inner: FuzzRandom::seeded(fuzzSeed ^ case),
            };
            let keyPair = scheme.generateKeyPair(&mut keyRandom).expect("key pair");
            assert_eq!(keyPair.secretKey.bytes(), &seed[..], "{failure}");
            let message = randomBytes(&mut random, 50 * case as usize);
            let signature = scheme
                .sign(&message, &seed, &mut keyRandom)
                .expect("signature");
            assert!(
                scheme.isValidSignature(&signature, &message, &keyPair.publicKey),
                "{failure}"
            );
        }
    }
}

#[test]
fn randomSignaturesAndKeysAreRefused() {
    let mut random = FuzzRandom::seeded(fuzzSeed ^ 1);
    for scheme in parameterSets {
        let description = scheme.description();
        let keyPair = scheme.generateKeyPair(&mut random).expect("key pair");
        let message = randomBytes(&mut random, 33);
        let signature = scheme
            .sign(&message, keyPair.secretKey.bytes(), &mut random)
            .expect("signature");
        let digestLength = description.secretKeyLength;
        for case in 0..4 {
            let failure = format!("{}, case {case} of seed {fuzzSeed:#x}", description.name);
            let hostile = randomBytes(&mut random, description.signatureLength);
            assert!(
                !scheme.isValidSignature(&hostile, &message, &keyPair.publicKey),
                "{failure}"
            );
            // The real signature with a random digest of the second challenge: another
            // challenge reads the path, the proof and the responses in other places.
            let mut otherChallenge = signature.clone();
            otherChallenge[2 * digestLength..3 * digestLength]
                .copy_from_slice(&randomBytes(&mut random, digestLength));
            assert!(
                !scheme.isValidSignature(&otherChallenge, &message, &keyPair.publicKey),
                "{failure}"
            );
            // A public key with the seed of the real one and a random syndrome, and a random
            // public key.
            let mut publicKey = keyPair.publicKey.clone();
            let syndrome = randomBytes(&mut random, publicKey.len() - digestLength);
            publicKey[digestLength..].copy_from_slice(&syndrome);
            assert!(
                !scheme.isValidSignature(&signature, &message, &publicKey),
                "{failure}"
            );
            let randomKey = randomBytes(&mut random, description.publicKeyLength);
            assert!(
                !scheme.isValidSignature(&signature, &message, &randomKey),
                "{failure}"
            );
            let other = randomBytes(&mut random, case * 11);
            assert!(
                !scheme.isValidSignature(&signature, &other, &keyPair.publicKey),
                "{failure}"
            );
        }
        assert!(scheme.isValidSignature(&signature, &message, &keyPair.publicKey));
    }
}
