//! The correctness test of liboqs `tests/test_sig.c` for each parameter set, and the accept and
//! reject decisions of the CROSS code and of the liboqs wrappers: the facts of each set, the
//! random requests, the secret key as a seed, the length errors and the missing context.

use OQSNativeAlgorithmTests::SignatureCorrectnessTest;
use OQSNativeCROSS::CROSS;
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError};
use OQSNativeKATRandom::NISTKATRandom;

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

const message: &[u8] = b"the quick brown fox";

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

/// A random source that records the length of each request, over the NIST generator.
struct RecordingRandom {
    inner: NISTKATRandom,
    requests: Vec<usize>,
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.requests.push(bytes.len());
        self.inner.fillRandomBytes(bytes);
    }
}

fn recording(seed: u8) -> RecordingRandom {
    RecordingRandom {
        inner: random(seed),
        requests: Vec::new(),
    }
}

/// A random source that gives the same bytes to each request, cut to its length.
struct FixedRandom(Vec<u8>);

impl RandomGenerating for FixedRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        let length = bytes.len();
        bytes.copy_from_slice(&self.0[..length]);
    }
}

/// The security parameter lambda of a set, which its secret key length gives: 2 lambda / 8.
fn lambdaBytes(scheme: &CROSS) -> usize {
    scheme.description().secretKeyLength / 2
}

/// A key pair and a signature of the message.
fn signed(scheme: &CROSS, seed: u8) -> (KeyPair, Vec<u8>) {
    let keyPair = scheme.generateKeyPair(&mut random(seed)).expect("key pair");
    let signature = scheme
        .sign(message, keyPair.secretKey.bytes(), &mut random(seed + 1))
        .expect("signature");
    (keyPair, signature)
}

fn checkCorrectness(scheme: &CROSS, seed: u8) {
    assert_eq!(
        SignatureCorrectnessTest::run(scheme, &mut random(seed)),
        Ok(())
    );
}

#[test]
fn testSigPassesForRSDP128Balanced() {
    checkCorrectness(&CROSS::crossRSDP128Balanced, 0);
}

#[test]
fn testSigPassesForRSDP128Fast() {
    checkCorrectness(&CROSS::crossRSDP128Fast, 1);
}

#[test]
fn testSigPassesForRSDP128Small() {
    checkCorrectness(&CROSS::crossRSDP128Small, 2);
}

#[test]
fn testSigPassesForRSDP192Balanced() {
    checkCorrectness(&CROSS::crossRSDP192Balanced, 3);
}

#[test]
fn testSigPassesForRSDP192Fast() {
    checkCorrectness(&CROSS::crossRSDP192Fast, 4);
}

#[test]
fn testSigPassesForRSDP192Small() {
    checkCorrectness(&CROSS::crossRSDP192Small, 5);
}

#[test]
fn testSigPassesForRSDP256Balanced() {
    checkCorrectness(&CROSS::crossRSDP256Balanced, 6);
}

#[test]
fn testSigPassesForRSDP256Fast() {
    checkCorrectness(&CROSS::crossRSDP256Fast, 7);
}

#[test]
fn testSigPassesForRSDP256Small() {
    checkCorrectness(&CROSS::crossRSDP256Small, 8);
}

#[test]
fn testSigPassesForRSDPG128Balanced() {
    checkCorrectness(&CROSS::crossRSDPG128Balanced, 9);
}

#[test]
fn testSigPassesForRSDPG128Fast() {
    checkCorrectness(&CROSS::crossRSDPG128Fast, 10);
}

#[test]
fn testSigPassesForRSDPG128Small() {
    checkCorrectness(&CROSS::crossRSDPG128Small, 11);
}

#[test]
fn testSigPassesForRSDPG192Balanced() {
    checkCorrectness(&CROSS::crossRSDPG192Balanced, 12);
}

#[test]
fn testSigPassesForRSDPG192Fast() {
    checkCorrectness(&CROSS::crossRSDPG192Fast, 13);
}

#[test]
fn testSigPassesForRSDPG192Small() {
    checkCorrectness(&CROSS::crossRSDPG192Small, 14);
}

#[test]
fn testSigPassesForRSDPG256Balanced() {
    checkCorrectness(&CROSS::crossRSDPG256Balanced, 15);
}

#[test]
fn testSigPassesForRSDPG256Fast() {
    checkCorrectness(&CROSS::crossRSDPG256Fast, 16);
}

#[test]
fn testSigPassesForRSDPG256Small() {
    checkCorrectness(&CROSS::crossRSDPG256Small, 17);
}

#[test]
fn eachSetHasTheFactsOfItsLiboqsFile() {
    // `sig_cross_<set>.c` and `sig_cross.h` of liboqs.
    let facts: [(&str, u8, usize, usize, usize); 18] = [
        ("cross-rsdp-128-balanced", 1, 77, 32, 13152),
        ("cross-rsdp-128-fast", 1, 77, 32, 18432),
        ("cross-rsdp-128-small", 1, 77, 32, 12432),
        ("cross-rsdp-192-balanced", 3, 115, 48, 29853),
        ("cross-rsdp-192-fast", 3, 115, 48, 41406),
        ("cross-rsdp-192-small", 3, 115, 48, 28391),
        ("cross-rsdp-256-balanced", 5, 153, 64, 53527),
        ("cross-rsdp-256-fast", 5, 153, 64, 74590),
        ("cross-rsdp-256-small", 5, 153, 64, 50818),
        ("cross-rsdpg-128-balanced", 1, 54, 32, 9120),
        ("cross-rsdpg-128-fast", 1, 54, 32, 11980),
        ("cross-rsdpg-128-small", 1, 54, 32, 8960),
        ("cross-rsdpg-192-balanced", 3, 83, 48, 22464),
        ("cross-rsdpg-192-fast", 3, 83, 48, 26772),
        ("cross-rsdpg-192-small", 3, 83, 48, 20452),
        ("cross-rsdpg-256-balanced", 5, 106, 64, 40100),
        ("cross-rsdpg-256-fast", 5, 106, 64, 48102),
        ("cross-rsdpg-256-small", 5, 106, 64, 36454),
    ];
    for (scheme, (name, level, publicKeyLength, secretKeyLength, signatureLength)) in
        parameterSets.into_iter().zip(facts)
    {
        let description = scheme.description();
        assert_eq!(description.name, name);
        assert_eq!(
            description.algorithmVersion,
            "2.2 + PQClean and OQS patches"
        );
        assert_eq!(description.claimedNISTLevel, level, "{name}");
        assert!(description.isEUFCMASecure, "{name}");
        assert!(!description.isSUFCMASecure, "{name}");
        assert!(!description.supportsContext, "{name}");
        assert_eq!(
            (
                description.publicKeyLength,
                description.secretKeyLength,
                description.signatureLength
            ),
            (publicKeyLength, secretKeyLength, signatureLength),
            "{name}"
        );
    }
}

#[test]
fn aKeyPairDrawsOneSeedAndASignatureARootSeedAndThenASalt() {
    for scheme in parameterSets {
        let name = scheme.description().name;
        let lambda = lambdaBytes(scheme);
        let mut recorder = recording(1);
        let keyPair = scheme.generateKeyPair(&mut recorder).expect("key pair");
        assert_eq!(recorder.requests, vec![2 * lambda], "{name}");
        recorder.requests.clear();
        let signature = scheme
            .sign(message, keyPair.secretKey.bytes(), &mut recorder)
            .expect("signature");
        assert_eq!(recorder.requests, vec![lambda, 2 * lambda], "{name}");
        // The secret key is the seed of the first request, and the signature starts with the
        // salt of the third request.
        let mut replay = random(1);
        let mut seed = vec![0u8; 2 * lambda];
        replay.fillRandomBytes(&mut seed);
        assert_eq!(keyPair.secretKey.bytes(), &seed[..], "{name}");
        replay.fillRandomBytes(&mut vec![0u8; lambda]);
        let mut salt = vec![0u8; 2 * lambda];
        replay.fillRandomBytes(&mut salt);
        assert_eq!(&signature[..2 * lambda], &salt[..], "{name}");
    }
}

#[test]
fn everySeedOfTheRightLengthIsASecretKeyThatSigns() {
    for scheme in parameterSets {
        let name = scheme.description().name;
        let length = scheme.description().secretKeyLength;
        for seed in [
            vec![0u8; length],
            vec![0xFF; length],
            (0..length as u8).collect(),
        ] {
            let keyPair = scheme
                .generateKeyPair(&mut FixedRandom(seed.clone()))
                .expect("key pair");
            assert_eq!(keyPair.secretKey.bytes(), &seed[..], "{name}");
            // The same seed gives the same public key, and another seed another one.
            let again = scheme
                .generateKeyPair(&mut FixedRandom(seed.clone()))
                .expect("key pair");
            assert_eq!(again.publicKey, keyPair.publicKey, "{name}");
            let signature = scheme
                .sign(message, &seed, &mut FixedRandom(vec![0x5A; length]))
                .expect("signature");
            assert!(
                scheme.isValidSignature(&signature, message, &keyPair.publicKey),
                "{name}"
            );
        }
        let first = scheme
            .generateKeyPair(&mut FixedRandom(vec![1; length]))
            .expect("key pair");
        let second = scheme
            .generateKeyPair(&mut FixedRandom(vec![2; length]))
            .expect("key pair");
        assert_ne!(first.publicKey, second.publicKey, "{name}");
    }
}

#[test]
fn theSignatureIsTheSignatureOfItsRootSeedAndSalt() {
    for scheme in parameterSets {
        let name = scheme.description().name;
        let (keyPair, _) = signed(scheme, 2);
        let secretKey = keyPair.secretKey.bytes();
        let length = 2 * lambdaBytes(scheme);
        let signature = scheme
            .sign(message, secretKey, &mut FixedRandom(vec![3; length]))
            .expect("signature");
        assert_eq!(
            scheme.sign(message, secretKey, &mut FixedRandom(vec![3; length])),
            Ok(signature.clone()),
            "{name}"
        );
        assert_ne!(
            scheme.sign(message, secretKey, &mut FixedRandom(vec![4; length])),
            Ok(signature),
            "{name}"
        );
    }
}

#[test]
fn aSecretKeyOfAWrongLengthIsALengthErrorBeforeAnyRandomByte() {
    for scheme in parameterSets {
        let description = scheme.description();
        let (keyPair, _) = signed(scheme, 4);
        let secretKey = keyPair.secretKey.bytes();
        let longer = [secretKey, &[0]].concat();
        for wrong in [&secretKey[1..], &longer[..], &[]] {
            let mut recorder = recording(5);
            assert_eq!(
                scheme.sign(message, wrong, &mut recorder),
                Err(OQSError::invalidLength {
                    expected: description.secretKeyLength,
                    actual: wrong.len()
                }),
                "{}",
                description.name
            );
            assert!(recorder.requests.is_empty(), "{}", description.name);
        }
    }
}

#[test]
fn verificationRefusesAnInputOfAWrongLengthAndAcceptsTheRightOnes() {
    for scheme in parameterSets {
        let name = scheme.description().name;
        let (keyPair, signature) = signed(scheme, 6);
        let publicKey = keyPair.publicKey.as_slice();
        assert!(
            scheme.isValidSignature(&signature, message, publicKey),
            "{name}"
        );
        // liboqs verifies the signature and then refuses a length other than its own.
        let longer = [&signature[..], &[0]].concat();
        for wrong in [&signature[..signature.len() - 1], &longer[..], &[]] {
            assert!(
                !scheme.isValidSignature(wrong, message, publicKey),
                "{name}"
            );
        }
        let longerKey = [publicKey, &[0]].concat();
        for wrong in [&publicKey[1..], &longerKey[..], &[]] {
            assert!(
                !scheme.isValidSignature(&signature, message, wrong),
                "{name}"
            );
        }
    }
}

#[test]
fn aSignatureIsAcceptedOnlyForItsMessageAndItsKey() {
    for scheme in parameterSets {
        let name = scheme.description().name;
        let (keyPair, signature) = signed(scheme, 8);
        let (otherKeys, _) = signed(scheme, 10);
        assert!(scheme.isValidSignature(&signature, message, &keyPair.publicKey));
        assert!(
            !scheme.isValidSignature(&signature, b"the quick brown box", &keyPair.publicKey),
            "{name}"
        );
        assert!(
            !scheme.isValidSignature(&signature, b"", &keyPair.publicKey),
            "{name}"
        );
        assert!(
            !scheme.isValidSignature(&signature, message, &otherKeys.publicKey),
            "{name}"
        );
        // The empty message signs and verifies too.
        let empty = scheme
            .sign(b"", keyPair.secretKey.bytes(), &mut random(12))
            .expect("signature");
        assert!(
            scheme.isValidSignature(&empty, b"", &keyPair.publicKey),
            "{name}"
        );
        assert!(
            !scheme.isValidSignature(&empty, message, &keyPair.publicKey),
            "{name}"
        );
    }
}

#[test]
fn aChangedBitAnywhereInASignatureIsRefused() {
    for scheme in parameterSets {
        let name = scheme.description().name;
        let (keyPair, signature) = signed(scheme, 13);
        let length = signature.len();
        for position in [
            0,
            40,
            70,
            100,
            length / 3,
            length / 2,
            length - 100,
            length - 1,
        ] {
            let mut changed = signature.clone();
            changed[position] ^= 0x01;
            assert!(
                !scheme.isValidSignature(&changed, message, &keyPair.publicKey),
                "{name}: byte {position}"
            );
        }
        let mut changedKey = keyPair.publicKey.clone();
        changedKey[0] ^= 0x80;
        assert!(
            !scheme.isValidSignature(&signature, message, &changedKey),
            "{name}"
        );
        let last = changedKey.len() - 1;
        let mut changedKey = keyPair.publicKey.clone();
        changedKey[last] ^= 0x01;
        assert!(
            !scheme.isValidSignature(&signature, message, &changedKey),
            "{name}"
        );
    }
}

#[test]
fn crossSignsWithoutAContextString() {
    for scheme in parameterSets {
        let name = scheme.description().name;
        let keyPair = scheme.generateKeyPair(&mut random(17)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let mut recorder = recording(18);
        assert_eq!(
            scheme.signWithContext(message, b"c", secretKey, &mut recorder),
            Err(OQSError::contextNotSupported),
            "{name}"
        );
        assert!(recorder.requests.is_empty());
        let signature = scheme
            .signWithContext(message, b"", secretKey, &mut random(18))
            .expect("the empty context signs");
        let plain = scheme
            .sign(message, secretKey, &mut random(18))
            .expect("signature");
        assert_eq!(signature, plain, "{name}");
        let publicKey = &keyPair.publicKey;
        assert!(scheme.isValidSignatureWithContext(&signature, message, b"", publicKey));
        assert!(!scheme.isValidSignatureWithContext(&signature, message, b"c", publicKey));
    }
}
