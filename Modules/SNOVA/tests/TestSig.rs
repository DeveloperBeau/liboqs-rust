//! The correctness test of liboqs `tests/test_sig.c` for each parameter set, and the accept and
//! reject decisions of the SNOVA code and of the liboqs wrappers: the formats of the keys and
//! the signatures, the random requests, and each refused input.

use OQSNativeAlgorithmTests::SignatureCorrectnessTest;
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSNOVA::SNOVA;

/// Every set, in the order of the liboqs list.
const parameterSets: [&SNOVA; 12] = [
    &SNOVA::snova24x5x4,
    &SNOVA::snova24x5x4SHAKE,
    &SNOVA::snova24x5x4WithExpandedSecretKey,
    &SNOVA::snova24x5x4SHAKEWithExpandedSecretKey,
    &SNOVA::snova37x17x2,
    &SNOVA::snova25x8x3,
    &SNOVA::snova56x25x2,
    &SNOVA::snova49x11x3,
    &SNOVA::snova37x8x4,
    &SNOVA::snova24x5x5,
    &SNOVA::snova60x10x4,
    &SNOVA::snova29x6x5,
];

/// The numbers v, o and l of each set, in the order of `parameterSets`.
const shapes: [(usize, usize, usize); 12] = [
    (24, 5, 4),
    (24, 5, 4),
    (24, 5, 4),
    (24, 5, 4),
    (37, 17, 2),
    (25, 8, 3),
    (56, 25, 2),
    (49, 11, 3),
    (37, 8, 4),
    (24, 5, 5),
    (60, 10, 4),
    (29, 6, 5),
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

impl RecordingRandom {
    fn new(seed: u8) -> Self {
        RecordingRandom {
            inner: random(seed),
            requests: Vec::new(),
        }
    }
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.requests.push(bytes.len());
        self.inner.fillRandomBytes(bytes);
    }
}

/// A random source that gives the start of the same bytes to each request.
struct FixedRandom(Vec<u8>);

impl RandomGenerating for FixedRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        let length = bytes.len();
        bytes.copy_from_slice(&self.0[..length]);
    }
}

/// A key pair and a signature of the message.
fn signed(scheme: &SNOVA, seed: u8) -> (KeyPair, Vec<u8>) {
    let keyPair = scheme.generateKeyPair(&mut random(seed)).expect("key pair");
    let signature = scheme
        .sign(message, keyPair.secretKey.bytes(), &mut random(seed + 1))
        .expect("signature");
    (keyPair, signature)
}

/// The length of the packed variables of a signature, before the 16 bytes of the salt.
fn variablesLength((vinegarCount, oilCount, rank): (usize, usize, usize)) -> usize {
    ((vinegarCount + oilCount) * rank * rank).div_ceil(2)
}

fn checkCorrectness(scheme: &SNOVA, seed: u8) {
    assert_eq!(
        SignatureCorrectnessTest::run(scheme, &mut random(seed)),
        Ok(())
    );
}

#[test]
fn testSigPassesForSNOVA24x5x4() {
    checkCorrectness(&SNOVA::snova24x5x4, 1);
}

#[test]
fn testSigPassesForSNOVA24x5x4SHAKE() {
    checkCorrectness(&SNOVA::snova24x5x4SHAKE, 2);
}

#[test]
fn testSigPassesForSNOVA24x5x4WithExpandedSecretKey() {
    checkCorrectness(&SNOVA::snova24x5x4WithExpandedSecretKey, 3);
}

#[test]
fn testSigPassesForSNOVA24x5x4SHAKEWithExpandedSecretKey() {
    checkCorrectness(&SNOVA::snova24x5x4SHAKEWithExpandedSecretKey, 4);
}

#[test]
fn testSigPassesForSNOVA37x17x2() {
    checkCorrectness(&SNOVA::snova37x17x2, 5);
}

#[test]
fn testSigPassesForSNOVA25x8x3() {
    checkCorrectness(&SNOVA::snova25x8x3, 6);
}

#[test]
fn testSigPassesForSNOVA56x25x2() {
    checkCorrectness(&SNOVA::snova56x25x2, 7);
}

#[test]
fn testSigPassesForSNOVA49x11x3() {
    checkCorrectness(&SNOVA::snova49x11x3, 8);
}

#[test]
fn testSigPassesForSNOVA37x8x4() {
    checkCorrectness(&SNOVA::snova37x8x4, 9);
}

#[test]
fn testSigPassesForSNOVA24x5x5() {
    checkCorrectness(&SNOVA::snova24x5x5, 10);
}

#[test]
fn testSigPassesForSNOVA60x10x4() {
    checkCorrectness(&SNOVA::snova60x10x4, 11);
}

#[test]
fn testSigPassesForSNOVA29x6x5() {
    checkCorrectness(&SNOVA::snova29x6x5, 12);
}

#[test]
fn eachSetHasTheFactsOfItsLiboqsFile() {
    let facts: [(&str, u8, usize, usize, usize); 12] = [
        ("SNOVA_24_5_4", 1, 1016, 48, 248),
        ("SNOVA_24_5_4_SHAKE", 1, 1016, 48, 248),
        ("SNOVA_24_5_4_esk", 1, 1016, 36848, 248),
        ("SNOVA_24_5_4_SHAKE_esk", 1, 1016, 36848, 248),
        ("SNOVA_37_17_2", 1, 9842, 48, 124),
        ("SNOVA_25_8_3", 1, 2320, 48, 165),
        ("SNOVA_56_25_2", 3, 31266, 48, 178),
        ("SNOVA_49_11_3", 3, 6006, 48, 286),
        ("SNOVA_37_8_4", 3, 4112, 48, 376),
        ("SNOVA_24_5_5", 3, 1579, 48, 379),
        ("SNOVA_60_10_4", 5, 8016, 48, 576),
        ("SNOVA_29_6_5", 5, 2716, 48, 454),
    ];
    for (scheme, (name, level, publicKeyLength, secretKeyLength, signatureLength)) in
        parameterSets.into_iter().zip(facts)
    {
        let description = scheme.description();
        assert_eq!(description.name, name);
        assert_eq!(description.algorithmVersion, "round2");
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
fn aKeyPairDrawsTheTwoSeedsInOneRequestAndASignatureTheSalt() {
    for scheme in parameterSets {
        let name = scheme.description().name;
        let mut recording = RecordingRandom::new(13);
        let keyPair = scheme.generateKeyPair(&mut recording).expect("key pair");
        assert_eq!(recording.requests, vec![48], "{name}");
        let signature = scheme
            .sign(message, keyPair.secretKey.bytes(), &mut recording)
            .expect("signature");
        assert_eq!(recording.requests, vec![48, 16], "{name}");
        // The public key starts with the public seed, the first 16 bytes of the request. The
        // secret key is the 48 bytes, or ends with them for an expanded key.
        let mut replay = random(13);
        let mut seeds = [0u8; 48];
        replay.fillRandomBytes(&mut seeds);
        assert_eq!(keyPair.publicKey[..16], seeds[..16], "{name}");
        let secretKey = keyPair.secretKey.bytes();
        assert_eq!(secretKey[secretKey.len() - 48..], seeds, "{name}");
        if secretKey.len() == 48 {
            assert_eq!(secretKey, seeds, "{name}");
        }
        // The signature ends with the salt, the request after the seeds.
        let mut salt = [0u8; 16];
        replay.fillRandomBytes(&mut salt);
        assert_eq!(signature[signature.len() - 16..], salt, "{name}");
    }
}

#[test]
fn theKeyPairIsTheKeyPairOfItsSeedsAndTheSignatureOfItsSalt() {
    for scheme in [
        &SNOVA::snova24x5x4,
        &SNOVA::snova37x17x2,
        &SNOVA::snova24x5x5,
    ] {
        let seeds: Vec<u8> = (0..48).collect();
        let first = scheme
            .generateKeyPair(&mut FixedRandom(seeds.clone()))
            .expect("key pair");
        let second = scheme
            .generateKeyPair(&mut FixedRandom(seeds.clone()))
            .expect("key pair");
        assert_eq!(first.publicKey, second.publicKey);
        assert_eq!(first.secretKey.bytes(), second.secretKey.bytes());
        let mut otherSeeds = seeds.clone();
        otherSeeds[40] ^= 1;
        let other = scheme
            .generateKeyPair(&mut FixedRandom(otherSeeds))
            .expect("key pair");
        // The secret seed changes the matrices T12, so P22 changes and the public seed does not.
        assert_eq!(other.publicKey[..16], first.publicKey[..16]);
        assert_ne!(other.publicKey, first.publicKey);
        let secretKey = first.secretKey.bytes();
        let signature = scheme
            .sign(message, secretKey, &mut FixedRandom(vec![5; 16]))
            .expect("signature");
        assert_eq!(
            scheme.sign(message, secretKey, &mut FixedRandom(vec![5; 16])),
            Ok(signature.clone())
        );
        assert_ne!(
            scheme.sign(message, secretKey, &mut FixedRandom(vec![6; 16])),
            Ok(signature)
        );
    }
}

#[test]
fn bothFormsOfTheSecretKeyGiveTheSameKeysAndSignatures() {
    for (seedForm, expandedForm) in [
        (
            &SNOVA::snova24x5x4,
            &SNOVA::snova24x5x4WithExpandedSecretKey,
        ),
        (
            &SNOVA::snova24x5x4SHAKE,
            &SNOVA::snova24x5x4SHAKEWithExpandedSecretKey,
        ),
    ] {
        let seedKeys = seedForm.generateKeyPair(&mut random(14)).expect("key pair");
        let expandedKeys = expandedForm
            .generateKeyPair(&mut random(14))
            .expect("key pair");
        assert_eq!(seedKeys.publicKey, expandedKeys.publicKey);
        assert_eq!(seedKeys.secretKey.bytes().len(), 48);
        assert_eq!(expandedKeys.secretKey.bytes().len(), 36848);
        let seedSignature = seedForm
            .sign(message, seedKeys.secretKey.bytes(), &mut random(15))
            .expect("signature");
        let expandedSignature = expandedForm
            .sign(message, expandedKeys.secretKey.bytes(), &mut random(15))
            .expect("signature");
        assert_eq!(seedSignature, expandedSignature);
        assert!(expandedForm.isValidSignature(&seedSignature, message, &seedKeys.publicKey));
    }
    // AES and SHAKE expand the same public seed into other public maps.
    let aesKeys = SNOVA::snova24x5x4
        .generateKeyPair(&mut random(14))
        .expect("key pair");
    let shakeKeys = SNOVA::snova24x5x4SHAKE
        .generateKeyPair(&mut random(14))
        .expect("key pair");
    assert_eq!(aesKeys.publicKey[..16], shakeKeys.publicKey[..16]);
    assert_ne!(aesKeys.publicKey, shakeKeys.publicKey);
}

#[test]
fn aSecretKeyOfAWrongLengthIsALengthErrorBeforeAnyRandomByte() {
    for scheme in parameterSets {
        let description = scheme.description();
        let keyPair = scheme.generateKeyPair(&mut random(16)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let longer = [secretKey, &[0]].concat();
        for wrong in [&secretKey[1..], &longer[..], &[]] {
            let mut recording = RecordingRandom::new(17);
            assert_eq!(
                scheme.sign(message, wrong, &mut recording),
                Err(OQSError::invalidLength {
                    expected: description.secretKeyLength,
                    actual: wrong.len()
                }),
                "{}",
                description.name
            );
            assert!(recording.requests.is_empty());
        }
    }
}

#[test]
fn verificationRefusesEachInputOfAWrongLengthAndAcceptsTheRightOnes() {
    for scheme in parameterSets {
        let (keyPair, signature) = signed(scheme, 18);
        let publicKey = keyPair.publicKey.as_slice();
        assert!(scheme.isValidSignature(&signature, message, publicKey));
        assert!(!scheme.isValidSignature(&signature[1..], message, publicKey));
        assert!(!scheme.isValidSignature(&signature[..signature.len() - 1], message, publicKey));
        let longer = [&signature[..], &[0]].concat();
        assert!(!scheme.isValidSignature(&longer, message, publicKey));
        assert!(!scheme.isValidSignature(&signature, message, &publicKey[1..]));
        let longerKey = [publicKey, &[0]].concat();
        assert!(!scheme.isValidSignature(&signature, message, &longerKey));
        assert!(!scheme.isValidSignature(&[], message, publicKey));
        assert!(!scheme.isValidSignature(&signature, message, &[]));
    }
}

#[test]
fn aSignatureIsAcceptedOnlyForItsMessageAndItsKey() {
    for scheme in parameterSets {
        let (keyPair, signature) = signed(scheme, 19);
        let (otherKeys, _) = signed(scheme, 21);
        assert!(scheme.isValidSignature(&signature, message, &keyPair.publicKey));
        assert!(!scheme.isValidSignature(&signature, b"the quick brown box", &keyPair.publicKey));
        assert!(!scheme.isValidSignature(&signature, b"", &keyPair.publicKey));
        assert!(!scheme.isValidSignature(&signature, message, &otherKeys.publicKey));
        // The public seed and the blocks P22 are both part of the key.
        let mut changedSeed = keyPair.publicKey.clone();
        changedSeed[3] ^= 0x10;
        assert!(!scheme.isValidSignature(&signature, message, &changedSeed));
        let mut changedBlock = keyPair.publicKey.clone();
        changedBlock[16] ^= 0x01;
        assert!(!scheme.isValidSignature(&signature, message, &changedBlock));
    }
}

#[test]
fn aChangeInEachPartOfASignatureIsRefused() {
    for (scheme, shape) in parameterSets.into_iter().zip(shapes) {
        let name = scheme.description().name;
        let (keyPair, signature) = signed(scheme, 22);
        let publicKey = &keyPair.publicKey;
        let variablesLength = variablesLength(shape);
        // The first vinegar variable, the last oil variable that fills its byte, and the salt.
        for position in [
            0,
            variablesLength / 2,
            variablesLength - 2,
            variablesLength,
            signature.len() - 1,
        ] {
            for bit in [0, 4, 7] {
                let mut changed = signature.clone();
                changed[position] ^= 1 << bit;
                assert!(
                    !scheme.isValidSignature(&changed, message, publicKey),
                    "{name}: byte {position}, bit {bit}"
                );
            }
        }
        // The low half of the last byte of the variables is always the last element.
        let mut changed = signature.clone();
        changed[variablesLength - 1] ^= 0x01;
        assert!(
            !scheme.isValidSignature(&changed, message, publicKey),
            "{name}"
        );
        assert!(scheme.isValidSignature(&signature, message, publicKey));
    }
}

#[test]
fn theHighHalfOfTheLastByteOfAnOddCountOfVariablesIsNotRead() {
    for (scheme, shape) in parameterSets.into_iter().zip(shapes) {
        let name = scheme.description().name;
        let (vinegarCount, oilCount, rank) = shape;
        let (keyPair, signature) = signed(scheme, 23);
        let last = variablesLength(shape) - 1;
        let mut changed = signature.clone();
        changed[last] ^= 0x80;
        let isOdd = (vinegarCount + oilCount) * rank * rank % 2 == 1;
        // SNOVA_24_5_5, SNOVA_25_8_3 and SNOVA_29_6_5 have an odd count of elements, and the
        // signature leaves the high half of the last byte at zero.
        if isOdd {
            assert_eq!(signature[last] >> 4, 0, "{name}");
        }
        assert_eq!(
            scheme.isValidSignature(&changed, message, &keyPair.publicKey),
            isOdd,
            "{name}"
        );
    }
}

#[test]
fn theHighHalfOfTheLastPublicKeyByteOfAnOddCountOfBlockElementsIsNotRead() {
    for (scheme, (_, oilCount, rank)) in parameterSets.into_iter().zip(shapes) {
        let name = scheme.description().name;
        let (keyPair, signature) = signed(scheme, 24);
        let mut changed = keyPair.publicKey.clone();
        let last = changed.len() - 1;
        changed[last] ^= 0x40;
        // SNOVA_24_5_5 and SNOVA_49_11_3 have an odd count of elements in P22.
        let isOdd = oilCount * oilCount * oilCount * rank * rank % 2 == 1;
        if isOdd {
            assert_eq!(keyPair.publicKey[last] >> 4, 0, "{name}");
        }
        assert_eq!(
            scheme.isValidSignature(&signature, message, &changed),
            isOdd,
            "{name}"
        );
        changed[last] ^= 0x41;
        assert!(
            !scheme.isValidSignature(&signature, message, &changed),
            "{name}"
        );
    }
}

#[test]
fn snovaSignsWithoutAContextString() {
    for scheme in parameterSets {
        let keyPair = scheme.generateKeyPair(&mut random(25)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        assert_eq!(
            scheme.signWithContext(message, b"c", secretKey, &mut random(26)),
            Err(OQSError::contextNotSupported)
        );
        let signature = scheme
            .signWithContext(message, b"", secretKey, &mut random(26))
            .expect("the empty context signs");
        let plain = scheme
            .sign(message, secretKey, &mut random(26))
            .expect("signature");
        assert_eq!(signature, plain);
        let publicKey = &keyPair.publicKey;
        assert!(scheme.isValidSignatureWithContext(&signature, message, b"", publicKey));
        assert!(!scheme.isValidSignatureWithContext(&signature, message, b"c", publicKey));
    }
}

#[test]
fn anyFortyEightBytesAreASecretKeyOfTheSeedForm() {
    for scheme in [
        &SNOVA::snova24x5x4,
        &SNOVA::snova25x8x3,
        &SNOVA::snova24x5x5,
    ] {
        let seeds: Vec<u8> = (0..48).map(|index| (index * 37 + 11) as u8).collect();
        let signature = scheme
            .sign(message, &seeds, &mut random(27))
            .expect("signature");
        let keyPair = scheme
            .generateKeyPair(&mut FixedRandom(seeds.clone()))
            .expect("key pair");
        assert_eq!(keyPair.secretKey.bytes(), seeds.as_slice());
        assert!(scheme.isValidSignature(&signature, message, &keyPair.publicKey));
    }
}

#[test]
fn anExpandedSecretKeyOfZerosFailsEveryAttemptAfterTheSalt() {
    // With A, B, Q1, Q2, T12 and F all zero, every system of the oil values is zero, so all
    // 254 attempts fail, and the C code returns -1.
    for scheme in [
        &SNOVA::snova24x5x4WithExpandedSecretKey,
        &SNOVA::snova24x5x4SHAKEWithExpandedSecretKey,
    ] {
        let mut recording = RecordingRandom::new(28);
        assert_eq!(
            scheme.sign(message, &vec![0u8; 36848], &mut recording),
            Err(OQSError::operationFailed)
        );
        assert_eq!(recording.requests, vec![16]);
    }
}

#[test]
fn anExpandedSecretKeyOfAnyBytesSigns() {
    // The expanded key is not checked, as in the C code.
    let scheme = &SNOVA::snova24x5x4WithExpandedSecretKey;
    let mut source = random(29);
    let mut secretKey = vec![0u8; 36848];
    source.fillRandomBytes(&mut secretKey);
    let signature = scheme
        .sign(message, &secretKey, &mut random(30))
        .expect("signature");
    assert_eq!(signature.len(), 248);
    assert_eq!(
        scheme.sign(message, &secretKey, &mut random(30)),
        Ok(signature)
    );
}
