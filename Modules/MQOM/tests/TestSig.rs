//! The correctness test of liboqs `tests/test_sig.c` through `SignatureCorrectnessTest`, and
//! the rejection paths, the random requests and the layout of the signatures of MQOM for each
//! parameter set.

use OQSNativeAlgorithmTests::SignatureCorrectnessTest;
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeMQOM::MQOM;

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

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

/// A random source that records the length of each request.
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

/// A random source that gives one byte to every request.
struct FixedRandom(u8);

impl RandomGenerating for FixedRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        bytes.fill(self.0);
    }
}

/// A random source that fills request n with the byte n + 1.
struct CountingRequests(u8);

impl RandomGenerating for CountingRequests {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.0 += 1;
        bytes.fill(self.0);
    }
}

fn lengthError(expected: usize, actual: usize) -> Result<(), OQSError> {
    Err(OQSError::invalidLength { expected, actual })
}

/// The length of a seed and of the salt of a set, λ / 8 bytes: 16, 24 or 32.
fn seedLength(scheme: &MQOM) -> usize {
    match scheme.description().claimedNISTLevel {
        1 => 16,
        3 => 24,
        _ => 32,
    }
}

#[test]
fn testSigPassesForMQOM2Cat1GF16FastR3() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat1GF16FastR3, &mut random(1)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat1GF16FastR5() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat1GF16FastR5, &mut random(2)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat1GF16ShortR3() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat1GF16ShortR3, &mut random(3)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat1GF16ShortR5() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat1GF16ShortR5, &mut random(4)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat3GF16FastR3() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat3GF16FastR3, &mut random(5)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat3GF16FastR5() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat3GF16FastR5, &mut random(6)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat3GF16ShortR3() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat3GF16ShortR3, &mut random(7)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat3GF16ShortR5() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat3GF16ShortR5, &mut random(8)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat5GF16FastR3() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat5GF16FastR3, &mut random(9)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat5GF16FastR5() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat5GF16FastR5, &mut random(10)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat5GF16ShortR3() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat5GF16ShortR3, &mut random(11)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMQOM2Cat5GF16ShortR5() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MQOM::mqom2Cat5GF16ShortR5, &mut random(12)),
        Ok(())
    );
}

#[test]
fn aKeyPairDrawsOneRequestAndASignatureTwoRequestsOfTheirSeeds() {
    for scheme in parameterSets {
        let seedLength = seedLength(scheme);
        let mut random = recording(1);
        let keyPair = scheme.generateKeyPair(&mut random).expect("key pair");
        // `crypto_sign_keypair` draws the seed key of 2 λ / 8 bytes, and
        // `crypto_sign_signature` the root seed and then the salt of λ / 8 bytes each.
        assert_eq!(random.requests, vec![2 * seedLength]);
        scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut random)
            .expect("signature");
        scheme
            .signWithContext(b"message", b"", keyPair.secretKey.bytes(), &mut random)
            .expect("signature with the empty context");
        assert_eq!(
            random.requests,
            vec![
                2 * seedLength,
                seedLength,
                seedLength,
                seedLength,
                seedLength
            ]
        );
    }
}

#[test]
fn theSaltIsTheSecondRequestAndStartsTheSignature() {
    for scheme in parameterSets {
        let seedLength = seedLength(scheme);
        let keyPair = scheme.generateKeyPair(&mut random(2)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        // The root seed takes the bytes 1 and the salt the bytes 2.
        let signature = scheme
            .sign(b"message", secretKey, &mut CountingRequests(0))
            .expect("signature");
        assert_eq!(signature[..seedLength], vec![2u8; seedLength]);
        // Another root seed with the same salt gives another signature with the same salt.
        let other = scheme
            .sign(b"message", secretKey, &mut CountingRequests(1))
            .expect("signature");
        assert_eq!(other[..seedLength], vec![3u8; seedLength]);
        let mut swapped = vec![2u8; seedLength];
        swapped.extend_from_slice(&other[seedLength..]);
        assert_ne!(swapped, signature);
        assert!(scheme.isValidSignature(&signature, b"message", &keyPair.publicKey));
        assert!(scheme.isValidSignature(&other, b"message", &keyPair.publicKey));
    }
}

#[test]
fn theKeyPairFollowsItsSeedAndTheSignatureItsRandomness() {
    for scheme in parameterSets {
        let description = scheme.description();
        let keyPair = scheme
            .generateKeyPair(&mut FixedRandom(3))
            .expect("key pair");
        assert_eq!(keyPair.publicKey.len(), description.publicKeyLength);
        assert_eq!(keyPair.secretKey.bytes().len(), description.secretKeyLength);
        // The secret key starts with the public key: the equation seed and y.
        assert_eq!(
            &keyPair.secretKey.bytes()[..description.publicKeyLength],
            keyPair.publicKey.as_slice()
        );
        let again = scheme
            .generateKeyPair(&mut FixedRandom(3))
            .expect("key pair");
        assert_eq!(again.publicKey, keyPair.publicKey);
        assert_eq!(again.secretKey.bytes(), keyPair.secretKey.bytes());
        let other = scheme
            .generateKeyPair(&mut FixedRandom(4))
            .expect("key pair");
        assert_ne!(other.publicKey, keyPair.publicKey);
        let secretKey = keyPair.secretKey.bytes();
        let signature = scheme
            .sign(b"message", secretKey, &mut FixedRandom(5))
            .expect("signature");
        assert_eq!(signature.len(), description.signatureLength);
        assert_eq!(
            scheme.sign(b"message", secretKey, &mut FixedRandom(5)),
            Ok(signature.clone())
        );
        let otherSignature = scheme
            .sign(b"message", secretKey, &mut FixedRandom(6))
            .expect("signature");
        assert_ne!(otherSignature, signature);
        assert!(scheme.isValidSignature(&signature, b"message", &keyPair.publicKey));
        assert!(scheme.isValidSignature(&otherSignature, b"message", &keyPair.publicKey));
    }
}

#[test]
fn aContextIsRefusedBeforeARandomByteIsDrawn() {
    for scheme in parameterSets {
        let keyPair = scheme.generateKeyPair(&mut random(2)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let mut random = recording(3);
        assert_eq!(
            scheme.signWithContext(b"message", b"c", secretKey, &mut random),
            Err(OQSError::contextNotSupported)
        );
        assert!(random.requests.is_empty());
        let signature = scheme
            .sign(b"message", secretKey, &mut FixedRandom(7))
            .expect("signature");
        // The empty context is the plain form, as a NULL context of the C code.
        assert_eq!(
            scheme.signWithContext(b"message", b"", secretKey, &mut FixedRandom(7)),
            Ok(signature.clone())
        );
        let publicKey = keyPair.publicKey.as_slice();
        assert!(scheme.isValidSignatureWithContext(&signature, b"message", b"", publicKey));
        assert!(!scheme.isValidSignatureWithContext(&signature, b"message", b"c", publicKey));
    }
}

#[test]
fn aSecretKeyOfAWrongLengthIsALengthErrorBeforeARandomByteIsDrawn() {
    for scheme in parameterSets {
        let length = scheme.description().secretKeyLength;
        let keyPair = scheme.generateKeyPair(&mut random(4)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let mut longKey = secretKey.to_vec();
        longKey.push(0);
        let mut random = recording(5);
        assert_eq!(
            scheme.sign(b"m", &secretKey[1..], &mut random).map(|_| ()),
            lengthError(length, length - 1)
        );
        assert_eq!(
            scheme.sign(b"m", &longKey, &mut random).map(|_| ()),
            lengthError(length, length + 1)
        );
        assert_eq!(
            scheme.sign(b"m", &[], &mut random).map(|_| ()),
            lengthError(length, 0)
        );
        assert_eq!(
            scheme
                .signWithContext(b"m", b"", &longKey, &mut random)
                .map(|_| ()),
            lengthError(length, length + 1)
        );
        assert!(random.requests.is_empty());
        assert!(scheme.sign(b"m", secretKey, &mut random).is_ok());
    }
}

#[test]
fn verificationRefusesEachInputOfAWrongLengthAndAcceptsTheRightOnes() {
    for scheme in parameterSets {
        let keyPair = scheme.generateKeyPair(&mut random(6)).expect("key pair");
        let publicKey = keyPair.publicKey.as_slice();
        let signature = scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut random(7))
            .expect("signature");
        assert!(scheme.isValidSignature(&signature, b"message", publicKey));
        // `crypto_sign_verify` refuses every length but the signature length.
        assert!(!scheme.isValidSignature(&signature[1..], b"message", publicKey));
        assert!(!scheme.isValidSignature(&signature[..signature.len() - 1], b"message", publicKey));
        // A byte after the nonce keeps every part at its place, as `Verify_default` reads the
        // parts at fixed places, so the length alone refuses it.
        let mut longSignature = signature.clone();
        longSignature.push(0);
        assert!(!scheme.isValidSignature(&longSignature, b"message", publicKey));
        // A byte before the nonce moves the nonce by one place.
        let nonceStart = signature.len() - 4;
        let mut insertedByte = signature[..nonceStart].to_vec();
        insertedByte.push(signature[nonceStart]);
        insertedByte.extend_from_slice(&signature[nonceStart..]);
        assert!(!scheme.isValidSignature(&insertedByte, b"message", publicKey));
        assert!(!scheme.isValidSignature(&signature, b"message", &publicKey[1..]));
        let mut longKey = publicKey.to_vec();
        longKey.push(0);
        assert!(!scheme.isValidSignature(&signature, b"message", &longKey));
        assert!(!scheme.isValidSignature(&[], b"message", publicKey));
        assert!(!scheme.isValidSignature(&signature, b"message", &[]));
    }
}

#[test]
fn aChangeInEachPartOfASignatureOrAKeyIsRefused() {
    for scheme in parameterSets {
        let description = scheme.description();
        let name = description.name;
        let seedLength = seedLength(scheme);
        let keyPair = scheme.generateKeyPair(&mut random(8)).expect("key pair");
        let publicKey = &keyPair.publicKey;
        let signature = scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut random(9))
            .expect("signature");
        assert!(scheme.isValidSignature(&signature, b"message", publicKey));
        // The salt, com1 and com2 start the signature, the nonce of four bytes ends it, and the
        // slopes alpha1 and the opening lie between them.
        let length = description.signatureLength;
        let digestLength = 2 * seedLength;
        for position in [
            0,
            seedLength - 1,
            seedLength,
            seedLength + digestLength - 1,
            seedLength + digestLength,
            seedLength + 2 * digestLength,
            length / 2,
            length - 5,
            length - 4,
            length - 1,
        ] {
            for bit in [0, 3, 7] {
                let mut changed = signature.clone();
                changed[position] ^= 1 << bit;
                assert!(
                    !scheme.isValidSignature(&changed, b"message", publicKey),
                    "{name}: byte {position}, bit {bit}"
                );
            }
        }
        // The public key is the equation seed of 2 λ / 8 bytes and the image y.
        for position in [0, digestLength - 1, digestLength, publicKey.len() - 1] {
            let mut changedKey = publicKey.clone();
            changedKey[position] ^= 0x10;
            assert!(
                !scheme.isValidSignature(&signature, b"message", &changedKey),
                "{name}: key byte {position}"
            );
        }
        assert!(!scheme.isValidSignature(&signature, b"messagf", publicKey));
        assert!(!scheme.isValidSignature(&signature, b"", publicKey));
        assert!(scheme.isValidSignature(&signature, b"message", publicKey));
    }
}

#[test]
fn messagesOfEveryLengthSignAndVerify() {
    for scheme in [
        &MQOM::mqom2Cat1GF16FastR5,
        &MQOM::mqom2Cat3GF16ShortR3,
        &MQOM::mqom2Cat5GF16FastR3,
    ] {
        let keyPair = scheme.generateKeyPair(&mut random(10)).expect("key pair");
        for message in [&b""[..], b"m", &[0xA5; 1000]] {
            let signature = scheme
                .sign(message, keyPair.secretKey.bytes(), &mut random(11))
                .expect("signature");
            assert!(
                scheme.isValidSignature(&signature, message, &keyPair.publicKey),
                "{}, message of {} bytes",
                scheme.description().name,
                message.len()
            );
        }
    }
}

#[test]
fn aSecretXThatSolvesNoEquationSignsAndItsSignatureIsRefused() {
    // `Sign` reads x and the public key from the secret key with no check, as the C code does.
    // The signature of another x is a proof for equations that x does not solve, so the
    // verification under the public key refuses it.
    for scheme in parameterSets {
        let description = scheme.description();
        let keyPair = scheme.generateKeyPair(&mut random(12)).expect("key pair");
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        let last = secretKey.len() - 1;
        secretKey[last] ^= 0x01;
        let signature = scheme
            .sign(b"message", &secretKey, &mut random(13))
            .expect("a signature");
        assert_eq!(signature.len(), description.signatureLength);
        assert!(
            !scheme.isValidSignature(&signature, b"message", &keyPair.publicKey),
            "{}",
            description.name
        );
        let valid = scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut random(13))
            .expect("a signature");
        assert!(scheme.isValidSignature(&valid, b"message", &keyPair.publicKey));
    }
}
