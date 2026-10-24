//! The correctness test of liboqs `tests/test_sig.c` through `SignatureCorrectnessTest`, and
//! the rejection paths, the random requests and the secret seeds of MAYO for each parameter
//! set.

use OQSNativeAlgorithmTests::SignatureCorrectnessTest;
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeMAYO::MAYO;

const parameterSets: [&MAYO; 4] = [&MAYO::mayo1, &MAYO::mayo2, &MAYO::mayo3, &MAYO::mayo5];

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

fn lengthError(expected: usize, actual: usize) -> Result<(), OQSError> {
    Err(OQSError::invalidLength { expected, actual })
}

#[test]
fn testSigPassesForMAYO1() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MAYO::mayo1, &mut random(1)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMAYO2() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MAYO::mayo2, &mut random(2)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMAYO3() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MAYO::mayo3, &mut random(3)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMAYO5() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MAYO::mayo5, &mut random(5)),
        Ok(())
    );
}

#[test]
fn aKeyPairDrawsTheSeedAndASignatureTheSaltRandomnessInOneRequestEach() {
    // `sk_seed_bytes` and `salt_bytes` of each set in `mayo.h`.
    for (scheme, length) in parameterSets.into_iter().zip([24, 24, 32, 40]) {
        let mut random = recording(1);
        let keyPair = scheme.generateKeyPair(&mut random).expect("key pair");
        assert_eq!(random.requests, vec![length]);
        scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut random)
            .expect("signature");
        scheme
            .signWithContext(b"message", b"", keyPair.secretKey.bytes(), &mut random)
            .expect("signature with the empty context");
        assert_eq!(random.requests, vec![length; 3]);
    }
}

#[test]
fn theSecretKeyIsTheSeedAndTheSignatureFollowsItsRandomness() {
    for scheme in parameterSets {
        let description = scheme.description();
        let keyPair = scheme
            .generateKeyPair(&mut FixedRandom(3))
            .expect("key pair");
        assert_eq!(
            keyPair.secretKey.bytes(),
            vec![3u8; description.secretKeyLength]
        );
        assert_eq!(keyPair.publicKey.len(), description.publicKeyLength);
        let again = scheme
            .generateKeyPair(&mut FixedRandom(3))
            .expect("key pair");
        assert_eq!(again.publicKey, keyPair.publicKey);
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
    // `salt_bytes` of each set in `mayo.h`.
    for (scheme, saltLength) in parameterSets.into_iter().zip([24, 24, 32, 40]) {
        let keyPair = scheme.generateKeyPair(&mut random(6)).expect("key pair");
        let publicKey = keyPair.publicKey.as_slice();
        let signature = scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut random(7))
            .expect("signature");
        assert!(scheme.isValidSignature(&signature, b"message", publicKey));
        assert!(!scheme.isValidSignature(&signature[1..], b"message", publicKey));
        assert!(!scheme.isValidSignature(&signature[..signature.len() - 1], b"message", publicKey));
        let mut longSignature = signature.clone();
        longSignature.push(0);
        assert!(!scheme.isValidSignature(&longSignature, b"message", publicKey));
        // One byte before the salt keeps the vectors at the start and the salt at the end, so
        // only the length refuses this signature.
        let saltStart = signature.len() - saltLength;
        let mut insertedByte = signature[..saltStart].to_vec();
        insertedByte.push(0);
        insertedByte.extend_from_slice(&signature[saltStart..]);
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
    // `salt_bytes` of each set in `mayo.h`.
    for (scheme, saltLength) in parameterSets.into_iter().zip([24, 24, 32, 40]) {
        let description = scheme.description();
        let name = description.name;
        let keyPair = scheme.generateKeyPair(&mut random(8)).expect("key pair");
        let publicKey = &keyPair.publicKey;
        let signature = scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut random(9))
            .expect("signature");
        assert!(scheme.isValidSignature(&signature, b"message", publicKey));
        // The vectors s_i fill the signature up to the salt, which ends it.
        let length = description.signatureLength;
        let saltStart = length - saltLength;
        for position in [0, 1, length / 3, saltStart - 1, saltStart, length - 1] {
            for bit in [0, 4, 7] {
                let mut changed = signature.clone();
                changed[position] ^= 1 << bit;
                assert!(
                    !scheme.isValidSignature(&changed, b"message", publicKey),
                    "{name}: byte {position}, bit {bit}"
                );
            }
        }
        // The public key is the public seed of 16 bytes and the upper triangle of P3.
        for position in [0, 15, 16, publicKey.len() / 2, publicKey.len() - 1] {
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
fn everySeedIsASecretKeyThatSignsForItsPublicKey() {
    // The secret key is the seed of the key pair, so any bytes of the right length sign, and
    // the signature is valid for the public key of the same seed.
    for scheme in parameterSets {
        for byte in [0x00, 0xFF, 0x5A] {
            let keyPair = scheme
                .generateKeyPair(&mut FixedRandom(byte))
                .expect("key pair");
            let secretKey = vec![byte; scheme.description().secretKeyLength];
            for message in [&b""[..], b"m", &[0xA5; 1000]] {
                let signature = scheme
                    .sign(message, &secretKey, &mut random(byte))
                    .expect("signature");
                assert!(
                    scheme.isValidSignature(&signature, message, &keyPair.publicKey),
                    "{}, seed byte {byte:#x}, message of {} bytes",
                    scheme.description().name,
                    message.len()
                );
            }
        }
    }
}
