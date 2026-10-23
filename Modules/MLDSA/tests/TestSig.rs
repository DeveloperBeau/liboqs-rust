//! The correctness test of liboqs `tests/test_sig.c` through `SignatureCorrectnessTest`, and
//! the rejection paths, the random requests and the message forms of FIPS 204 for each
//! parameter set.

use OQSNativeAlgorithmTests::SignatureCorrectnessTest;
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeMLDSA::{MLDSA, PreHashAlgorithm};
use OQSNativeSHA3::SHAKE256;

const parameterSets: [&MLDSA; 3] = [&MLDSA::mldsa44, &MLDSA::mldsa65, &MLDSA::mldsa87];

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

/// A random source that gives the same 32 bytes to each request of 32 bytes.
struct FixedRandom([u8; 32]);

impl RandomGenerating for FixedRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0);
    }
}

fn lengthError(expected: usize, actual: usize) -> Result<(), OQSError> {
    Err(OQSError::invalidLength { expected, actual })
}

#[test]
fn testSigPassesForMLDSA44() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MLDSA::mldsa44, &mut random(44)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMLDSA65() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MLDSA::mldsa65, &mut random(65)),
        Ok(())
    );
}

#[test]
fn testSigPassesForMLDSA87() {
    assert_eq!(
        SignatureCorrectnessTest::run(&MLDSA::mldsa87, &mut random(87)),
        Ok(())
    );
}

#[test]
fn aKeyPairAndASignatureEachDrawOneRequestOf32Bytes() {
    for scheme in parameterSets {
        let mut recording = RecordingRandom {
            inner: random(1),
            requests: Vec::new(),
        };
        let keyPair = scheme.generateKeyPair(&mut recording).expect("key pair");
        assert_eq!(recording.requests, vec![32]);
        scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut recording)
            .expect("signature");
        scheme
            .signWithContext(
                b"message",
                b"context",
                keyPair.secretKey.bytes(),
                &mut recording,
            )
            .expect("signature with a context");
        assert_eq!(recording.requests, vec![32, 32, 32]);
    }
}

#[test]
fn theKeyPairIsTheKeyPairOfItsSeedAndTheSignatureOfItsRandomness() {
    for scheme in parameterSets {
        let first = scheme
            .generateKeyPair(&mut FixedRandom([3; 32]))
            .expect("key pair");
        let second = scheme
            .generateKeyPair(&mut FixedRandom([3; 32]))
            .expect("key pair");
        assert_eq!(first.publicKey, second.publicKey);
        assert_eq!(first.secretKey.bytes(), second.secretKey.bytes());
        let other = scheme
            .generateKeyPair(&mut FixedRandom([4; 32]))
            .expect("key pair");
        assert_ne!(other.publicKey, first.publicKey);
        let secretKey = first.secretKey.bytes();
        let signature = scheme
            .sign(b"hedged", secretKey, &mut FixedRandom([5; 32]))
            .expect("signature");
        assert_eq!(
            scheme.sign(b"hedged", secretKey, &mut FixedRandom([5; 32])),
            Ok(signature.clone())
        );
        assert_ne!(
            scheme.sign(b"hedged", secretKey, &mut FixedRandom([6; 32])),
            Ok(signature)
        );
    }
}

#[test]
fn aContextOfMoreThan255BytesIsRefusedBeforeARandomByteIsDrawn() {
    for scheme in parameterSets {
        let keyPair = scheme.generateKeyPair(&mut random(2)).expect("key pair");
        let mut recording = RecordingRandom {
            inner: random(3),
            requests: Vec::new(),
        };
        assert_eq!(
            scheme.signWithContext(
                b"message",
                &[7u8; 256],
                keyPair.secretKey.bytes(),
                &mut recording
            ),
            Err(OQSError::contextTooLong)
        );
        assert!(recording.requests.is_empty());
        let signature = scheme
            .signWithContext(
                b"message",
                &[7u8; 255],
                keyPair.secretKey.bytes(),
                &mut recording,
            )
            .expect("a context of 255 bytes");
        assert!(scheme.isValidSignatureWithContext(
            &signature,
            b"message",
            &[7u8; 255],
            &keyPair.publicKey
        ));
        assert!(!scheme.isValidSignatureWithContext(
            &signature,
            b"message",
            &[7u8; 256],
            &keyPair.publicKey
        ));
        assert_eq!(
            scheme
                .preHashSignature(
                    &[0u8; 32],
                    PreHashAlgorithm::sha256,
                    &[0u8; 256],
                    keyPair.secretKey.bytes(),
                    &[0u8; 32]
                )
                .map(|_| ()),
            Err(OQSError::contextTooLong)
        );
    }
}

#[test]
fn eachInputOfAWrongLengthIsALengthError() {
    for scheme in parameterSets {
        let description = scheme.description();
        let keyPair = scheme.generateKeyPair(&mut random(4)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let shortKey = &secretKey[1..];
        let mut longKey = secretKey.to_vec();
        longKey.push(0);
        let secretLength = description.secretKeyLength;
        assert_eq!(
            scheme.sign(b"m", shortKey, &mut random(5)).map(|_| ()),
            lengthError(secretLength, secretLength - 1)
        );
        assert_eq!(
            scheme
                .signWithContext(b"m", b"c", &longKey, &mut random(5))
                .map(|_| ()),
            lengthError(secretLength, secretLength + 1)
        );
        // The secret key is checked before the context.
        assert_eq!(
            scheme
                .signWithContext(b"m", &[0; 300], shortKey, &mut random(5))
                .map(|_| ()),
            lengthError(secretLength, secretLength - 1)
        );
        assert_eq!(
            scheme
                .internalSignature(b"m", shortKey, &[0; 32], false)
                .map(|_| ()),
            lengthError(secretLength, secretLength - 1)
        );
        for randomnessLength in [0, 31, 33] {
            assert_eq!(
                scheme
                    .internalSignature(b"m", secretKey, &vec![0; randomnessLength], false)
                    .map(|_| ()),
                lengthError(32, randomnessLength)
            );
        }
        // An external message representative has exactly 64 bytes.
        for representativeLength in [0, 63, 65] {
            assert_eq!(
                scheme
                    .internalSignature(&vec![1; representativeLength], secretKey, &[0; 32], true)
                    .map(|_| ()),
                lengthError(64, representativeLength)
            );
        }
        assert!(
            scheme
                .internalSignature(&[1; 64], secretKey, &[0; 32], true)
                .is_ok()
        );
        // A pre-hash has the length of its hash function.
        for (algorithm, length) in [
            (PreHashAlgorithm::sha224, 28),
            (PreHashAlgorithm::sha384, 48),
            (PreHashAlgorithm::shake128, 32),
            (PreHashAlgorithm::shake256, 64),
        ] {
            assert_eq!(
                scheme
                    .preHashSignature(&vec![0; length + 1], algorithm, b"", secretKey, &[0; 32])
                    .map(|_| ()),
                lengthError(length, length + 1),
                "{algorithm:?}"
            );
            assert!(
                scheme
                    .preHashSignature(&vec![0; length], algorithm, b"", secretKey, &[0; 32])
                    .is_ok()
            );
        }
        assert_eq!(
            scheme
                .preHashSignature(&[0; 32], PreHashAlgorithm::sha256, b"", &longKey, &[0; 32])
                .map(|_| ()),
            lengthError(secretLength, secretLength + 1)
        );
        assert_eq!(
            scheme
                .preHashSignature(&[0; 32], PreHashAlgorithm::sha256, b"", secretKey, &[0; 16])
                .map(|_| ()),
            lengthError(32, 16)
        );
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
        assert!(!scheme.isValidSignature(&signature[1..], b"message", publicKey));
        let mut longSignature = signature.clone();
        longSignature.push(0);
        assert!(!scheme.isValidSignature(&longSignature, b"message", publicKey));
        assert!(!scheme.isValidSignature(&signature, b"message", &publicKey[1..]));
        let mut longKey = publicKey.to_vec();
        longKey.push(0);
        assert!(!scheme.isValidSignature(&signature, b"message", &longKey));
        assert!(!scheme.isValidSignature(&[], b"message", publicKey));
        assert!(!scheme.isValidSignature(&signature, b"message", &[]));
    }
}

/// The formatted message M' of FIPS 204, Algorithm 2: zero, the context length, the context
/// and the message.
fn pureMessage(context: &[u8], message: &[u8]) -> Vec<u8> {
    let mut formatted = vec![0, context.len() as u8];
    formatted.extend_from_slice(context);
    formatted.extend_from_slice(message);
    formatted
}

/// The DER of the object identifier 2.16.840.1.101.3.4.2.1 of SHA-256, FIPS 204, Algorithm 4.
const sha256Identifier: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

#[test]
fn theSignatureFormsAreTheInternalSignatureOfTheirFormattedMessages() {
    for scheme in parameterSets {
        let keyPair = scheme.generateKeyPair(&mut random(8)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let publicKey = keyPair.publicKey.as_slice();
        let randomness = [9u8; 32];
        let message = b"the message";
        let context = b"the context";
        // OQS_SIG_sign is the context form with the empty context.
        let plain = scheme
            .sign(message, secretKey, &mut FixedRandom(randomness))
            .expect("signature");
        assert_eq!(
            scheme.internalSignature(&pureMessage(b"", message), secretKey, &randomness, false),
            Ok(plain.clone())
        );
        let withContext = scheme
            .signWithContext(message, context, secretKey, &mut FixedRandom(randomness))
            .expect("signature with a context");
        let formatted = pureMessage(context, message);
        assert_eq!(
            scheme.internalSignature(&formatted, secretKey, &randomness, false),
            Ok(withContext.clone())
        );
        assert!(scheme.isValidInternalSignature(&withContext, &formatted, publicKey, false));
        assert!(!scheme.isValidInternalSignature(&withContext, message, publicKey, false));
        // The external representative is mu = SHAKE256(tr || M', 64), with tr in the key.
        let mut representative = [0u8; 64];
        let mut sponge = SHAKE256::new();
        sponge.absorb(&secretKey[64..128]);
        sponge.absorb(&formatted);
        sponge.finalize().squeeze(&mut representative);
        assert_eq!(
            scheme.internalSignature(&representative, secretKey, &randomness, true),
            Ok(withContext.clone())
        );
        assert!(scheme.isValidInternalSignature(&withContext, &representative, publicKey, true));
        representative[0] ^= 1;
        assert!(!scheme.isValidInternalSignature(&withContext, &representative, publicKey, true));
        assert!(!scheme.isValidInternalSignature(
            &withContext,
            &representative[1..],
            publicKey,
            true
        ));
        // A pre-hash signature signs 1, the context length, the context, the identifier of
        // the hash function and the hash.
        let hash = [0x5Au8; 32];
        let preHashSigned = scheme
            .preHashSignature(
                &hash,
                PreHashAlgorithm::sha256,
                context,
                secretKey,
                &randomness,
            )
            .expect("pre-hash signature");
        let mut preHashMessage = vec![1, context.len() as u8];
        preHashMessage.extend_from_slice(context);
        preHashMessage.extend_from_slice(&sha256Identifier);
        preHashMessage.extend_from_slice(&hash);
        assert_eq!(
            scheme.internalSignature(&preHashMessage, secretKey, &randomness, false),
            Ok(preHashSigned.clone())
        );
        assert!(scheme.isValidPreHashSignature(
            &preHashSigned,
            &hash,
            PreHashAlgorithm::sha256,
            context,
            publicKey
        ));
        // The same hash under another function, context or key is not valid, and the forms
        // do not accept the signatures of each other.
        assert!(!scheme.isValidPreHashSignature(
            &preHashSigned,
            &hash,
            PreHashAlgorithm::sha3256,
            context,
            publicKey
        ));
        assert!(!scheme.isValidPreHashSignature(
            &preHashSigned,
            &hash,
            PreHashAlgorithm::sha256,
            b"other",
            publicKey
        ));
        assert!(!scheme.isValidPreHashSignature(
            &preHashSigned,
            &hash[1..],
            PreHashAlgorithm::sha256,
            context,
            publicKey
        ));
        assert!(!scheme.isValidPreHashSignature(
            &preHashSigned,
            &hash,
            PreHashAlgorithm::sha256,
            &[0; 256],
            publicKey
        ));
        assert!(!scheme.isValidSignatureWithContext(&preHashSigned, &hash, context, publicKey));
        assert!(!scheme.isValidPreHashSignature(
            &withContext,
            &hash,
            PreHashAlgorithm::sha256,
            context,
            publicKey
        ));
        assert!(!scheme.isValidSignatureWithContext(&withContext, message, b"", publicKey));
        assert!(scheme.isValidSignature(&plain, message, publicKey));
        assert!(!scheme.isValidSignature(&withContext, message, publicKey));
    }
}

#[test]
fn aChangeInEachPartOfASignatureIsRefused() {
    for scheme in parameterSets {
        let description = scheme.description();
        let keyPair = scheme.generateKeyPair(&mut random(10)).expect("key pair");
        let signature = scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut random(11))
            .expect("signature");
        let length = description.signatureLength;
        // The commitment hash starts the signature, the hint counts end it, and the response
        // and the hint places lie between them.
        let hintCountStart = length - (description.publicKeyLength - 32) / 320;
        for position in [
            0,
            31,
            100,
            length / 2,
            hintCountStart - 1,
            hintCountStart,
            length - 1,
        ] {
            for bit in [0, 7] {
                let mut changed = signature.clone();
                changed[position] ^= 1 << bit;
                assert!(
                    !scheme.isValidSignature(&changed, b"message", &keyPair.publicKey),
                    "{}: byte {position}, bit {bit}",
                    description.name
                );
            }
        }
        let mut changedKey = keyPair.publicKey.clone();
        changedKey[40] ^= 2;
        assert!(!scheme.isValidSignature(&signature, b"message", &changedKey));
        assert!(!scheme.isValidSignature(&signature, b"messagf", &keyPair.publicKey));
        assert!(scheme.isValidSignature(&signature, b"message", &keyPair.publicKey));
    }
}

#[test]
fn aSecretKeyWithCoefficientsOutOfRangeStillSignsAsTheCCodeDoes() {
    // mldsa-native decodes s1 and s2 with no range check, so a key with the half bytes 15 in
    // s1 signs. The parity tests compare such signatures with the C library.
    for scheme in parameterSets {
        let keyPair = scheme.generateKeyPair(&mut random(12)).expect("key pair");
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        for byte in &mut secretKey[128..160] {
            *byte = 0xFF;
        }
        let signature = scheme
            .internalSignature(b"message", &secretKey, &[0; 32], false)
            .expect("a signature");
        assert_eq!(signature.len(), scheme.description().signatureLength);
        assert_eq!(
            scheme.internalSignature(b"message", &secretKey, &[0; 32], false),
            Ok(signature)
        );
    }
}
