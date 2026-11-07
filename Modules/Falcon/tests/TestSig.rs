//! The correctness test of liboqs `tests/test_sig.c` for each parameter set, and the accept and
//! reject decisions of the Falcon code of PQClean and of the liboqs wrappers: the formats of the
//! keys and the signatures, the random requests, and each refused input.

use OQSNativeAlgorithmTests::SignatureCorrectnessTest;
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError};
use OQSNativeFalcon::Falcon;
use OQSNativeKATRandom::NISTKATRandom;

const parameterSets: [&Falcon; 4] = [
    &Falcon::falcon512,
    &Falcon::falcon1024,
    &Falcon::falconPadded512,
    &Falcon::falconPadded1024,
];

/// The degree logarithm of each set, in the order of `parameterSets`.
const lognValues: [u8; 4] = [9, 10, 9, 10];

/// The length of a padded signature of the degree of each set.
const paddedLengths: [usize; 4] = [666, 1280, 666, 1280];

/// The length of the header byte and the nonce of a signature.
const prefixLength: usize = 41;

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

/// A key pair and a signature of the message.
fn signed(scheme: &Falcon, seed: u8) -> (KeyPair, Vec<u8>) {
    let keyPair = scheme.generateKeyPair(&mut random(seed)).expect("key pair");
    let signature = scheme
        .sign(message, keyPair.secretKey.bytes(), &mut random(seed + 1))
        .expect("signature");
    (keyPair, signature)
}

/// The bit of a value at a position. The first bit is the high bit of the first byte.
fn bit(value: &[u8], position: usize) -> u8 {
    (value[position / 8] >> (7 - position % 8)) & 1
}

/// The coefficients of a compressed value of degree `n`, each with the position of its sign
/// bit, and the number of bits that they take. A coefficient is a sign bit, the seven low bits
/// of its absolute value, and the high bits in unary: a zero for each 128, then a one.
fn compressedLayout(value: &[u8], n: usize) -> (Vec<(usize, i32)>, usize) {
    let mut position = 0;
    let mut coefficients = Vec::with_capacity(n);
    for _ in 0..n {
        let start = position;
        let mut magnitude = (1..8).fold(0, |low, offset| {
            (low << 1) | i32::from(bit(value, start + offset))
        });
        position += 8;
        while bit(value, position) == 0 {
            magnitude += 128;
            position += 1;
        }
        position += 1;
        let sign = if bit(value, start) == 1 { -1 } else { 1 };
        coefficients.push((start, sign * magnitude));
    }
    (coefficients, position)
}

/// The length of a signature without its zero padding.
fn compressedLength(signature: &[u8], n: usize) -> usize {
    let (_, bitLength) = compressedLayout(&signature[prefixLength..], n);
    prefixLength + bitLength.div_ceil(8)
}

#[test]
fn testSigPassesForEveryParameterSet() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        assert_eq!(
            SignatureCorrectnessTest::run(scheme, &mut random(index as u8)),
            Ok(())
        );
    }
}

#[test]
fn eachSetHasTheFactsOfItsLiboqsFile() {
    let facts: [(&str, u8, usize, usize, usize); 4] = [
        ("Falcon-512", 1, 897, 1281, 752),
        ("Falcon-1024", 5, 1793, 2305, 1462),
        ("Falcon-padded-512", 1, 897, 1281, 666),
        ("Falcon-padded-1024", 5, 1793, 2305, 1280),
    ];
    for (scheme, (name, level, publicKeyLength, secretKeyLength, signatureLength)) in
        parameterSets.into_iter().zip(facts)
    {
        let description = scheme.description();
        assert_eq!(description.name, name);
        assert_eq!(
            description.algorithmVersion,
            "20211101 with PQClean patches"
        );
        assert_eq!(description.claimedNISTLevel, level);
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
fn aKeyPairDrawsOneSeedAndASignatureANonceAndThenASeed() {
    for scheme in parameterSets {
        let mut recording = RecordingRandom {
            inner: random(1),
            requests: Vec::new(),
        };
        let keyPair = scheme.generateKeyPair(&mut recording).expect("key pair");
        assert_eq!(recording.requests, vec![48]);
        recording.requests.clear();
        let signature = scheme
            .sign(message, keyPair.secretKey.bytes(), &mut recording)
            .expect("signature");
        assert_eq!(recording.requests, vec![40, 48]);
        // The nonce in the signature is the request after the seed of the key pair.
        let mut replay = random(1);
        replay.fillRandomBytes(&mut [0u8; 48]);
        let mut nonce = [0u8; 40];
        replay.fillRandomBytes(&mut nonce);
        assert_eq!(&signature[1..prefixLength], &nonce);
    }
}

#[test]
fn keysAndSignaturesHaveTheHeaderBytesAndLengthsOfTheirFormats() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let logn = lognValues[index];
        let description = scheme.description();
        let (keyPair, signature) = signed(scheme, 3);
        assert_eq!(keyPair.publicKey.len(), description.publicKeyLength);
        assert_eq!(keyPair.publicKey[0], logn);
        assert_eq!(keyPair.secretKey.bytes().len(), description.secretKeyLength);
        assert_eq!(keyPair.secretKey.bytes()[0], 0x50 + logn);
        assert_eq!(signature[0], 0x30 + logn);
        let length = compressedLength(&signature, 1 << logn);
        if index >= 2 {
            // The padded sets pad the compressed value with zeros.
            assert_eq!(signature.len(), description.signatureLength);
            assert!(signature[length..].iter().all(|byte| *byte == 0));
        } else {
            assert_eq!(signature.len(), length);
        }
        assert!(scheme.isValidSignature(&signature, message, &keyPair.publicKey));
    }
}

#[test]
fn aSecretKeyOfAWrongLengthIsALengthError() {
    for scheme in parameterSets {
        let description = scheme.description();
        let keyPair = scheme.generateKeyPair(&mut random(4)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let longer = [secretKey, &[0]].concat();
        for wrong in [&secretKey[1..], &longer[..], &[]] {
            assert_eq!(
                scheme.sign(message, wrong, &mut random(5)),
                Err(OQSError::invalidLength {
                    expected: description.secretKeyLength,
                    actual: wrong.len()
                })
            );
        }
    }
}

#[test]
fn aSecretKeyThatDoesNotDecodeIsRefusedBeforeAnyRandomByte() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let logn = lognValues[index];
        let keyPair = scheme.generateKeyPair(&mut random(6)).expect("key pair");
        let signedWith = |secretKey: &[u8]| {
            let mut recording = RecordingRandom {
                inner: random(7),
                requests: Vec::new(),
            };
            let result = scheme.sign(message, secretKey, &mut recording).map(|_| ());
            (result, recording.requests)
        };
        let refused = (Err(OQSError::operationFailed), Vec::new());
        // The header byte of the other degree.
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        secretKey[0] = 0x50 + (19 - logn);
        assert_eq!(signedWith(&secretKey), refused, "{index}");
        // The first coefficient of f becomes -2^(bits - 1), the forbidden value: 100000 in six
        // bits for Falcon-512, and 10000 in five bits for Falcon-1024.
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        secretKey[1] = if logn == 9 {
            0x80 | (secretKey[1] & 0x03)
        } else {
            0x80 | (secretKey[1] & 0x07)
        };
        assert_eq!(signedWith(&secretKey), refused, "{index}");
        // The last coefficient of F becomes -128, the forbidden value in eight bits.
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        let last = secretKey.len() - 1;
        secretKey[last] = 0x80;
        assert_eq!(signedWith(&secretKey), refused, "{index}");
        // f = 0 is not invertible modulo q, so G does not exist.
        let fLength = if logn == 9 { 384 } else { 640 };
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        secretKey[1..1 + fLength].fill(0);
        assert_eq!(signedWith(&secretKey), refused, "{index}");
        // f = 1 makes G = g F modulo q, whose coefficients are not all within 127.
        secretKey[1] = if logn == 9 { 0x04 } else { 0x08 };
        assert_eq!(signedWith(&secretKey), refused, "{index}");
        // The unchanged key signs.
        assert_eq!(
            signedWith(keyPair.secretKey.bytes()),
            (Ok(()), vec![40, 48]),
            "{index}"
        );
    }
}

#[test]
fn aSignatureIsAcceptedOnlyForItsMessageAndItsKey() {
    for scheme in parameterSets {
        let (keyPair, signature) = signed(scheme, 8);
        let (otherKeys, _) = signed(scheme, 10);
        assert!(scheme.isValidSignature(&signature, message, &keyPair.publicKey));
        assert!(!scheme.isValidSignature(&signature, b"the quick brown box", &keyPair.publicKey));
        assert!(!scheme.isValidSignature(&signature, b"", &keyPair.publicKey));
        assert!(!scheme.isValidSignature(&signature, message, &otherKeys.publicKey));
        // A changed nonce changes the hashed message.
        let mut changed = signature.clone();
        changed[20] ^= 0x01;
        assert!(!scheme.isValidSignature(&changed, message, &keyPair.publicKey));
    }
}

#[test]
fn aPublicKeyThatDoesNotDecodeIsRefused() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let logn = lognValues[index];
        let (keyPair, signature) = signed(scheme, 11);
        let publicKey = &keyPair.publicKey;
        // The decoding reads only the bytes of the key, so the longer key would verify without
        // the length check.
        assert!(!scheme.isValidSignature(&signature, message, &publicKey[1..]));
        let longer = [publicKey, &[0][..]].concat();
        assert!(!scheme.isValidSignature(&signature, message, &longer));
        assert!(!scheme.isValidSignature(&signature, message, &[]));
        let mut changed = publicKey.clone();
        changed[0] = 19 - logn;
        assert!(!scheme.isValidSignature(&signature, message, &changed));
        // The first coefficient becomes 12289 = 0x3001, the first value that is too large.
        let mut changed = publicKey.clone();
        changed[1] = 0xC0;
        changed[2] = (changed[2] & 0x03) | 0x04;
        assert!(!scheme.isValidSignature(&signature, message, &changed));
    }
}

#[test]
fn aSignatureThatDoesNotDecodeIsRefused() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let logn = lognValues[index];
        let (keyPair, signature) = signed(scheme, 12);
        let publicKey = &keyPair.publicKey;
        for length in [0, 1, 40, 41] {
            assert!(!scheme.isValidSignature(&signature[..length], message, publicKey));
        }
        let mut changed = signature.clone();
        changed[0] = 0x30 + (19 - logn);
        assert!(!scheme.isValidSignature(&changed, message, publicKey));
        // The value ends before the last coefficient.
        let length = compressedLength(&signature, 1 << logn);
        let truncated = &signature[..prefixLength + (length - prefixLength) / 2];
        assert!(!scheme.isValidSignature(truncated, message, publicKey));
    }
}

#[test]
fn aNegativeZeroIsRefusedThoughTheVectorIsTheSame() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let n = 1usize << lognValues[index];
        let keyPair = scheme.generateKeyPair(&mut random(20)).expect("key pair");
        // The first signature with a zero coefficient.
        let (signature, start) = (21..60)
            .find_map(|seed| {
                let signature = scheme
                    .sign(message, keyPair.secretKey.bytes(), &mut random(seed))
                    .expect("signature");
                let (coefficients, _) = compressedLayout(&signature[prefixLength..], n);
                let (start, _) = coefficients.into_iter().find(|(_, value)| *value == 0)?;
                Some((signature, start))
            })
            .expect("a signature with a zero coefficient");
        let mut negative = signature.clone();
        negative[prefixLength + start / 8] |= 0x80 >> (start % 8);
        assert!(scheme.isValidSignature(&signature, message, &keyPair.publicKey));
        assert!(!scheme.isValidSignature(&negative, message, &keyPair.publicKey));
    }
}

#[test]
fn aSetPaddingBitIsRefusedThoughTheVectorIsTheSame() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let n = 1usize << lognValues[index];
        let keyPair = scheme.generateKeyPair(&mut random(30)).expect("key pair");
        // The first signature whose value does not end on a byte boundary.
        let (signature, bitLength) = (31..70)
            .find_map(|seed| {
                let signature = scheme
                    .sign(message, keyPair.secretKey.bytes(), &mut random(seed))
                    .expect("signature");
                let (_, bitLength) = compressedLayout(&signature[prefixLength..], n);
                (bitLength % 8 != 0).then_some((signature, bitLength))
            })
            .expect("a value with padding bits");
        let mut changed = signature.clone();
        changed[prefixLength + bitLength / 8] |= 0x01;
        assert!(scheme.isValidSignature(&signature, message, &keyPair.publicKey));
        assert!(!scheme.isValidSignature(&changed, message, &keyPair.publicKey));
    }
}

#[test]
fn aSignatureVectorAboveTheNormBoundIsRefused() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let n = 1usize << lognValues[index];
        let (keyPair, signature) = signed(scheme, 13);
        // Each coefficient is 1000: sign 0, low bits 1101000, then seven zeros and the stop
        // bit. The value decodes, and its norm is far above the bound.
        let value: Vec<u8> = (0..n).flat_map(|_| [0x68, 0x01]).collect();
        let (coefficients, _) = compressedLayout(&value, n);
        assert!(coefficients.iter().all(|(_, value)| *value == 1000));
        let large = [&signature[..prefixLength], &value[..]].concat();
        assert!(!scheme.isValidSignature(&large, message, &keyPair.publicKey));
    }
}

#[test]
fn trailingBytesAreRefusedExceptZerosUpToThePaddedLength() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let paddedLength = paddedLengths[index];
        let (keyPair, signature) = signed(scheme, 14);
        let publicKey = &keyPair.publicKey;
        let length = compressedLength(&signature, 1 << lognValues[index]);
        assert!(length < paddedLength - 1, "{index}");
        // A compressed signature, with no padding, verifies in both forms, and a zero after it
        // does not.
        let mut compressed = signature[..length].to_vec();
        assert!(
            scheme.isValidSignature(&compressed, message, publicKey),
            "{index}"
        );
        compressed.push(0);
        assert!(
            !scheme.isValidSignature(&compressed, message, publicKey),
            "{index}"
        );
        // Zeros up to the padded length verify, and a nonzero byte or one more zero does not.
        let mut padded = signature[..length].to_vec();
        padded.resize(paddedLength, 0);
        assert!(
            scheme.isValidSignature(&padded, message, publicKey),
            "{index}"
        );
        let mut nonZero = padded.clone();
        nonZero[paddedLength - 1] = 1;
        assert!(
            !scheme.isValidSignature(&nonZero, message, publicKey),
            "{index}"
        );
        let mut longer = padded.clone();
        longer.push(0);
        assert!(
            !scheme.isValidSignature(&longer, message, publicKey),
            "{index}"
        );
    }
}

#[test]
fn bothFormsOfADegreeShareTheirKeysAndVerifyTheSignaturesOfTheOther() {
    for (compressed, padded) in [
        (&Falcon::falcon512, &Falcon::falconPadded512),
        (&Falcon::falcon1024, &Falcon::falconPadded1024),
    ] {
        let keyPair = compressed
            .generateKeyPair(&mut random(15))
            .expect("key pair");
        let paddedKeyPair = padded.generateKeyPair(&mut random(15)).expect("key pair");
        assert_eq!(keyPair.publicKey, paddedKeyPair.publicKey);
        assert_eq!(keyPair.secretKey.bytes(), paddedKeyPair.secretKey.bytes());
        let compressedSignature = compressed
            .sign(message, keyPair.secretKey.bytes(), &mut random(16))
            .expect("signature");
        let paddedSignature = padded
            .sign(message, keyPair.secretKey.bytes(), &mut random(16))
            .expect("signature");
        // The same random bytes give the same vector. When its compressed value fits the padded
        // length, as here, the padded signature is the compressed one with zeros.
        let length = compressedSignature.len();
        assert!(length <= padded.description().signatureLength);
        assert_eq!(&paddedSignature[..length], &compressedSignature[..]);
        assert!(padded.isValidSignature(&compressedSignature, message, &keyPair.publicKey));
        assert!(compressed.isValidSignature(&paddedSignature, message, &keyPair.publicKey));
    }
}

#[test]
fn falconSignsWithoutAContextString() {
    for scheme in parameterSets {
        let keyPair = scheme.generateKeyPair(&mut random(17)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        assert_eq!(
            scheme.signWithContext(message, b"c", secretKey, &mut random(18)),
            Err(OQSError::contextNotSupported)
        );
        let signature = scheme
            .signWithContext(message, b"", secretKey, &mut random(18))
            .expect("the empty context signs");
        let plain = scheme
            .sign(message, secretKey, &mut random(18))
            .expect("signature");
        assert_eq!(signature, plain);
        let publicKey = &keyPair.publicKey;
        assert!(scheme.isValidSignatureWithContext(&signature, message, b"", publicKey));
        assert!(!scheme.isValidSignatureWithContext(&signature, message, b"c", publicKey));
    }
}
