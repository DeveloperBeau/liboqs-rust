//! The correctness test of liboqs `tests/test_sig.c` through `SignatureCorrectnessTest`, and the
//! rejection paths of SLH-DSA: the lengths, the context, the random requests, and changed
//! signatures, messages, contexts and keys.

use OQSNativeAlgorithmTests::{SignatureCorrectnessTest, SuiteSample};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSHA2::SHA256;
use OQSNativeSLHDSA::{PreHash, SLHDSA};

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

/// Runs the correctness test on a scheme with the NIST DRBG of a seed byte, and names the
/// scheme and the seed in a failure.
fn checkCorrectness(scheme: &dyn Signing, seed: u8) {
    assert_eq!(
        SignatureCorrectnessTest::run(scheme, &mut random(seed)),
        Ok(()),
        "{}, the NIST DRBG seeded with 48 bytes {seed}",
        scheme.description().name
    );
}

/// A random source that gives the bytes 0, 1, 2 and so on, and records the length of each
/// request.
#[derive(Default)]
struct RecordingRandom {
    requests: Vec<usize>,
    next: u8,
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.requests.push(bytes.len());
        for byte in bytes.iter_mut() {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }
}

/// A random source that gives the bytes of a buffer once, in order.
struct FixedRandom(Vec<u8>);

impl RandomGenerating for FixedRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        assert!(
            bytes.len() <= self.0.len(),
            "the request is longer than the buffer"
        );
        let rest = self.0.split_off(bytes.len());
        bytes.copy_from_slice(&self.0);
        self.0 = rest;
    }
}

/// The schemes of the suite sample, in liboqs order.
fn sampleSchemes() -> Vec<&'static dyn Signing> {
    SLHDSA::schemes
        .iter()
        .copied()
        .filter(|scheme| SuiteSample::contains(scheme.description().name))
        .collect()
}

#[test]
fn testSigPassesForEachPureSchemeOfTheSuiteSample() {
    let schemes: Vec<&dyn Signing> = sampleSchemes()
        .into_iter()
        .filter(|scheme| scheme.description().name.contains("PURE"))
        .collect();
    assert_eq!(schemes.len(), 6);
    for (index, scheme) in schemes.into_iter().enumerate() {
        checkCorrectness(scheme, index as u8);
    }
}

/// Runs the correctness test on the pre-hash schemes of the suite sample whose names pass a
/// filter, six of them.
fn runPreHashSchemesOfTheSuiteSample(isSelected: fn(&str) -> bool, seed: u8) {
    let schemes: Vec<&dyn Signing> = sampleSchemes()
        .into_iter()
        .filter(|scheme| {
            let name = scheme.description().name;
            name.contains("PREHASH") && isSelected(name)
        })
        .collect();
    assert_eq!(schemes.len(), 6);
    for (index, scheme) in schemes.into_iter().enumerate() {
        checkCorrectness(scheme, seed + index as u8);
    }
}

#[test]
fn testSigPassesForEachSHA2PreHashSchemeOfTheSuiteSample() {
    runPreHashSchemesOfTheSuiteSample(|name| name.starts_with("SLH_DSA_SHA2_"), 20);
}

#[test]
fn testSigPassesForEachSHA3AndSHAKEPreHashSchemeOfTheSuiteSample() {
    runPreHashSchemesOfTheSuiteSample(|name| !name.starts_with("SLH_DSA_SHA2_"), 30);
}

#[test]
#[ignore = "the 156 schemes sign for an hour in a debug build, and parity run checks them in release builds"]
fn testSigPassesForEveryScheme() {
    for (index, scheme) in SLHDSA::schemes.iter().enumerate() {
        checkCorrectness(*scheme, index as u8);
    }
}

/// One fast scheme of each hash family and one pre-hash form, for the rejection tests.
fn rejectionSchemes() -> [SLHDSA; 4] {
    [
        SLHDSA::sha2128f,
        SLHDSA::shake128f,
        SLHDSA::sha2192f,
        SLHDSA::sha2128f.preHashed(PreHash::sha256),
    ]
}

#[test]
fn keyPairsAndSignaturesDrawTheirBytesInOneRequestEach() {
    for scheme in [
        SLHDSA::sha2128f,
        SLHDSA::shake192f,
        SLHDSA::sha2256f,
        SLHDSA::shake256f.preHashed(PreHash::shake256),
    ] {
        let n = scheme.description().publicKeyLength / 2;
        let mut random = RecordingRandom::default();
        let keyPair = scheme.generateKeyPair(&mut random).expect("key pair");
        // SK.seed, SK.prf and PK.seed in one request of 3 n bytes.
        assert_eq!(random.requests, [3 * n]);
        let secretKey = keyPair.secretKey.bytes();
        let seeds: Vec<u8> = (0..3 * n as u8).collect();
        assert_eq!(&secretKey[..3 * n], seeds.as_slice());
        assert_eq!(&keyPair.publicKey[..n], &seeds[2 * n..]);
        assert_eq!(&keyPair.publicKey[n..], &secretKey[3 * n..]);
        scheme
            .sign(b"message", secretKey, &mut random)
            .expect("signature");
        scheme
            .signWithContext(b"message", b"context", secretKey, &mut random)
            .expect("signature");
        assert_eq!(random.requests, [3 * n, n, n]);
    }
}

#[test]
fn aContextOfMoreThan255BytesIsRefusedAfterTheRandomRequest() {
    for scheme in rejectionSchemes() {
        let n = scheme.description().publicKeyLength / 2;
        let keyPair = scheme.generateKeyPair(&mut random(1)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let mut recording = RecordingRandom::default();
        assert_eq!(
            scheme.signWithContext(b"message", &[7; 256], secretKey, &mut recording),
            Err(OQSError::contextTooLong)
        );
        // The C code draws `addrnd` before it checks the context.
        assert_eq!(recording.requests, [n]);
        let longest = [7u8; 255];
        let signature = scheme
            .signWithContext(b"message", &longest, secretKey, &mut random(2))
            .expect("a context of 255 bytes");
        assert!(scheme.isValidSignatureWithContext(
            &signature,
            b"message",
            &longest,
            &keyPair.publicKey
        ));
        assert!(!scheme.isValidSignatureWithContext(
            &signature,
            b"message",
            &[7; 256],
            &keyPair.publicKey
        ));
        assert!(!scheme.isValidSignatureWithContext(
            &signature,
            b"message",
            &longest[1..],
            &keyPair.publicKey
        ));
    }
}

#[test]
fn eachInputOfAWrongLengthIsALengthErrorOrARejection() {
    for scheme in rejectionSchemes() {
        let description = scheme.description();
        let n = description.publicKeyLength / 2;
        let keyPair = scheme.generateKeyPair(&mut random(3)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let publicKey = keyPair.publicKey.as_slice();
        let lengthError =
            |expected: usize, actual: usize| Err(OQSError::invalidLength { expected, actual });
        for wrongLength in [secretKey.len() - 1, secretKey.len() + 1, 0] {
            let mut wrongKey = secretKey.to_vec();
            wrongKey.resize(wrongLength, 0);
            assert_eq!(
                scheme.sign(b"message", &wrongKey, &mut random(4)),
                lengthError(4 * n, wrongLength)
            );
            assert_eq!(
                scheme.signWithContext(b"message", b"ctx", &wrongKey, &mut random(4)),
                lengthError(4 * n, wrongLength)
            );
            assert_eq!(
                scheme.signInternal(b"message", &wrongKey, &[0; 32][..n]),
                lengthError(4 * n, wrongLength)
            );
        }
        assert_eq!(
            scheme.signInternal(b"message", secretKey, &[0; 33][..n + 1]),
            lengthError(n, n + 1)
        );
        assert_eq!(
            scheme.signInternal(b"message", secretKey, &[0; 32][..n - 1]),
            lengthError(n, n - 1)
        );
        let signature = scheme
            .sign(b"message", secretKey, &mut random(5))
            .expect("signature");
        assert_eq!(signature.len(), description.signatureLength);
        assert!(scheme.isValidSignature(&signature, b"message", publicKey));
        let mut longer = signature.clone();
        longer.push(0);
        assert!(!scheme.isValidSignature(&longer, b"message", publicKey));
        assert!(!scheme.isValidSignature(&signature[1..], b"message", publicKey));
        assert!(!scheme.isValidSignature(&[], b"message", publicKey));
        assert!(!scheme.isValidSignature(&signature, b"message", &publicKey[1..]));
        let mut longerKey = publicKey.to_vec();
        longerKey.push(0);
        assert!(!scheme.isValidSignature(&signature, b"message", &longerKey));
        assert!(!scheme.isValidSignatureInternal(&signature[..n], b"message", publicKey));
    }
}

#[test]
fn aChangedSignatureMessageContextOrKeyIsRejected() {
    for scheme in rejectionSchemes() {
        let description = scheme.description();
        let n = description.publicKeyLength / 2;
        let keyPair = scheme.generateKeyPair(&mut random(6)).expect("key pair");
        let publicKey = keyPair.publicKey.as_slice();
        let signature = scheme
            .signWithContext(
                b"message",
                b"ctx",
                keyPair.secretKey.bytes(),
                &mut random(7),
            )
            .expect("signature");
        let isValid = |signature: &[u8], message: &[u8], context: &[u8], publicKey: &[u8]| {
            scheme.isValidSignatureWithContext(signature, message, context, publicKey)
        };
        assert!(isValid(&signature, b"message", b"ctx", publicKey));
        // The randomizer R, a FORS value, an XMSS value of the first and of the last layer.
        let forsStart = n;
        let hypertreeStart = n + (description.signatureLength - n) / 4;
        for position in [
            0,
            n - 1,
            forsStart + 3,
            hypertreeStart,
            description.signatureLength - 1,
        ] {
            let mut changed = signature.clone();
            changed[position] ^= 0x01;
            assert!(
                !isValid(&changed, b"message", b"ctx", publicKey),
                "{}, byte {position}",
                description.name
            );
        }
        // The same bit in two bytes, so that an exclusive or of their differences would cancel.
        let mut twice = signature.clone();
        twice[hypertreeStart] ^= 0x10;
        twice[hypertreeStart + 1] ^= 0x10;
        assert!(!isValid(&twice, b"message", b"ctx", publicKey));
        assert!(!isValid(&signature, b"messagf", b"ctx", publicKey));
        assert!(!isValid(&signature, b"message", b"ctX", publicKey));
        assert!(!isValid(&signature, b"message", b"", publicKey));
        assert!(!scheme.isValidSignature(&signature, b"message", publicKey));
        for position in [0, n] {
            let mut changedKey = publicKey.to_vec();
            changedKey[position] ^= 0x80;
            assert!(!isValid(&signature, b"message", b"ctx", &changedKey));
        }
    }
}

#[test]
fn pureAndPreHashFormsOfASetRejectTheSignaturesOfEachOther() {
    let pure = SLHDSA::shake128f;
    let forms = [
        pure,
        pure.preHashed(PreHash::sha256),
        pure.preHashed(PreHash::sha512),
        pure.preHashed(PreHash::shake128),
    ];
    let keyPair = pure.generateKeyPair(&mut random(8)).expect("key pair");
    for (signerIndex, signer) in forms.iter().enumerate() {
        let signature = signer
            .sign(b"message", keyPair.secretKey.bytes(), &mut random(9))
            .expect("signature");
        for (verifierIndex, verifier) in forms.iter().enumerate() {
            assert_eq!(
                verifier.isValidSignature(&signature, b"message", &keyPair.publicKey),
                signerIndex == verifierIndex,
                "{} and {}",
                signer.description().name,
                verifier.description().name
            );
        }
    }
}

#[test]
fn pureFormSignsThePrefixedMessageOfFIPS205Algorithm22() {
    // M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M, signed by slh_sign_internal.
    for scheme in [SLHDSA::sha2128f, SLHDSA::shake192f] {
        let n = scheme.description().publicKeyLength / 2;
        let keyPair = scheme.generateKeyPair(&mut random(10)).expect("key pair");
        let additionalRandomness: Vec<u8> = (100..100 + n as u8).collect();
        let signature = scheme
            .signWithContext(
                b"message",
                b"context",
                keyPair.secretKey.bytes(),
                &mut FixedRandom(additionalRandomness.clone()),
            )
            .expect("signature");
        let mut prefixed = vec![0, 7];
        prefixed.extend_from_slice(b"context");
        prefixed.extend_from_slice(b"message");
        assert_eq!(
            scheme.signInternal(&prefixed, keyPair.secretKey.bytes(), &additionalRandomness),
            Ok(signature.clone())
        );
        assert!(scheme.isValidSignatureInternal(&signature, &prefixed, &keyPair.publicKey));
        assert!(!scheme.isValidSignatureInternal(&signature, b"message", &keyPair.publicKey));
    }
}

#[test]
fn preHashFormSignsTheDigestMessageOfFIPS205Algorithm23() {
    // M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M), with the DER encoding of
    // the object identifier 2.16.840.1.101.3.4.2.1 of SHA-256.
    let scheme = SLHDSA::sha2128f.preHashed(PreHash::sha256);
    let keyPair = scheme.generateKeyPair(&mut random(11)).expect("key pair");
    let additionalRandomness = [0x42u8; 16];
    let signature = scheme
        .signWithContext(
            b"message",
            b"ctx",
            keyPair.secretKey.bytes(),
            &mut FixedRandom(additionalRandomness.to_vec()),
        )
        .expect("signature");
    let mut prefixed = vec![1, 3];
    prefixed.extend_from_slice(b"ctx");
    prefixed.extend_from_slice(&[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ]);
    prefixed.extend_from_slice(&SHA256::hash(b"message"));
    assert_eq!(
        SLHDSA::sha2128f.signInternal(&prefixed, keyPair.secretKey.bytes(), &additionalRandomness),
        Ok(signature.clone())
    );
    assert!(SLHDSA::sha2128f.isValidSignatureInternal(&signature, &prefixed, &keyPair.publicKey));
}

#[test]
fn theSameRandomBytesGiveTheSameSignatureAndOtherBytesAnotherOne() {
    for scheme in rejectionSchemes() {
        let keyPair = scheme.generateKeyPair(&mut random(12)).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let first = scheme
            .sign(b"message", secretKey, &mut random(13))
            .expect("signature");
        let again = scheme
            .sign(b"message", secretKey, &mut random(13))
            .expect("signature");
        let other = scheme
            .sign(b"message", secretKey, &mut random(14))
            .expect("signature");
        assert_eq!(first, again);
        assert_ne!(first, other);
        assert!(scheme.isValidSignature(&other, b"message", &keyPair.publicKey));
        // The empty context of `signWithContext` is the plain signature.
        assert_eq!(
            scheme.signWithContext(b"message", b"", secretKey, &mut random(13)),
            Ok(first)
        );
    }
}

#[test]
fn theSecretKeyGivesTheRootOfItsMessageHashAndThePRFKeyOnlyTheRandomizer() {
    // As in the C code, the signature uses the PK.root of the secret key. A changed root
    // gives a signature that the public key rejects. A changed SK.prf changes only the
    // randomizer R, so the signature still verifies.
    for scheme in [SLHDSA::sha2128f, SLHDSA::shake128f] {
        let n = scheme.description().publicKeyLength / 2;
        let keyPair = scheme.generateKeyPair(&mut random(15)).expect("key pair");
        let mut changedRoot = keyPair.secretKey.bytes().to_vec();
        changedRoot[4 * n - 1] ^= 1;
        let signature = scheme
            .sign(b"message", &changedRoot, &mut random(16))
            .expect("a signature with any secret key");
        assert!(!scheme.isValidSignature(&signature, b"message", &keyPair.publicKey));
        let mut changedPRFKey = keyPair.secretKey.bytes().to_vec();
        changedPRFKey[n] ^= 1;
        let signature = scheme
            .sign(b"message", &changedPRFKey, &mut random(16))
            .expect("signature");
        assert!(scheme.isValidSignature(&signature, b"message", &keyPair.publicKey));
        let original = scheme
            .sign(b"message", keyPair.secretKey.bytes(), &mut random(16))
            .expect("signature");
        assert_ne!(signature[..n], original[..n]);
    }
}
