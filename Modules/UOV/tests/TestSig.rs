//! The correctness test of liboqs `tests/test_sig.c` for each parameter set, and the accept and
//! reject decisions of the UOV reference code and of the liboqs wrappers: the random requests,
//! the lengths, the three forms of the keys, a public key made by hand, and each refused input.

use OQSNativeAlgorithmTests::SignatureCorrectnessTest;
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSHA3::SHAKE256;
use OQSNativeUOV::UOV;

/// The twelve sets in the order of the liboqs list: the classic sets, the sets with a
/// compressed public key, and the sets with compressed keys.
const parameterSets: [&UOV; 12] = [
    &UOV::ovIs,
    &UOV::ovIp,
    &UOV::ovIII,
    &UOV::ovV,
    &UOV::ovIsCompressedPublicKey,
    &UOV::ovIpCompressedPublicKey,
    &UOV::ovIIICompressedPublicKey,
    &UOV::ovVCompressedPublicKey,
    &UOV::ovIsCompressedKeys,
    &UOV::ovIpCompressedKeys,
    &UOV::ovIIICompressedKeys,
    &UOV::ovVCompressedKeys,
];

/// The vinegar variables v, the oil variables o and the elements of a byte of the four shapes,
/// from `params.h`. The set at index i of `parameterSets` has the shape at `i % 4`.
const shapes: [(usize, usize, usize); 4] = [(96, 64, 2), (68, 44, 1), (112, 72, 1), (148, 96, 1)];

/// The length of the salt at the end of a signature.
const saltLength: usize = 16;

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

fn randomBytes(seed: u8, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random(seed).fillRandomBytes(&mut bytes);
    bytes
}

fn checkTestSig(index: usize) {
    assert_eq!(
        SignatureCorrectnessTest::run(parameterSets[index], &mut random(index as u8)),
        Ok(())
    );
}

#[test]
fn testSigPassesForOVIs() {
    checkTestSig(0);
}

#[test]
fn testSigPassesForOVIp() {
    checkTestSig(1);
}

#[test]
fn testSigPassesForOVIII() {
    checkTestSig(2);
}

#[test]
fn testSigPassesForOVV() {
    checkTestSig(3);
}

#[test]
fn testSigPassesForOVIsWithACompressedPublicKey() {
    checkTestSig(4);
}

#[test]
fn testSigPassesForOVIpWithACompressedPublicKey() {
    checkTestSig(5);
}

#[test]
fn testSigPassesForOVIIIWithACompressedPublicKey() {
    checkTestSig(6);
}

#[test]
fn testSigPassesForOVVWithACompressedPublicKey() {
    checkTestSig(7);
}

#[test]
fn testSigPassesForOVIsWithCompressedKeys() {
    checkTestSig(8);
}

#[test]
fn testSigPassesForOVIpWithCompressedKeys() {
    checkTestSig(9);
}

#[test]
fn testSigPassesForOVIIIWithCompressedKeys() {
    checkTestSig(10);
}

#[test]
fn testSigPassesForOVVWithCompressedKeys() {
    checkTestSig(11);
}

#[test]
fn eachSetHasTheFactsOfItsLiboqsFile() {
    // `src/sig/uov/sig_uov_ov_<set>.c` and `sig_uov.h` of liboqs 0.16.0.
    let facts: [(&str, u8, usize, usize, usize); 12] = [
        ("OV-Is", 1, 412160, 348704, 96),
        ("OV-Ip", 1, 278432, 237896, 128),
        ("OV-III", 3, 1225440, 1044320, 200),
        ("OV-V", 5, 2869440, 2436704, 260),
        ("OV-Is-pkc", 1, 66576, 348704, 96),
        ("OV-Ip-pkc", 1, 43576, 237896, 128),
        ("OV-III-pkc", 3, 189232, 1044320, 200),
        ("OV-V-pkc", 5, 446992, 2436704, 260),
        ("OV-Is-pkc-skc", 1, 66576, 32, 96),
        ("OV-Ip-pkc-skc", 1, 43576, 32, 128),
        ("OV-III-pkc-skc", 3, 189232, 32, 200),
        ("OV-V-pkc-skc", 5, 446992, 32, 260),
    ];
    for (scheme, (name, level, publicKeyLength, secretKeyLength, signatureLength)) in
        parameterSets.into_iter().zip(facts)
    {
        let description = scheme.description();
        assert_eq!(description.name, name);
        assert_eq!(description.algorithmVersion, "Round 2");
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
fn aKeyPairDrawsOneSeedAndASignatureOneSaltAtTheEndOfTheSignature() {
    for scheme in parameterSets {
        let description = scheme.description();
        let mut recording = RecordingRandom::new(1);
        let keyPair = scheme.generateKeyPair(&mut recording).expect("key pair");
        assert_eq!(recording.requests, vec![32], "{}", description.name);
        assert_eq!(keyPair.publicKey.len(), description.publicKeyLength);
        assert_eq!(keyPair.secretKey.bytes().len(), description.secretKeyLength);
        recording.requests.clear();
        let signature = scheme
            .sign(message, keyPair.secretKey.bytes(), &mut recording)
            .expect("signature");
        assert_eq!(recording.requests, vec![16], "{}", description.name);
        assert_eq!(signature.len(), description.signatureLength);
        // The salt is the request after the seed of the key pair.
        let mut replay = random(1);
        replay.fillRandomBytes(&mut [0u8; 32]);
        let mut salt = [0u8; saltLength];
        replay.fillRandomBytes(&mut salt);
        assert_eq!(signature[signature.len() - saltLength..], salt);
        assert!(scheme.isValidSignature(&signature, message, &keyPair.publicKey));
    }
}

#[test]
fn aSecretKeyOfAWrongLengthIsALengthErrorBeforeAnyRandomByte() {
    for scheme in parameterSets {
        let expected = scheme.description().secretKeyLength;
        for length in [expected - 1, expected + 1, 0] {
            let mut recording = RecordingRandom::new(2);
            assert_eq!(
                scheme.sign(message, &vec![0u8; length], &mut recording),
                Err(OQSError::invalidLength {
                    expected,
                    actual: length
                })
            );
            assert!(recording.requests.is_empty());
        }
    }
}

#[test]
fn aSignatureIsValidOnlyWithItsMessageItsKeyAndTheLengthsOfTheSet() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let name = scheme.description().name;
        let keyPair = scheme.generateKeyPair(&mut random(3)).expect("key pair");
        let signature = scheme
            .sign(message, keyPair.secretKey.bytes(), &mut random(4))
            .expect("signature");
        let publicKey = &keyPair.publicKey;
        assert!(
            scheme.isValidSignature(&signature, message, publicKey),
            "{name}"
        );
        assert!(!scheme.isValidSignature(&signature, b"the quick brown box", publicKey));
        assert!(!scheme.isValidSignature(&signature, b"", publicKey));
        // A changed byte of the point w, and a changed byte of the salt.
        let (vinegarCount, _, elementsPerByte) = shapes[index % 4];
        for position in [0, vinegarCount / elementsPerByte, signature.len() - 1] {
            let mut changed = signature.clone();
            changed[position] ^= 0x01;
            assert!(
                !scheme.isValidSignature(&changed, message, publicKey),
                "{name}, byte {position}"
            );
        }
        // `crypto_sign_verify` refuses a signature of another length, also one with the bytes of
        // the valid signature at its start.
        let longer = [&signature[..], &[0]].concat();
        for wrong in [&signature[..signature.len() - 1], &longer, &[]] {
            assert!(
                !scheme.isValidSignature(wrong, message, publicKey),
                "{name}"
            );
        }
        // A public key of another length.
        let longerKey = [&publicKey[..], &[0]].concat();
        for wrong in [&publicKey[..publicKey.len() - 1], &longerKey, &[]] {
            assert!(
                !scheme.isValidSignature(&signature, message, wrong),
                "{name}"
            );
        }
        // An entry (i, i) of the map counts only when the variable i of the point is not zero.
        // So the test changes the entry of the first vinegar variable that is not zero in P1,
        // or the public seed of a compressed key, and the entry of the last oil variable that
        // is not zero in P3.
        let (_, oilCount, _) = shapes[index % 4];
        let entryLength = oilCount / elementsPerByte;
        let element = |variable: usize| {
            if elementsPerByte == 2 {
                (signature[variable / 2] >> (4 * (variable % 2))) & 0x0F
            } else {
                signature[variable]
            }
        };
        let firstVinegar = (0..vinegarCount)
            .find(|variable| element(*variable) != 0)
            .expect("a vinegar variable that is not zero");
        let lastOil = (0..oilCount)
            .rev()
            .find(|variable| element(vinegarCount + variable) != 0)
            .expect("an oil variable that is not zero");
        let triangleIndex = |row: usize, dimension: usize| (2 * dimension - row + 1) * row / 2;
        let oilBlockStart = publicKey.len() - entryLength * oilCount * (oilCount + 1) / 2;
        let firstPosition = if index < 4 {
            triangleIndex(firstVinegar, vinegarCount) * entryLength
        } else {
            0
        };
        let lastPosition = oilBlockStart + triangleIndex(lastOil, oilCount) * entryLength;
        for position in [firstPosition, lastPosition] {
            let mut changed = publicKey.clone();
            changed[position] ^= 0x01;
            assert!(
                !scheme.isValidSignature(&signature, message, &changed),
                "{name}, key byte {position}"
            );
        }
    }
}

#[test]
fn theThreeFormsOfAShapeShareTheirKeysAndTheirSignatures() {
    for shape in 0..4 {
        let (classic, compressedPublicKey, compressedKeys) = (
            parameterSets[shape],
            parameterSets[shape + 4],
            parameterSets[shape + 8],
        );
        let name = classic.description().name;
        let keyPairs: Vec<_> = [classic, compressedPublicKey, compressedKeys]
            .iter()
            .map(|scheme| scheme.generateKeyPair(&mut random(5)).expect("key pair"))
            .collect();
        // The compressed public key is the public seed and P3, and the classic key ends with P3.
        let classicKey = &keyPairs[0].publicKey;
        let compressedKey = &keyPairs[1].publicKey;
        assert_eq!(compressedKey, &keyPairs[2].publicKey, "{name}");
        let oilBlockLength = compressedKey.len() - 16;
        assert_eq!(
            classicKey[classicKey.len() - oilBlockLength..],
            compressedKey[16..],
            "{name}"
        );
        // The secret key of the pkc form is the classic one, and the compressed secret key is
        // its seed.
        let classicSecretKey = keyPairs[0].secretKey.bytes();
        assert_eq!(keyPairs[1].secretKey.bytes(), classicSecretKey, "{name}");
        assert_eq!(
            keyPairs[2].secretKey.bytes(),
            &classicSecretKey[..32],
            "{name}"
        );
        // The same salt gives the same signature in each form, and each form verifies it.
        let signatures: Vec<Vec<u8>> = [classic, compressedPublicKey, compressedKeys]
            .iter()
            .zip(&keyPairs)
            .map(|(scheme, keyPair)| {
                scheme
                    .sign(message, keyPair.secretKey.bytes(), &mut random(6))
                    .expect("signature")
            })
            .collect();
        assert_eq!(signatures[0], signatures[1], "{name}");
        assert_eq!(signatures[0], signatures[2], "{name}");
        assert!(classic.isValidSignature(&signatures[2], message, classicKey));
        assert!(compressedPublicKey.isValidSignature(&signatures[0], message, compressedKey));
        assert!(compressedKeys.isValidSignature(&signatures[1], message, compressedKey));
    }
}

#[test]
fn aSecretKeyWhoseLinearBlockIsZeroFailsAfterEveryAttemptAndDrawsTheSalt() {
    // With S zero, the linear system of every attempt is zero and singular, so `ov_sign`
    // returns -1 after 256 attempts. A compressed secret key is a seed, which never gives a
    // zero S. The loop is the same for each shape, so the test runs the two shapes of the
    // smallest systems, one of each field, in both forms of the secret key.
    for scheme in [
        &UOV::ovIs,
        &UOV::ovIp,
        &UOV::ovIsCompressedPublicKey,
        &UOV::ovIpCompressedPublicKey,
    ] {
        let mut recording = RecordingRandom::new(7);
        let secretKey = vec![0u8; scheme.description().secretKeyLength];
        assert_eq!(
            scheme.sign(message, &secretKey, &mut recording),
            Err(OQSError::operationFailed),
            "{}",
            scheme.description().name
        );
        assert_eq!(recording.requests, vec![16]);
    }
}

/// A public key made by hand and the signature that it accepts: every entry of the public map
/// is zero, except the entry of the first oil variable squared, and the point of the signature
/// has that variable at one and every other variable at zero. So the map at the point is that
/// entry, which the function sets to the target, SHAKE256 of the message and the salt.
fn handMadeKeyAndSignature(index: usize) -> (Vec<u8>, Vec<u8>) {
    let description = parameterSets[index].description();
    let (vinegarCount, oilCount, elementsPerByte) = shapes[index % 4];
    let entryLength = oilCount / elementsPerByte;
    let salt = randomBytes(8, saltLength);
    let mut target = vec![0u8; entryLength];
    let mut hash = SHAKE256::new();
    hash.absorb(message);
    hash.absorb(&salt);
    hash.finalize().squeeze(&mut target);
    // P3 starts after P1 and P2 in a classic key, and after the 16-byte seed in a compressed
    // key. Its first entry is the first oil variable squared.
    let mut publicKey = vec![0u8; description.publicKeyLength];
    let oilBlockStart = if index < 4 {
        description.publicKeyLength - entryLength * oilCount * (oilCount + 1) / 2
    } else {
        16
    };
    publicKey[oilBlockStart..oilBlockStart + entryLength].copy_from_slice(&target);
    // The first oil variable is element v of the point: the low half of byte v / 2 for GF(16).
    let mut signature = vec![0u8; description.signatureLength - saltLength];
    signature[vinegarCount / elementsPerByte] = 0x01;
    signature.extend_from_slice(&salt);
    (publicKey, signature)
}

#[test]
fn aPublicKeyMadeByHandAcceptsTheSignatureThatItWasMadeFor() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let (publicKey, signature) = handMadeKeyAndSignature(index);
        assert!(
            scheme.isValidSignature(&signature, message, &publicKey),
            "{}",
            scheme.description().name
        );
        // The vinegar values of the point are zero, so P1 and P2 do not count: a compressed
        // key accepts the signature with any public seed.
        if index >= 4 {
            let mut otherSeed = publicKey.clone();
            otherSeed[..16].copy_from_slice(&randomBytes(9, 16));
            assert!(scheme.isValidSignature(&signature, message, &otherSeed));
        }
        // Another value of the oil variable gives the entry times its square.
        let mut other = signature.clone();
        let (vinegarCount, _, elementsPerByte) = shapes[index % 4];
        other[vinegarCount / elementsPerByte] = 0x02;
        assert!(!scheme.isValidSignature(&other, message, &publicKey));
    }
}

#[test]
fn theSameBitChangedInTwoBytesOfTheMapIsRefused() {
    // The map then differs from the target by the same value in two bytes, which an exclusive
    // or of the differences would cancel. `_ov_verify` folds them with an or.
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let (publicKey, signature) = handMadeKeyAndSignature(index);
        let description = scheme.description();
        let oilBlockStart = if index < 4 {
            let (_, oilCount, elementsPerByte) = shapes[index % 4];
            description.publicKeyLength - oilCount / elementsPerByte * oilCount * (oilCount + 1) / 2
        } else {
            16
        };
        for (first, second) in [(0, 1), (0, 7), (3, 17)] {
            let mut changed = publicKey.clone();
            changed[oilBlockStart + first] ^= 0x10;
            changed[oilBlockStart + second] ^= 0x10;
            assert!(
                !scheme.isValidSignature(&signature, message, &changed),
                "{}, bytes {first} and {second}",
                description.name
            );
            changed[oilBlockStart + second] ^= 0x10;
            assert!(!scheme.isValidSignature(&signature, message, &changed));
        }
    }
}

#[test]
fn uovSignsWithoutAContextString() {
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        // Every secret key of random bytes signs, and a compressed secret key is any seed.
        let secretKey = randomBytes(10 + index as u8, scheme.description().secretKeyLength);
        let mut recording = RecordingRandom::new(11);
        assert_eq!(
            scheme.signWithContext(message, b"c", &secretKey, &mut recording),
            Err(OQSError::contextNotSupported)
        );
        assert!(recording.requests.is_empty());
        let signature = scheme
            .signWithContext(message, b"", &secretKey, &mut random(12))
            .expect("the empty context signs");
        let plain = scheme
            .sign(message, &secretKey, &mut random(12))
            .expect("signature");
        assert_eq!(signature, plain);
        let (publicKey, handMadeSignature) = handMadeKeyAndSignature(index);
        assert!(scheme.isValidSignatureWithContext(&handMadeSignature, message, b"", &publicKey));
        assert!(!scheme.isValidSignatureWithContext(&handMadeSignature, message, b"c", &publicKey));
    }
}
