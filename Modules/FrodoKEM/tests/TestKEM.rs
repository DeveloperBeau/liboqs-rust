//! The correctness test of liboqs `tests/test_kem.c`, and the rejection paths of FrodoKEM, for
//! each parameter set.
//!
//! FrodoKEM checks neither key, so its only rejection path is the implicit rejection of
//! decapsulation: a ciphertext that differs from the re-encryption gives the hash of the
//! ciphertext and of the rejection value `s`, the first bytes of the secret key. The expected
//! values come from the C code of `crypto_kem_dec`: `ss = SHAKE(ct || s)`.

use OQSNativeAlgorithmTests::KEMCorrectnessTest;
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::OQSError;
use OQSNativeFrodoKEM::FrodoKEM;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSHA3::{SHAKE128, SHAKE256};

/// Every set, in liboqs order.
const everySet: [&FrodoKEM; 12] = [
    &FrodoKEM::frodoKEM640AES,
    &FrodoKEM::frodoKEM640SHAKE,
    &FrodoKEM::frodoKEM976AES,
    &FrodoKEM::frodoKEM976SHAKE,
    &FrodoKEM::frodoKEM1344AES,
    &FrodoKEM::frodoKEM1344SHAKE,
    &FrodoKEM::eFrodoKEM640AES,
    &FrodoKEM::eFrodoKEM640SHAKE,
    &FrodoKEM::eFrodoKEM976AES,
    &FrodoKEM::eFrodoKEM976SHAKE,
    &FrodoKEM::eFrodoKEM1344AES,
    &FrodoKEM::eFrodoKEM1344SHAKE,
];

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

/// The facts of the C parameter header of a set that the tests need: the dimension `n`, the
/// bits `D` of each value, the bits `B` of the message in each value, and the salt length.
struct SetFacts {
    dimension: usize,
    modulusBits: usize,
    messageBits: usize,
    saltLength: usize,
}

fn facts(mechanism: &FrodoKEM) -> SetFacts {
    let name = mechanism.description().name;
    let secretLength = mechanism.description().sharedSecretLength;
    let (dimension, modulusBits, messageBits) = if name.contains("-640-") {
        (640, 15, 2)
    } else if name.contains("-976-") {
        (976, 16, 3)
    } else {
        (1344, 16, 4)
    };
    SetFacts {
        dimension,
        modulusBits,
        messageBits,
        saltLength: if name.starts_with('e') {
            0
        } else {
            2 * secretLength
        },
    }
}

/// The `shake` of the parameter header of a set: SHAKE128 for FrodoKEM-640 and SHAKE256 for
/// the others.
fn hash(mechanism: &FrodoKEM, parts: &[&[u8]], length: usize) -> Vec<u8> {
    let mut output = vec![0u8; length];
    if facts(mechanism).dimension == 640 {
        let mut function = SHAKE128::new();
        parts.iter().for_each(|part| function.absorb(part));
        function.finalize().squeeze(&mut output);
    } else {
        let mut function = SHAKE256::new();
        parts.iter().for_each(|part| function.absorb(part));
        function.finalize().squeeze(&mut output);
    }
    output
}

/// The implicit-rejection secret of a ciphertext: the hash of the ciphertext and of the
/// rejection value `s`, the first bytes of the secret key.
fn rejectionSecret(mechanism: &FrodoKEM, ciphertext: &[u8], secretKey: &[u8]) -> Vec<u8> {
    let length = mechanism.description().sharedSecretLength;
    hash(mechanism, &[ciphertext, &secretKey[..length]], length)
}

/// Flips the low bit of a value of a packed matrix that starts at a byte of the ciphertext.
/// The values are packed from their high bit, so the low bit of value `v` is bit
/// `(v + 1) D - 1` of the stream.
fn flipLowBit(ciphertext: &mut [u8], start: usize, modulusBits: usize, value: usize) {
    let bit = (value + 1) * modulusBits - 1;
    ciphertext[start + bit / 8] ^= 0x80 >> (bit % 8);
}

/// A random source that gives the bytes of the NIST DRBG and records each request.
struct RecordingRandom {
    source: NISTKATRandom,
    requests: Vec<Vec<u8>>,
}

impl RecordingRandom {
    fn new(seed: u8) -> Self {
        RecordingRandom {
            source: random(seed),
            requests: Vec::new(),
        }
    }
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.source.fillRandomBytes(bytes);
        self.requests.push(bytes.to_vec());
    }
}

#[test]
fn testKEMPassesForEveryParameterSet() {
    for (index, mechanism) in everySet.into_iter().enumerate() {
        assert_eq!(
            KEMCorrectnessTest::run(mechanism, &mut random(index as u8)),
            Ok(())
        );
    }
}

#[test]
fn eachOperationDrawsTheRequestsOfTheCCode() {
    // `crypto_kem_keypair` draws `s`, the noise seed and the seed of the matrix seed in one
    // request, and `crypto_kem_enc` draws the message and the salt in one request. eFrodoKEM
    // has no salt, and its noise seed has the length of the shared secret.
    let expected = [
        (64, 48),
        (64, 48),
        (88, 72),
        (88, 72),
        (112, 96),
        (112, 96),
        (48, 16),
        (48, 16),
        (64, 24),
        (64, 24),
        (80, 32),
        (80, 32),
    ];
    for (mechanism, (keyPairLength, encapsulationLength)) in everySet.into_iter().zip(expected) {
        let name = mechanism.description().name;
        let mut keyPairRandom = RecordingRandom::new(1);
        let keyPair = mechanism
            .generateKeyPair(&mut keyPairRandom)
            .expect("key pair");
        let lengths: Vec<usize> = keyPairRandom.requests.iter().map(Vec::len).collect();
        assert_eq!(lengths, vec![keyPairLength], "{name}");
        let mut encapsulationRandom = RecordingRandom::new(2);
        mechanism
            .encapsulate(&keyPair.publicKey, &mut encapsulationRandom)
            .expect("encapsulation");
        let lengths: Vec<usize> = encapsulationRandom.requests.iter().map(Vec::len).collect();
        assert_eq!(lengths, vec![encapsulationLength], "{name}");
    }
}

#[test]
fn theKeysHoldTheRandomValuesTheHashesAndASmallSecretMatrix() {
    for mechanism in everySet {
        let description = mechanism.description();
        let name = description.name;
        let secretLength = description.sharedSecretLength;
        let facts = facts(mechanism);
        let mut random = RecordingRandom::new(3);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let request = &random.requests[0];
        let publicKey = keyPair.publicKey.as_slice();
        let secretKey = keyPair.secretKey.bytes();
        // pk = seedA || b, with seedA = SHAKE(z, 16) for the last 16 bytes z of the request.
        assert_eq!(
            &publicKey[..16],
            hash(mechanism, &[&request[request.len() - 16..]], 16).as_slice(),
            "{name}"
        );
        // sk = s || pk || S || SHAKE(pk), with s the first bytes of the request.
        assert_eq!(
            &secretKey[..secretLength],
            &request[..secretLength],
            "{name}"
        );
        assert_eq!(
            &secretKey[secretLength..secretLength + publicKey.len()],
            publicKey,
            "{name}"
        );
        assert_eq!(
            &secretKey[secretKey.len() - secretLength..],
            hash(mechanism, &[publicKey], secretLength).as_slice(),
            "{name}"
        );
        // The secret matrix holds n n̄ samples of the error distribution, two bytes each,
        // low byte first, with absolute values up to 12, 10 and 6.
        let largest = match facts.dimension {
            640 => 12,
            976 => 10,
            _ => 6,
        };
        let matrixStart = secretLength + publicKey.len();
        let matrix = &secretKey[matrixStart..secretKey.len() - secretLength];
        assert_eq!(matrix.len(), 2 * 8 * facts.dimension, "{name}");
        let samples: Vec<i16> = matrix
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert!(
            samples
                .iter()
                .all(|sample| sample.unsigned_abs() <= largest),
            "{name}"
        );
        assert!(
            samples.contains(&1) && samples.contains(&-1) && samples.contains(&0),
            "{name}"
        );
    }
}

#[test]
fn theCiphertextEndsWithTheSaltOfTheRequestOrHasNoSalt() {
    for mechanism in everySet {
        let description = mechanism.description();
        let name = description.name;
        let facts = facts(mechanism);
        let keyPair = mechanism.generateKeyPair(&mut random(4)).expect("key pair");
        let mut random = RecordingRandom::new(5);
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let request = &random.requests[0];
        let ciphertext = &encapsulation.ciphertext;
        // ct = c1 || c2 || salt, with c1 of D n n̄ / 8 bytes and c2 of D n̄ n̄ / 8 bytes.
        assert_eq!(
            ciphertext.len(),
            facts.modulusBits * facts.dimension + 8 * facts.modulusBits + facts.saltLength,
            "{name}"
        );
        // The request is the message of B n̄ n̄ / 8 bytes, then the salt.
        assert_eq!(
            request.len(),
            8 * facts.messageBits + facts.saltLength,
            "{name}"
        );
        assert_eq!(
            &ciphertext[ciphertext.len() - facts.saltLength..],
            &request[8 * facts.messageBits..],
            "{name}"
        );
    }
}

#[test]
fn aChangedCiphertextGivesTheRejectionSecret() {
    for mechanism in everySet {
        let name = mechanism.description().name;
        let facts = facts(mechanism);
        let mut random = random(6);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let secretKey = keyPair.secretKey.bytes();
        let length = encapsulation.ciphertext.len();
        let messageMatrixStart = facts.modulusBits * facts.dimension;
        // A byte of the matrix B', the first byte of the matrix C, and the last byte, which is
        // in the salt for FrodoKEM and in C for eFrodoKEM.
        for (position, change) in [
            (0, 0x80u8),
            (messageMatrixStart / 2, 0x01),
            (messageMatrixStart, 0x10),
            (length - 1, 0x01),
        ] {
            let mut changed = encapsulation.ciphertext.clone();
            changed[position] ^= change;
            let secret = mechanism
                .decapsulate(&changed, secretKey)
                .expect("decapsulation");
            assert_ne!(
                secret.bytes(),
                encapsulation.sharedSecret.bytes(),
                "{name}, byte {position}"
            );
            assert_eq!(
                secret.bytes(),
                rejectionSecret(mechanism, &changed, secretKey),
                "{name}, byte {position}"
            );
        }
        // The unchanged ciphertext gives the shared secret, not the rejection secret.
        let secret = mechanism
            .decapsulate(&encapsulation.ciphertext, secretKey)
            .expect("decapsulation");
        assert_eq!(secret.bytes(), encapsulation.sharedSecret.bytes(), "{name}");
        assert_ne!(
            secret.bytes(),
            rejectionSecret(mechanism, &encapsulation.ciphertext, secretKey),
            "{name}"
        );
    }
}

#[test]
fn aCiphertextWithTheSameBitChangedInTwoValuesIsRejected() {
    for mechanism in everySet {
        let name = mechanism.description().name;
        let facts = facts(mechanism);
        let mut random = random(7);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let secretKey = keyPair.secretKey.bytes();
        // The low bit of the values 0 and 8 of the matrix B', and then of the matrix C. The
        // change is small, so the decryption gives the same message, and the re-encryption
        // differs from the ciphertext in exactly these two values, by the same bit. The two
        // differences cancel in an exclusive or, so the comparison must gather them with an or.
        // A change in B' alone and a change in C alone also show that decapsulation joins the
        // two comparisons with an or.
        for start in [0, facts.modulusBits * facts.dimension] {
            let mut changed = encapsulation.ciphertext.clone();
            flipLowBit(&mut changed, start, facts.modulusBits, 0);
            flipLowBit(&mut changed, start, facts.modulusBits, 8);
            let secret = mechanism
                .decapsulate(&changed, secretKey)
                .expect("decapsulation");
            assert_eq!(
                secret.bytes(),
                rejectionSecret(mechanism, &changed, secretKey),
                "{name}, matrix at byte {start}"
            );
        }
    }
}

#[test]
fn theLowBitOfAValueIsTheSameBitInTwoBytesForValuesZeroAndEight() {
    // For D = 15 the low bits of the values 0 and 8 are bit 1 of the bytes 1 and 16, and for
    // D = 16 they are bit 0 of the bytes 1 and 17.
    let mut bytes = vec![0u8; 20];
    flipLowBit(&mut bytes, 0, 15, 0);
    flipLowBit(&mut bytes, 0, 15, 8);
    assert_eq!((bytes[1], bytes[16]), (0x02, 0x02));
    assert_eq!(bytes.iter().filter(|byte| **byte != 0).count(), 2);
    let mut bytes = vec![0u8; 20];
    flipLowBit(&mut bytes, 0, 16, 0);
    flipLowBit(&mut bytes, 0, 16, 8);
    assert_eq!((bytes[1], bytes[17]), (0x01, 0x01));
    assert_eq!(bytes.iter().filter(|byte| **byte != 0).count(), 2);
}

#[test]
fn anyKeyOfTheRightLengthIsAcceptedAsTheCCodeAcceptsIt() {
    for mechanism in everySet {
        let description = mechanism.description();
        let name = description.name;
        // The zero secret key has the matrix seed zero and the secret matrix zero, so the zero
        // ciphertext decrypts to the zero message, its re-encryption is not zero, and the
        // result is the rejection secret of the zero rejection value.
        let secretKey = vec![0u8; description.secretKeyLength];
        let ciphertext = vec![0u8; description.ciphertextLength];
        let secret = mechanism
            .decapsulate(&ciphertext, &secretKey)
            .expect("no key check");
        assert_eq!(
            secret.bytes(),
            hash(
                mechanism,
                &[&ciphertext, &vec![0u8; description.sharedSecretLength]],
                description.sharedSecretLength
            )
            .as_slice(),
            "{name}"
        );
        let encapsulation = mechanism
            .encapsulate(&vec![0xFFu8; description.publicKeyLength], &mut random(8))
            .expect("no key check");
        assert_eq!(
            encapsulation.ciphertext.len(),
            description.ciphertextLength,
            "{name}"
        );
    }
}

#[test]
fn eachInputOfAWrongLengthIsALengthError() {
    for mechanism in everySet {
        let description = mechanism.description();
        let lengthError =
            |expected: usize, actual: usize| Err(OQSError::invalidLength { expected, actual });
        let publicKeyLength = description.publicKeyLength;
        let ciphertextLength = description.ciphertextLength;
        let secretKeyLength = description.secretKeyLength;
        for actual in [publicKeyLength - 1, publicKeyLength + 1, 0] {
            assert_eq!(
                mechanism
                    .encapsulate(&vec![0u8; actual], &mut random(9))
                    .map(|_| ()),
                lengthError(publicKeyLength, actual)
            );
        }
        let secretKey = vec![0u8; secretKeyLength];
        for actual in [ciphertextLength - 1, ciphertextLength + 1, 0] {
            assert_eq!(
                mechanism
                    .decapsulate(&vec![0u8; actual], &secretKey)
                    .map(|_| ()),
                lengthError(ciphertextLength, actual)
            );
        }
        let ciphertext = vec![0u8; ciphertextLength];
        for actual in [secretKeyLength - 2, secretKeyLength + 1] {
            assert_eq!(
                mechanism
                    .decapsulate(&ciphertext, &vec![0u8; actual])
                    .map(|_| ()),
                lengthError(secretKeyLength, actual)
            );
        }
        // The ciphertext is checked first.
        assert_eq!(
            mechanism
                .decapsulate(&ciphertext[1..], &secretKey[1..])
                .map(|_| ()),
            lengthError(ciphertextLength, ciphertextLength - 1)
        );
    }
}

#[test]
fn theSeededFormsAreNotSupportedAsInLiboqs() {
    for mechanism in everySet {
        let description = mechanism.description();
        assert_eq!(
            (
                description.keyPairSeedLength,
                description.encapsulationSeedLength
            ),
            (0, 0)
        );
        assert_eq!(
            mechanism.generateKeyPairFromSeed(&[0u8; 64]).map(|_| ()),
            Err(OQSError::seedNotSupported)
        );
        assert_eq!(
            mechanism
                .encapsulateWithSeed(&vec![0u8; description.publicKeyLength], &[0u8; 32])
                .map(|_| ()),
            Err(OQSError::seedNotSupported)
        );
    }
}

#[test]
fn eachSetHasTheFactsOfItsCFile() {
    // `kem_frodokem*.c` and `kem_efrodokem*.c`: one version text, IND-CCA, and the level of
    // the dimension.
    let version = "https://github.com/microsoft/PQCrypto-LWEKE/commit/a2f9dec8917ccc3464b3378d46b140fa7353320d";
    let names = [
        "FrodoKEM-640-AES",
        "FrodoKEM-640-SHAKE",
        "FrodoKEM-976-AES",
        "FrodoKEM-976-SHAKE",
        "FrodoKEM-1344-AES",
        "FrodoKEM-1344-SHAKE",
        "eFrodoKEM-640-AES",
        "eFrodoKEM-640-SHAKE",
        "eFrodoKEM-976-AES",
        "eFrodoKEM-976-SHAKE",
        "eFrodoKEM-1344-AES",
        "eFrodoKEM-1344-SHAKE",
    ];
    let levels = [1, 1, 3, 3, 5, 5, 1, 1, 3, 3, 5, 5];
    for ((mechanism, name), level) in everySet.into_iter().zip(names).zip(levels) {
        let description = mechanism.description();
        assert_eq!(description.name, name);
        assert_eq!(description.algorithmVersion, version, "{name}");
        assert_eq!(description.claimedNISTLevel, level, "{name}");
        assert!(description.isINDCCASecure, "{name}");
    }
}
