//! Contract tests of the oracle: each call reaches the C library and gives the answer that an
//! independent source states, and each rejection path gives its error without a call.

use OQSNativeCOracle::{COracle, OracleMechanism, OracleRandomness, OracleSignatureScheme};
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating, Signing};
use OQSNativeEntities::OQSError;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digits"))
        .collect()
}

fn countingEntropy() -> [u8; 48] {
    std::array::from_fn(|index| index as u8)
}

/// A source that gives the bytes 0, 1, 2 and so on and records the length of each request.
#[derive(Default)]
struct RecordingSource {
    next: u8,
    requestLengths: Vec<usize>,
}

impl RandomGenerating for RecordingSource {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.requestLengths.push(bytes.len());
        for byte in bytes {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }
}

#[test]
fn nistRandomGivesTheSeedsOfTheNISTKnownAnswerFiles() {
    // The `seed` lines of count 0 and count 1 of every NIST PQC KAT response file.
    let mut oracle = COracle::new(OracleRandomness::nist(countingEntropy()));
    let mut seed = [0u8; 48];
    oracle.fillRandomBytes(&mut seed);
    assert_eq!(
        seed.to_vec(),
        hex(
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
        )
    );
    oracle.fillRandomBytes(&mut seed);
    assert_eq!(
        seed.to_vec(),
        hex(
            "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC81ADDE6AEEB4A5A875C3BFCADFA958F"
        )
    );
}

#[test]
fn eachOracleStartsItsRandomSourceAgain() {
    let mut first = [0u8; 16];
    let mut second = [0u8; 16];
    COracle::new(OracleRandomness::nist(countingEntropy())).fillRandomBytes(&mut first);
    COracle::new(OracleRandomness::nist(countingEntropy())).fillRandomBytes(&mut second);
    assert_eq!(first, second);
}

#[test]
fn knownAnswerRandomIsSHAKE256ForHQCAndTheNISTDRBGForOthers() {
    let entropy = countingEntropy();
    let mut hqcBytes = [0u8; 40];
    COracle::new(OracleRandomness::knownAnswer {
        algorithm: "HQC-1",
        entropy,
    })
    .fillRandomBytes(&mut hqcBytes);
    // The HQC generator of `tests/test_helpers.c`: SHAKE256 of the entropy and the domain
    // byte 0, computed here by the C SHAKE256.
    let mut seedAndDomain = entropy.to_vec();
    seedAndDomain.push(0);
    let oracle = COracle::new(OracleRandomness::nist([0; 48]));
    assert_eq!(hqcBytes.to_vec(), oracle.shake256(&seedAndDomain, 40));
    drop(oracle);
    let mut nistBytes = [0u8; 48];
    COracle::new(OracleRandomness::knownAnswer {
        algorithm: "ML-KEM-768",
        entropy,
    })
    .fillRandomBytes(&mut nistBytes);
    assert_eq!(
        nistBytes.to_vec(),
        hex(
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
        )
    );
}

#[test]
fn sourceRandomFeedsTheCCodeInItsOwnRequests() {
    // The ML-KEM key pair of liboqs asks for 64 bytes at once, and encapsulation for 32.
    let mut source = RecordingSource::default();
    let keyPair = COracle::new(OracleRandomness::source(&mut source))
        .generateKEMKeyPair("ML-KEM-768")
        .expect("key pair");
    assert_eq!(source.requestLengths, vec![64]);
    let mut encapsulationSource = RecordingSource::default();
    COracle::new(OracleRandomness::source(&mut encapsulationSource))
        .encapsulate("ML-KEM-768", &keyPair.publicKey)
        .expect("encapsulation");
    assert_eq!(encapsulationSource.requestLengths, vec![32]);
}

#[test]
fn kemRoundTripRecoversTheSecretAndAChangedCiphertextDoesNot() {
    let mut oracle = COracle::new(OracleRandomness::nist(countingEntropy()));
    let keyPair = oracle.generateKEMKeyPair("ML-KEM-512").expect("key pair");
    let encapsulation = oracle
        .encapsulate("ML-KEM-512", &keyPair.publicKey)
        .expect("encapsulation");
    let recovered = oracle
        .decapsulate(
            "ML-KEM-512",
            &encapsulation.ciphertext,
            keyPair.secretKey.bytes(),
        )
        .expect("decapsulation");
    assert_eq!(recovered.bytes(), encapsulation.sharedSecret.bytes());
    let mut changed = encapsulation.ciphertext.clone();
    changed[0] ^= 1;
    let rejected = oracle
        .decapsulate("ML-KEM-512", &changed, keyPair.secretKey.bytes())
        .expect("implicit rejection is not an error");
    assert_ne!(rejected.bytes(), encapsulation.sharedSecret.bytes());
}

#[test]
fn seededKEMFormsAreDeterministicAndOtherKEMsRefuseThem() {
    let mut oracle = COracle::new(OracleRandomness::nist([0; 48]));
    let seed = [7u8; 64];
    let first = oracle
        .generateKEMKeyPairFromSeed("ML-KEM-768", &seed)
        .expect("seeded key pair");
    let second = oracle
        .generateKEMKeyPairFromSeed("ML-KEM-768", &seed)
        .expect("seeded key pair");
    assert_eq!(first.publicKey, second.publicKey);
    let encapsulation = oracle
        .encapsulateWithSeed("ML-KEM-768", &first.publicKey, &[9u8; 32])
        .expect("seeded encapsulation");
    let again = oracle
        .encapsulateWithSeed("ML-KEM-768", &first.publicKey, &[9u8; 32])
        .expect("seeded encapsulation");
    assert_eq!(encapsulation.ciphertext, again.ciphertext);
    assert_eq!(
        oracle
            .generateKEMKeyPairFromSeed("FrodoKEM-640-SHAKE", &seed)
            .err(),
        Some(OQSError::seedNotSupported)
    );
}

#[test]
fn wrongLengthsAreErrorsBeforeAnyCCall() {
    let mut oracle = COracle::new(OracleRandomness::nist([0; 48]));
    assert_eq!(
        oracle.encapsulate("ML-KEM-512", &[0u8; 10]).err(),
        Some(OQSError::invalidLength {
            expected: 800,
            actual: 10
        })
    );
    assert_eq!(
        oracle
            .decapsulate("ML-KEM-512", &[0u8; 768], &[0u8; 5])
            .err(),
        Some(OQSError::invalidLength {
            expected: 1632,
            actual: 5
        })
    );
    assert_eq!(
        oracle
            .generateKEMKeyPairFromSeed("ML-KEM-512", &[0u8; 63])
            .err(),
        Some(OQSError::invalidLength {
            expected: 64,
            actual: 63
        })
    );
    assert_eq!(
        oracle.sign("ML-DSA-44", b"m", &[0u8; 3]).err(),
        Some(OQSError::invalidLength {
            expected: 2560,
            actual: 3
        })
    );
    assert!(!oracle.isValidSignature("ML-DSA-44", &[0u8; 2420], b"m", &[0u8; 3]));
}

#[test]
fn unknownNamesAreFailuresAndNotPanics() {
    let mut oracle = COracle::new(OracleRandomness::nist([0; 48]));
    assert_eq!(oracle.kemDescription("No-Such-KEM"), None);
    assert_eq!(oracle.signatureDescription("No-Such-Scheme"), None);
    assert_eq!(oracle.statefulSignatureDescription("No-Such-Scheme"), None);
    assert_eq!(
        oracle.generateKEMKeyPair("No-Such-KEM").err(),
        Some(OQSError::operationFailed)
    );
    assert_eq!(
        oracle.generateKEMKeyPair("Nul\0Name").err(),
        Some(OQSError::operationFailed)
    );
    assert!(!oracle.isValidSignature("No-Such-Scheme", b"s", b"m", b"k"));
    drop(oracle);
    assert!(OracleMechanism::named("No-Such-KEM").is_none());
    assert!(OracleSignatureScheme::named("No-Such-Scheme").is_none());
}

#[test]
#[should_panic(expected = "this thread already holds a COracle")]
fn secondOracleOnOneThreadStopsAtOnceAndDoesNotWaitForItself() {
    let first = COracle::new(OracleRandomness::nist([0; 48]));
    let second = COracle::new(OracleRandomness::nist([0; 48]));
    drop(second);
    drop(first);
}

#[test]
fn descriptionsHoldTheFactsOfTheCLibrary() {
    let oracle = COracle::new(OracleRandomness::nist([0; 48]));
    let kem = oracle.kemDescription("ML-KEM-768").expect("ML-KEM-768");
    assert_eq!(
        (
            kem.name,
            kem.claimedNISTLevel,
            kem.isINDCCASecure,
            kem.publicKeyLength,
            kem.secretKeyLength,
            kem.ciphertextLength,
            kem.sharedSecretLength,
            kem.keyPairSeedLength,
            kem.encapsulationSeedLength
        ),
        ("ML-KEM-768", 3, true, 1184, 2400, 1088, 32, 64, 32)
    );
    let signature = oracle.signatureDescription("ML-DSA-65").expect("ML-DSA-65");
    assert_eq!(
        (
            signature.name,
            signature.claimedNISTLevel,
            signature.isEUFCMASecure,
            signature.isSUFCMASecure,
            signature.supportsContext,
            signature.publicKeyLength,
            signature.secretKeyLength,
            signature.signatureLength
        ),
        ("ML-DSA-65", 3, true, true, true, 1952, 4032, 3309)
    );
    // Falcon claims EUF-CMA and not SUF-CMA, so the two facts come from their own fields.
    let falcon = oracle
        .signatureDescription("Falcon-512")
        .expect("Falcon-512");
    assert_eq!(
        (
            falcon.isEUFCMASecure,
            falcon.isSUFCMASecure,
            falcon.supportsContext
        ),
        (true, false, false)
    );
    let stateful = oracle
        .statefulSignatureDescription("LMS_SHA256_H5_W1")
        .expect("LMS_SHA256_H5_W1");
    assert_eq!(
        (
            stateful.name,
            stateful.isEUFCMASecure,
            stateful.isSUFCMASecure
        ),
        ("LMS_SHA256_H5_W1", true, false)
    );
    assert!(oracle.kemNames().contains(&"ML-KEM-1024"));
    assert!(oracle.signatureNames().contains(&"Falcon-512"));
    assert!(
        oracle
            .statefulSignatureNames()
            .contains(&"XMSS-SHA2_10_256")
    );
}

#[test]
fn signatureRoundTripAcceptsTheSignatureAndRejectsChanges() {
    let mut oracle = COracle::new(OracleRandomness::nist(countingEntropy()));
    let keyPair = oracle
        .generateSignatureKeyPair("ML-DSA-44")
        .expect("key pair");
    let message = b"the quick brown fox";
    let signature = oracle
        .sign("ML-DSA-44", message, keyPair.secretKey.bytes())
        .expect("signature");
    assert!(oracle.isValidSignature("ML-DSA-44", &signature, message, &keyPair.publicKey));
    assert!(!oracle.isValidSignature(
        "ML-DSA-44",
        &signature,
        b"the quick brown box",
        &keyPair.publicKey
    ));
    let mut changed = signature.clone();
    changed[10] ^= 4;
    assert!(!oracle.isValidSignature("ML-DSA-44", &changed, message, &keyPair.publicKey));
    let withContext = oracle
        .signWithContext("ML-DSA-44", message, b"context", keyPair.secretKey.bytes())
        .expect("signature with context");
    assert!(oracle.isValidSignatureWithContext(
        "ML-DSA-44",
        &withContext,
        message,
        b"context",
        &keyPair.publicKey
    ));
    assert!(!oracle.isValidSignatureWithContext(
        "ML-DSA-44",
        &withContext,
        message,
        b"other",
        &keyPair.publicKey
    ));
}

#[test]
fn statefulSigningAdvancesTheSecretKeyThatTheCLibraryPersists() {
    let name = "LMS_SHA256_H5_W1";
    let mut oracle = COracle::new(OracleRandomness::nist(countingEntropy()));
    let keyPair = oracle.generateStatefulKeyPair(name).expect("key pair");
    // The LMS code of liboqs (hash-sigs) counts up to the highest sequence number, 2^5 - 1, so
    // it reports 31 for a tree of 32 one-time keys.
    assert_eq!(
        oracle.totalSignatureCount(name, keyPair.secretKey.bytes()),
        Ok(31)
    );
    assert_eq!(
        oracle.remainingSignatureCount(name, keyPair.secretKey.bytes()),
        Ok(31)
    );
    let (signature, advanced) = oracle
        .signStateful(name, b"message", keyPair.secretKey.bytes())
        .expect("signature");
    assert_ne!(advanced.bytes(), keyPair.secretKey.bytes());
    assert_eq!(
        oracle.remainingSignatureCount(name, advanced.bytes()),
        Ok(30)
    );
    assert!(oracle.isValidStatefulSignature(name, &signature, b"message", &keyPair.publicKey));
    assert!(!oracle.isValidStatefulSignature(name, &signature, b"massage", &keyPair.publicKey));
}

#[test]
fn primitivesGiveTheirStandardAnswers() {
    let oracle = COracle::new(OracleRandomness::nist([0; 48]));
    // FIPS 202 and FIPS 180-4 digests of the empty input.
    assert_eq!(
        oracle.sha3256(b"").to_vec(),
        hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    );
    assert_eq!(
        oracle.sha256(b"").to_vec(),
        hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        oracle.shake128(b"", 16),
        hex("7f9c2ba4e88f827d616045507605853e")
    );
    assert_eq!(
        oracle.shake256(b"", 16),
        hex("46b9dd2b0ba88d13233b3feb743eeb24")
    );
    assert_eq!(
        oracle.sha3384(b"").to_vec(),
        hex(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
        )
    );
    assert_eq!(
        oracle.sha3512(b"").to_vec(),
        hex(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        )
    );
    assert_eq!(
        oracle.sha384(b"").to_vec(),
        hex(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        )
    );
    assert_eq!(
        oracle.sha512(b"").to_vec(),
        hex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
    );
    // FIPS 197, appendix C.1 and C.3.
    let key128: [u8; 16] = std::array::from_fn(|index| index as u8);
    let key256: [u8; 32] = std::array::from_fn(|index| index as u8);
    let plaintext = hex("00112233445566778899aabbccddeeff");
    assert_eq!(
        oracle.aes128ECB(&key128, &plaintext),
        hex("69c4e0d86a7b0430d8cdb78070b4c55a")
    );
    assert_eq!(
        oracle.aes256ECB(&key256, &plaintext),
        hex("8ea2b7ca516745bfeafc49904b496089")
    );
    // NIST SP 800-38A, F.5.1 and F.5.5: the first block of CTR-AES128 and CTR-AES256.
    let counterBlock = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let block = hex("6bc1bee22e409f96e93d7e117393172a");
    let encrypted = |keystream: Vec<u8>| -> Vec<u8> {
        keystream
            .iter()
            .zip(&block)
            .map(|(key, byte)| key ^ byte)
            .collect()
    };
    let ctrKey128: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c")
        .try_into()
        .expect("16 bytes");
    assert_eq!(
        encrypted(oracle.aes128CounterStream(&ctrKey128, &counterBlock, 16)),
        hex("874d6191b620e3261bef6864990db6ce")
    );
    let ctrKey256: [u8; 32] =
        hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .try_into()
            .expect("32 bytes");
    assert_eq!(
        encrypted(oracle.aes256CounterStream(&ctrKey256, &counterBlock, 16)),
        hex("601ec313775789a5b7a7f504bbf3d228")
    );
}

#[test]
fn incrementalAndCounterFormsAgreeWithTheOneShotForms() {
    let oracle = COracle::new(OracleRandomness::nist([0; 48]));
    let input: Vec<u8> = (0..500u32).map(|value| value as u8).collect();
    assert_eq!(
        oracle.shake128InPieces(&input, 7, 333, 50),
        oracle.shake128(&input, 333)
    );
    assert_eq!(
        oracle.shake256InPieces(&input, 0, 333, 0),
        oracle.shake256(&input, 333)
    );
    let key = [3u8; 32];
    let iv = [5u8; 12];
    assert_eq!(
        oracle.aes256CounterBlocksTwice(&key, &iv, 2, 3),
        oracle.aes256CounterStream(&key, &iv, 80)
    );
}

#[test]
fn oracleAdaptersRunTheCAlgorithmWithRustRandomness() {
    let mechanism = OracleMechanism::named("ML-KEM-512").expect("ML-KEM-512");
    assert_eq!(mechanism.description().name, "ML-KEM-512");
    let mut source = RecordingSource::default();
    let keyPair = mechanism.generateKeyPair(&mut source).expect("key pair");
    let encapsulation = mechanism
        .encapsulate(&keyPair.publicKey, &mut source)
        .expect("encapsulation");
    assert_eq!(source.requestLengths, vec![64, 32]);
    let recovered = mechanism
        .decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())
        .expect("decapsulation");
    assert_eq!(recovered.bytes(), encapsulation.sharedSecret.bytes());
    let scheme = OracleSignatureScheme::named("ML-DSA-44").expect("ML-DSA-44");
    let signatureKeys = scheme.generateKeyPair(&mut source).expect("key pair");
    let signature = scheme
        .signWithContext(b"m", b"c", signatureKeys.secretKey.bytes(), &mut source)
        .expect("signature");
    assert!(scheme.isValidSignatureWithContext(&signature, b"m", b"c", &signatureKeys.publicKey));
    assert!(!scheme.isValidSignatureWithContext(&signature, b"m", b"d", &signatureKeys.publicKey));
    assert!(!scheme.isValidSignature(&signature, b"m", &signatureKeys.publicKey));
    let plain = scheme
        .sign(b"m", signatureKeys.secretKey.bytes(), &mut source)
        .expect("signature");
    assert_eq!(plain.len(), 2420);
    assert!(scheme.isValidSignature(&plain, b"m", &signatureKeys.publicKey));
    assert!(!scheme.isValidSignature(&plain, b"n", &signatureKeys.publicKey));
}
