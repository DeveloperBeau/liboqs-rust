//! The ACVP vectors of liboqs `tests/test_acvp_vectors.py` and `tests/vectors_kem.c`: the
//! key generation, encapsulation and decapsulation vectors of NIST ACVP-Server for ML-KEM.

use OQSNativeAlgorithmTests::{JSONValue, TestVectorFiles};
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeMLKEM::MLKEM;

fn mechanism(parameterSet: &str) -> Option<&'static MLKEM> {
    match parameterSet {
        "ML-KEM-512" => Some(&MLKEM::mlkem512),
        "ML-KEM-768" => Some(&MLKEM::mlkem768),
        "ML-KEM-1024" => Some(&MLKEM::mlkem1024),
        _ => None,
    }
}

fn bytes(test: &JSONValue, field: &str) -> Vec<u8> {
    test.member(field)
        .and_then(JSONValue::hexBytes)
        .unwrap_or_else(|| panic!("the vector has the hexadecimal field {field}"))
}

fn identifier(test: &JSONValue) -> String {
    match test.member("tcId") {
        Some(JSONValue::number(text)) => text.clone(),
        _ => "?".to_string(),
    }
}

/// The groups of a file whose parameter set is an ML-KEM set, with the count of their tests.
fn groups(document: &JSONValue) -> Vec<(&'static MLKEM, &JSONValue)> {
    document
        .member("testGroups")
        .map(JSONValue::elements)
        .unwrap_or_default()
        .iter()
        .filter_map(|group| {
            let parameterSet = group.member("parameterSet").and_then(JSONValue::text)?;
            Some((mechanism(parameterSet)?, group))
        })
        .collect()
}

#[test]
fn keyGenerationVectorsGiveTheirKeys() {
    let document = TestVectorFiles::document("ML-KEM-keyGen-FIPS203.json")
        .unwrap_or_else(|message| panic!("{message}"));
    let mut testCount = 0;
    for (mechanism, group) in groups(&document) {
        for test in group
            .member("tests")
            .map(JSONValue::elements)
            .unwrap_or_default()
        {
            let mut seed = bytes(test, "d");
            seed.extend(bytes(test, "z"));
            let keyPair = mechanism
                .generateKeyPairFromSeed(&seed)
                .expect("a key pair");
            let name = mechanism.description().name;
            assert_eq!(
                keyPair.publicKey,
                bytes(test, "ek"),
                "{name}, tcId {}",
                identifier(test)
            );
            assert_eq!(
                keyPair.secretKey.bytes(),
                bytes(test, "dk"),
                "{name}, tcId {}",
                identifier(test)
            );
            testCount += 1;
        }
    }
    assert_eq!(testCount, 75);
}

#[test]
fn encapsulationVectorsGiveTheirCiphertextsAndSecrets() {
    let document = TestVectorFiles::document("ML-KEM-encapDecap-FIPS203.json")
        .unwrap_or_else(|message| panic!("{message}"));
    let mut testCount = 0;
    for (mechanism, group) in groups(&document) {
        if group.member("function").and_then(JSONValue::text) != Some("encapsulation") {
            continue;
        }
        for test in group
            .member("tests")
            .map(JSONValue::elements)
            .unwrap_or_default()
        {
            let encapsulation = mechanism
                .encapsulateWithSeed(&bytes(test, "ek"), &bytes(test, "m"))
                .expect("an encapsulation");
            let name = mechanism.description().name;
            assert_eq!(
                encapsulation.ciphertext,
                bytes(test, "c"),
                "{name}, tcId {}",
                identifier(test)
            );
            assert_eq!(
                encapsulation.sharedSecret.bytes(),
                bytes(test, "k"),
                "{name}, tcId {}",
                identifier(test)
            );
            testCount += 1;
        }
    }
    assert_eq!(testCount, 75);
}

#[test]
fn decapsulationVectorsGiveTheirSecrets() {
    let document = TestVectorFiles::document("ML-KEM-encapDecap-FIPS203.json")
        .unwrap_or_else(|message| panic!("{message}"));
    let mut testCount = 0;
    for (mechanism, group) in groups(&document) {
        if group.member("function").and_then(JSONValue::text) != Some("decapsulation") {
            continue;
        }
        for test in group
            .member("tests")
            .map(JSONValue::elements)
            .unwrap_or_default()
        {
            let secret = mechanism
                .decapsulate(&bytes(test, "c"), &bytes(test, "dk"))
                .expect("a decapsulation");
            let name = mechanism.description().name;
            assert_eq!(
                secret.bytes(),
                bytes(test, "k"),
                "{name}, tcId {}",
                identifier(test)
            );
            testCount += 1;
        }
    }
    assert_eq!(testCount, 30);
}
