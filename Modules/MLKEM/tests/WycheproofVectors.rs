//! The Wycheproof vectors of liboqs `tests/test_wycheproof_vectors.py` for ML-KEM: key
//! generation from a seed, encapsulation with keys whose coefficients overflow the modulus, and
//! decapsulation with invalid ciphertexts and keys.
//!
//! The C program `tests/vectors_kem.c` checks each key with its own helper before it calls
//! liboqs. The Rust port makes those checks inside `encapsulate` and `decapsulate`, so here the
//! port itself must refuse each invalid key.

use OQSNativeAlgorithmTests::{JSONValue, TestVectorFiles};
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeMLKEM::MLKEM;

const parameterSets: [(&str, &MLKEM); 3] = [
    ("512", &MLKEM::mlkem512),
    ("768", &MLKEM::mlkem768),
    ("1024", &MLKEM::mlkem1024),
];

fn field(test: &JSONValue, name: &str) -> Option<Vec<u8>> {
    test.member(name).and_then(JSONValue::hexBytes)
}

fn label(test: &JSONValue) -> String {
    match test.member("tcId") {
        Some(JSONValue::number(text)) => format!("tcId {text}"),
        _ => "tcId ?".to_string(),
    }
}

fn isValid(test: &JSONValue) -> bool {
    test.member("result").and_then(JSONValue::text) == Some("valid")
}

fn hasFlag(test: &JSONValue, flag: &str) -> bool {
    test.member("flags")
        .map(JSONValue::elements)
        .unwrap_or_default()
        .iter()
        .any(|value| value.text() == Some(flag))
}

/// The counts of the valid and of the invalid tests of a list.
fn counts(tests: &[JSONValue]) -> (usize, usize) {
    let validCount = tests.iter().filter(|test| isValid(test)).count();
    (validCount, tests.len() - validCount)
}

/// The tests of the groups of a type in a vector file.
fn tests(fileName: &str, groupTypes: &[&str]) -> Vec<JSONValue> {
    let document =
        TestVectorFiles::document(fileName).unwrap_or_else(|message| panic!("{message}"));
    document
        .member("testGroups")
        .map(JSONValue::elements)
        .unwrap_or_default()
        .iter()
        .filter(|group| {
            group
                .member("type")
                .and_then(JSONValue::text)
                .is_some_and(|groupType| groupTypes.contains(&groupType))
        })
        .flat_map(|group| {
            group
                .member("tests")
                .map(JSONValue::elements)
                .unwrap_or_default()
                .to_vec()
        })
        .collect()
}

#[test]
fn keyGenerationFromASeedGivesTheKeysOfEachVector() {
    for (set, mechanism) in parameterSets {
        let file = format!("mlkem_{set}_keygen_seed_test.json");
        let tests = tests(&file, &["MLKEMKeyGen"]);
        assert_eq!(counts(&tests), (100, 0), "{file}");
        for test in &tests {
            let keyPair = mechanism.generateKeyPairFromSeed(&field(test, "seed").expect("a seed"));
            let isAccepted = keyPair.as_ref().is_ok_and(|keyPair| {
                Some(&keyPair.publicKey) == field(test, "ek").as_ref()
                    && Some(keyPair.secretKey.bytes().to_vec()) == field(test, "dk")
            });
            assert_eq!(isAccepted, isValid(test), "{file}, {}", label(test));
        }
    }
}

#[test]
fn encapsulationAcceptsTheValidVectorsAndRefusesEveryOtherOne() {
    for ((set, mechanism), invalidCount) in parameterSets.into_iter().zip([128, 132, 136]) {
        let file = format!("mlkem_{set}_encaps_test.json");
        let tests = tests(&file, &["MLKEMEncapsTest"]);
        assert_eq!(counts(&tests), (133, invalidCount), "{file}");
        let publicKeyLength = mechanism.description().publicKeyLength;
        for test in &tests {
            let publicKey = field(test, "ek").unwrap_or_default();
            let message = field(test, "m").unwrap_or_else(|| vec![0; 32]);
            let expectedCiphertext = field(test, "c").filter(|bytes| !bytes.is_empty());
            let expectedSecret = field(test, "K").filter(|bytes| !bytes.is_empty());
            let result = mechanism.encapsulateWithSeed(&publicKey, &message);
            let isInvalidKey = expectedCiphertext.is_none()
                || expectedSecret.is_none()
                || hasFlag(test, "ModulusOverflow");
            if isInvalidKey && publicKey.len() == publicKeyLength {
                // The modulus check must refuse a key of the right length with an overflow.
                assert!(
                    result.is_err(),
                    "{file}, {}: the overflowing key is accepted",
                    label(test)
                );
                continue;
            }
            let isAccepted = result.as_ref().is_ok_and(|encapsulation| {
                Some(&encapsulation.ciphertext) == expectedCiphertext.as_ref()
                    && Some(encapsulation.sharedSecret.bytes().to_vec()) == expectedSecret
            });
            assert_eq!(isAccepted, isValid(test), "{file}, {}", label(test));
        }
    }
}

#[test]
fn keyGenerationAndDecapsulationGiveTheSecretOfEachVector() {
    for (set, mechanism) in parameterSets {
        let file = format!("mlkem_{set}_test.json");
        let tests = tests(&file, &["MLKEMTest"]);
        assert_eq!(counts(&tests), (153, 40), "{file}");
        for test in &tests {
            let (Some(seed), Some(publicKey)) = (field(test, "seed"), field(test, "ek")) else {
                continue;
            };
            let ciphertext = field(test, "c").unwrap_or_default();
            let expectedSecret = field(test, "K").unwrap_or_else(|| vec![0; 32]);
            let isAccepted = mechanism
                .generateKeyPairFromSeed(&seed)
                .is_ok_and(|keyPair| {
                    keyPair.publicKey == publicKey
                        && mechanism
                            .decapsulate(&ciphertext, keyPair.secretKey.bytes())
                            .is_ok_and(|secret| secret.bytes() == expectedSecret)
                });
            assert_eq!(isAccepted, isValid(test), "{file}, {}", label(test));
        }
    }
}

#[test]
fn decapsulationRefusesInvalidKeysAndCiphertextsOfTheValidationVectors() {
    for (set, mechanism) in parameterSets {
        let file = format!("mlkem_{set}_semi_expanded_decaps_test.json");
        let tests = tests(&file, &["MLKEMDecapsValidationTest"]);
        assert_eq!(counts(&tests), (1, 6), "{file}");
        for test in &tests {
            let secretKey = field(test, "dk").unwrap_or_default();
            let ciphertext = field(test, "c").unwrap_or_default();
            let result = mechanism.decapsulate(&ciphertext, &secretKey);
            if isValid(test) {
                // The file gives no secret for a valid case, so the decapsulation must complete.
                assert!(result.is_ok(), "{file}, {}", label(test));
            } else {
                assert!(
                    result.is_err(),
                    "{file}, {}: the invalid input is accepted",
                    label(test)
                );
            }
        }
    }
}
