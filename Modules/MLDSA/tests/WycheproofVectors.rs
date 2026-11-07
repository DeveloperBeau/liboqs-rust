//! The Wycheproof vectors of liboqs `tests/test_wycheproof_vectors.py` for ML-DSA: signatures
//! from expanded keys and from seeds, and verifications of valid and invalid signatures.
//!
//! The Python test signs with the randomness of a vector, or with zeros when it has none, and
//! passes when the signature equals the signature of a valid vector and differs from the one
//! of an invalid vector, which has no signature. A vector with an `Internal` flag, or with a
//! representative mu and no message, takes the internal form with the external mu. The vectors
//! with an expanded key and a message also hold mu, and this test signs both forms of them.

use OQSNativeAlgorithmTests::{JSONValue, TestVectorFiles, VectorRandom};
use OQSNativeDomain::Signing;
use OQSNativeMLDSA::MLDSA;

const parameterSets: [(&str, &MLDSA); 3] = [
    ("44", &MLDSA::mldsa44),
    ("65", &MLDSA::mldsa65),
    ("87", &MLDSA::mldsa87),
];

fn field(value: &JSONValue, name: &str) -> Option<Vec<u8>> {
    value.member(name).and_then(JSONValue::hexBytes)
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

/// True when the Python test takes the internal form with the external mu for a vector.
fn isInternal(test: &JSONValue) -> bool {
    hasFlag(test, "Internal") || (test.member("mu").is_some() && test.member("msg").is_none())
}

/// Each group of a type in a vector file, with its tests.
fn groups(fileName: &str, groupType: &str) -> Vec<(JSONValue, Vec<JSONValue>)> {
    let document =
        TestVectorFiles::document(fileName).unwrap_or_else(|message| panic!("{message}"));
    document
        .member("testGroups")
        .map(JSONValue::elements)
        .unwrap_or_default()
        .iter()
        .filter(|group| group.member("type").and_then(JSONValue::text) == Some(groupType))
        .map(|group| {
            let tests = group
                .member("tests")
                .map(JSONValue::elements)
                .unwrap_or_default()
                .to_vec();
            (group.clone(), tests)
        })
        .collect()
}

/// The counts of the valid and of the invalid tests of the groups.
fn counts(groups: &[(JSONValue, Vec<JSONValue>)]) -> (usize, usize) {
    let tests: Vec<&JSONValue> = groups.iter().flat_map(|(_, tests)| tests).collect();
    let validCount = tests.iter().filter(|test| isValid(test)).count();
    (validCount, tests.len() - validCount)
}

/// Checks the sign tests of a file with the secret key of each group, as
/// `test_wycheproof_vec_sig_sign` does.
fn checkSignTests(
    file: &str,
    scheme: &MLDSA,
    groups: &[(JSONValue, Vec<JSONValue>)],
    secretKeyOf: impl Fn(&JSONValue) -> Vec<u8>,
) {
    for (group, tests) in groups {
        let secretKey = secretKeyOf(group);
        for test in tests {
            let randomness = field(test, "rnd").unwrap_or_else(|| vec![0; 32]);
            let expected = field(test, "sig").filter(|signature| !signature.is_empty());
            let signature = if isInternal(test) {
                let representative = field(test, "mu").unwrap_or_default();
                scheme.internalSignature(&representative, &secretKey, &randomness, true)
            } else {
                let message = field(test, "msg").unwrap_or_default();
                let context = field(test, "ctx").unwrap_or_default();
                let mut random = VectorRandom::new(&randomness);
                scheme.signWithContext(&message, &context, &secretKey, &mut random)
            };
            let isAccepted = signature
                .as_ref()
                .is_ok_and(|signature| Some(signature) == expected.as_ref());
            assert_eq!(isAccepted, isValid(test), "{file}, {}", label(test));
            if isValid(test) && !isInternal(test) {
                // The external representative of the same message gives the same signature.
                if let Some(representative) = field(test, "mu") {
                    assert_eq!(
                        scheme
                            .internalSignature(&representative, &secretKey, &randomness, true)
                            .ok(),
                        expected,
                        "{file}, {}, mu",
                        label(test)
                    );
                }
            }
        }
    }
}

#[test]
fn signaturesWithExpandedKeysAreTheSignaturesOfTheValidVectorsOnly() {
    for ((set, scheme), expectedCounts) in
        parameterSets.into_iter().zip([(67, 5), (72, 5), (63, 5)])
    {
        let file = format!("mldsa_{set}_sign_noseed_test.json");
        let groups = groups(&file, "MlDsaSign");
        assert_eq!(counts(&groups), expectedCounts, "{file}");
        checkSignTests(&file, scheme, &groups, |group| {
            field(group, "privateKey").expect("an expanded key")
        });
    }
}

#[test]
fn signaturesWithKeysFromSeedsAreTheSignaturesOfTheValidVectorsOnly() {
    for ((set, scheme), expectedCounts) in
        parameterSets.into_iter().zip([(65, 1), (72, 1), (63, 1)])
    {
        let file = format!("mldsa_{set}_sign_seed_test.json");
        let groups = groups(&file, "MlDsaSign");
        assert_eq!(counts(&groups), expectedCounts, "{file}");
        checkSignTests(&file, scheme, &groups, |group| {
            // `expand_private_key_from_seed` takes the key pair of the seed, as keyGen does.
            let seed = field(group, "privateSeed").expect("a seed");
            let mut random = VectorRandom::new(&seed);
            let keyPair = scheme.generateKeyPair(&mut random).expect("a key pair");
            assert_eq!(
                Some(keyPair.publicKey),
                field(group, "publicKey"),
                "{file}: the public key of the seed"
            );
            keyPair.secretKey.bytes().to_vec()
        });
    }
}

#[test]
fn verificationAcceptsTheValidVectorsAndRefusesEveryOtherOne() {
    for ((set, scheme), expectedCounts) in
        parameterSets
            .into_iter()
            .zip([(63, 58), (65, 69), (56, 91)])
    {
        let file = format!("mldsa_{set}_verify_test.json");
        let groups = groups(&file, "MlDsaVerify");
        assert_eq!(counts(&groups), expectedCounts, "{file}");
        for (group, tests) in &groups {
            let groupKey = field(group, "publicKey").unwrap_or_default();
            for test in tests {
                let publicKey = field(test, "publicKey").unwrap_or_else(|| groupKey.clone());
                let signature = field(test, "sig").unwrap_or_default();
                let verdict = if isInternal(test) {
                    let representative = field(test, "mu").unwrap_or_default();
                    scheme.isValidInternalSignature(&signature, &representative, &publicKey, true)
                } else {
                    let message = field(test, "msg").unwrap_or_default();
                    let context = field(test, "ctx").unwrap_or_default();
                    let verdict = scheme
                        .isValidSignatureWithContext(&signature, &message, &context, &publicKey);
                    if context.is_empty() {
                        assert_eq!(
                            scheme.isValidSignature(&signature, &message, &publicKey),
                            verdict,
                            "{file}, {}",
                            label(test)
                        );
                    }
                    verdict
                };
                assert_eq!(verdict, isValid(test), "{file}, {}", label(test));
            }
        }
    }
}
