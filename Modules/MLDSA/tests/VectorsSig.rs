//! The ACVP vectors of liboqs `tests/test_acvp_vectors.py` and `tests/vectors_sig.c`: the key
//! generation, signature generation and signature verification vectors of NIST ACVP-Server for
//! ML-DSA, in the external, the pre-hash and the internal forms.
//!
//! As in the C program, a key pair and an external signature draw the seed and the randomness
//! of a vector from a `VectorRandom` source, and the internal forms take them as arguments.
//! The Python test hashes the message of a pre-hash vector with `hashlib`, and this test hashes
//! it with the hash functions of the port.

use OQSNativeAlgorithmTests::{JSONValue, TestVectorFiles, VectorRandom};
use OQSNativeDomain::Signing;
use OQSNativeMLDSA::{MLDSA, PreHashAlgorithm};
use OQSNativeSHA2::{SHA224, SHA256, SHA384, SHA512, SHA512224, SHA512256};
use OQSNativeSHA3::{SHA3224, SHA3256, SHA3384, SHA3512, SHAKE128, SHAKE256};

fn scheme(parameterSet: &str) -> Option<&'static MLDSA> {
    match parameterSet {
        "ML-DSA-44" => Some(&MLDSA::mldsa44),
        "ML-DSA-65" => Some(&MLDSA::mldsa65),
        "ML-DSA-87" => Some(&MLDSA::mldsa87),
        _ => None,
    }
}

fn bytes(test: &JSONValue, field: &str) -> Vec<u8> {
    test.member(field)
        .and_then(JSONValue::hexBytes)
        .unwrap_or_else(|| panic!("the vector has the hexadecimal field {field}"))
}

fn text<'value>(value: &'value JSONValue, field: &str) -> &'value str {
    value
        .member(field)
        .and_then(JSONValue::text)
        .unwrap_or_else(|| panic!("the vector has the text field {field}"))
}

fn flag(value: &JSONValue, field: &str) -> bool {
    match value.member(field) {
        Some(JSONValue::boolean(isSet)) => *isSet,
        _ => panic!("the vector has the boolean field {field}"),
    }
}

fn identifier(test: &JSONValue) -> String {
    match test.member("tcId") {
        Some(JSONValue::number(text)) => text.clone(),
        _ => "?".to_string(),
    }
}

/// The groups of a file whose parameter set is an ML-DSA set.
fn groups(document: &JSONValue) -> Vec<(&'static MLDSA, &JSONValue)> {
    document
        .member("testGroups")
        .map(JSONValue::elements)
        .unwrap_or_default()
        .iter()
        .filter_map(|group| {
            let parameterSet = group.member("parameterSet").and_then(JSONValue::text)?;
            Some((scheme(parameterSet)?, group))
        })
        .collect()
}

fn tests(group: &JSONValue) -> &[JSONValue] {
    group
        .member("tests")
        .map(JSONValue::elements)
        .unwrap_or_default()
}

/// The pre-hash function of an ACVP hash name and the hash of a message, as `calc_hash` of
/// `tests/test_acvp_vectors.py` computes it.
fn preHash(hashName: &str, message: &[u8]) -> (PreHashAlgorithm, Vec<u8>) {
    match hashName {
        "SHA2-224" => (PreHashAlgorithm::sha224, SHA224::hash(message).to_vec()),
        "SHA2-256" => (PreHashAlgorithm::sha256, SHA256::hash(message).to_vec()),
        "SHA2-384" => (PreHashAlgorithm::sha384, SHA384::hash(message).to_vec()),
        "SHA2-512" => (PreHashAlgorithm::sha512, SHA512::hash(message).to_vec()),
        "SHA2-512/224" => (
            PreHashAlgorithm::sha512224,
            SHA512224::hash(message).to_vec(),
        ),
        "SHA2-512/256" => (
            PreHashAlgorithm::sha512256,
            SHA512256::hash(message).to_vec(),
        ),
        "SHA3-224" => (PreHashAlgorithm::sha3224, SHA3224::hash(message).to_vec()),
        "SHA3-256" => (PreHashAlgorithm::sha3256, SHA3256::hash(message).to_vec()),
        "SHA3-384" => (PreHashAlgorithm::sha3384, SHA3384::hash(message).to_vec()),
        "SHA3-512" => (PreHashAlgorithm::sha3512, SHA3512::hash(message).to_vec()),
        "SHAKE-128" => {
            let mut hash = vec![0u8; 32];
            SHAKE128::hash(message, &mut hash);
            (PreHashAlgorithm::shake128, hash)
        }
        "SHAKE-256" => {
            let mut hash = vec![0u8; 64];
            SHAKE256::hash(message, &mut hash);
            (PreHashAlgorithm::shake256, hash)
        }
        other => panic!("the hash function {other} has no pre-hash form"),
    }
}

#[test]
fn keyGenerationVectorsGiveTheirKeysFromOneRequestOfTheSeed() {
    let document = TestVectorFiles::document("ML-DSA-keyGen-FIPS204.json")
        .unwrap_or_else(|message| panic!("{message}"));
    let mut testCount = 0;
    for (scheme, group) in groups(&document) {
        let name = scheme.description().name;
        for test in tests(group) {
            let mut random = VectorRandom::new(&bytes(test, "seed"));
            let keyPair = scheme.generateKeyPair(&mut random).expect("a key pair");
            assert_eq!(
                random.remainingCount(),
                0,
                "{name}, tcId {}",
                identifier(test)
            );
            assert_eq!(
                keyPair.publicKey,
                bytes(test, "pk"),
                "{name}, tcId {}",
                identifier(test)
            );
            assert_eq!(
                keyPair.secretKey.bytes(),
                bytes(test, "sk"),
                "{name}, tcId {}",
                identifier(test)
            );
            testCount += 1;
        }
    }
    assert_eq!(testCount, 75);
}

#[test]
fn signatureGenerationVectorsGiveTheirSignaturesInEachForm() {
    let document = TestVectorFiles::document("ML-DSA-sigGen-FIPS204.json")
        .unwrap_or_else(|message| panic!("{message}"));
    let mut formCounts = [0usize; 4];
    for (scheme, group) in groups(&document) {
        let name = scheme.description().name;
        let isDeterministic = flag(group, "deterministic");
        let interface = text(group, "signatureInterface");
        let isPreHash = text(group, "preHash") == "preHash";
        let isExternalMu = flag(group, "externalMu");
        for test in tests(group) {
            let label = format!("{name}, tcId {}", identifier(test));
            let secretKey = bytes(test, "sk");
            let randomness = if isDeterministic {
                vec![0u8; 32]
            } else {
                bytes(test, "rnd")
            };
            let expected = bytes(test, "signature");
            match (interface, isPreHash) {
                ("internal", _) => {
                    let message = bytes(test, if isExternalMu { "mu" } else { "message" });
                    assert_eq!(
                        scheme.internalSignature(&message, &secretKey, &randomness, isExternalMu),
                        Ok(expected),
                        "{label}"
                    );
                    formCounts[usize::from(isExternalMu)] += 1;
                }
                ("external", false) => {
                    let message = bytes(test, "message");
                    let context = bytes(test, "context");
                    let mut random = VectorRandom::new(&randomness);
                    assert_eq!(
                        scheme.signWithContext(&message, &context, &secretKey, &mut random),
                        Ok(expected.clone()),
                        "{label}"
                    );
                    if context.is_empty() {
                        // `OQS_SIG_sign` gives the signature of the empty context.
                        let mut random = VectorRandom::new(&randomness);
                        assert_eq!(
                            scheme.sign(&message, &secretKey, &mut random),
                            Ok(expected),
                            "{label}"
                        );
                    }
                    formCounts[2] += 1;
                }
                ("external", true) => {
                    let (algorithm, hash) = preHash(text(test, "hashAlg"), &bytes(test, "message"));
                    assert_eq!(
                        scheme.preHashSignature(
                            &hash,
                            algorithm,
                            &bytes(test, "context"),
                            &secretKey,
                            &randomness
                        ),
                        Ok(expected),
                        "{label}"
                    );
                    formCounts[3] += 1;
                }
                (other, _) => panic!("{label}: the interface {other} is unknown"),
            }
        }
    }
    // Internal, internal with an external mu, external and pre-hash, deterministic and not,
    // for each of the three sets.
    assert_eq!(formCounts, [90, 90, 90, 90]);
}

#[test]
fn signatureVerificationVectorsGiveTheirVerdictsInEachForm() {
    let document = TestVectorFiles::document("ML-DSA-sigVer-FIPS204.json")
        .unwrap_or_else(|message| panic!("{message}"));
    let mut verdictCounts = [0usize; 2];
    for (scheme, group) in groups(&document) {
        let name = scheme.description().name;
        let interface = text(group, "signatureInterface");
        let isPreHash = text(group, "preHash") == "preHash";
        let isExternalMu = flag(group, "externalMu");
        for test in tests(group) {
            let label = format!("{name}, tcId {}", identifier(test));
            let isPassed = flag(test, "testPassed");
            let publicKey = bytes(test, "pk");
            let signature = bytes(test, "signature");
            let verdict = match (interface, isPreHash) {
                ("internal", _) => {
                    let message = bytes(test, if isExternalMu { "mu" } else { "message" });
                    scheme.isValidInternalSignature(&signature, &message, &publicKey, isExternalMu)
                }
                ("external", false) => {
                    let message = bytes(test, "message");
                    let context = bytes(test, "context");
                    let verdict = scheme
                        .isValidSignatureWithContext(&signature, &message, &context, &publicKey);
                    if context.is_empty() {
                        assert_eq!(
                            scheme.isValidSignature(&signature, &message, &publicKey),
                            verdict,
                            "{label}"
                        );
                    }
                    verdict
                }
                ("external", true) => {
                    let (algorithm, hash) = preHash(text(test, "hashAlg"), &bytes(test, "message"));
                    scheme.isValidPreHashSignature(
                        &signature,
                        &hash,
                        algorithm,
                        &bytes(test, "context"),
                        &publicKey,
                    )
                }
                (other, _) => panic!("{label}: the interface {other} is unknown"),
            };
            assert_eq!(verdict, isPassed, "{label}");
            verdictCounts[usize::from(isPassed)] += 1;
        }
    }
    // Both verdicts occur, so the test proves both sides of the decision.
    assert_eq!(verdictCounts.iter().sum::<usize>(), 180);
    assert!(
        verdictCounts.iter().all(|count| *count > 30),
        "{verdictCounts:?}"
    );
}
