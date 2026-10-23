//! The ACVP vectors of liboqs `tests/test_acvp_vectors.py` and `tests/vectors_sig.c` for
//! SLH-DSA: the key generation, signature generation and verification vectors of NIST
//! ACVP-Server for FIPS 205.
//!
//! As in `vectors_sig.c`, a key generation draws its seeds from the expected secret key, and a
//! signature of the external interface draws the additional randomness of the vector, or
//! `PK.seed` for a deterministic vector, from the random source. The internal interface calls
//! `signInternal` and `isValidSignatureInternal`, as the C program calls `slh_sign_internal`
//! and `slh_verify_internal`. With an empty context, the plain forms must give the same result.
//!
//! `test_acvp_vectors.py` makes the liboqs name of a pre-hash vector from its hash name with
//! `-` replaced by `_`, so `SHA2-512/224` and `SHA2-512/256` keep their slash, match no liboqs
//! name, and liboqs skips their vectors. This test maps them to `SHA2_512_224` and
//! `SHA2_512_256` and runs them too.

use OQSNativeAlgorithmTests::{JSONValue, TestVectorFiles};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeSLHDSA::SLHDSA;

/// A random source that gives the bytes of a stream in order, as `SLHDSA_randombytes` of
/// `vectors_sig.c` does.
struct StreamRandom {
    bytes: Vec<u8>,
    position: usize,
}

impl StreamRandom {
    fn new(bytes: Vec<u8>) -> Self {
        StreamRandom { bytes, position: 0 }
    }
}

impl RandomGenerating for StreamRandom {
    fn fillRandomBytes(&mut self, output: &mut [u8]) {
        let end = self.position + output.len();
        assert!(
            end <= self.bytes.len(),
            "the request ends at byte {end} of a stream of {} bytes",
            self.bytes.len()
        );
        output.copy_from_slice(&self.bytes[self.position..end]);
        self.position = end;
    }
}

fn document(fileName: &str) -> JSONValue {
    TestVectorFiles::document(fileName).unwrap_or_else(|message| panic!("{message}"))
}

fn text<'value>(value: &'value JSONValue, field: &str) -> &'value str {
    value
        .member(field)
        .and_then(JSONValue::text)
        .unwrap_or_else(|| panic!("the vector has the text field {field}"))
}

fn bytes(test: &JSONValue, field: &str) -> Vec<u8> {
    test.member(field)
        .and_then(JSONValue::hexBytes)
        .unwrap_or_else(|| panic!("the vector has the hexadecimal field {field}"))
}

fn isTrue(value: &JSONValue, field: &str) -> bool {
    value.member(field) == Some(&JSONValue::boolean(true))
}

fn identifier(test: &JSONValue) -> String {
    match test.member("tcId") {
        Some(JSONValue::number(text)) => text.clone(),
        _ => "?".to_string(),
    }
}

fn groups(document: &JSONValue) -> &[JSONValue] {
    document
        .member("testGroups")
        .map(JSONValue::elements)
        .unwrap_or_default()
}

fn tests(group: &JSONValue) -> &[JSONValue] {
    group
        .member("tests")
        .map(JSONValue::elements)
        .unwrap_or_default()
}

/// The liboqs name of an ACVP parameter set, such as `SLH-DSA-SHA2-128s`, in the pure form or
/// with the hash name of a pre-hash vector, as `slh_test_sig_name` of the Python script makes
/// it, with the slash of `SHA2-512/224` and `SHA2-512/256` replaced too.
fn liboqsName(parameterSet: &str, preHash: Option<&str>) -> String {
    let set = parameterSet
        .strip_prefix("SLH-DSA-")
        .unwrap_or_else(|| panic!("{parameterSet} is an SLH-DSA set"))
        .replace('-', "_")
        .to_uppercase();
    match preHash {
        None => format!("SLH_DSA_PURE_{set}"),
        Some(hash) => format!("SLH_DSA_{}_PREHASH_{set}", hash.replace(['-', '/'], "_")),
    }
}

/// The scheme of a liboqs name.
fn scheme(name: &str) -> &'static dyn Signing {
    SLHDSA::schemes
        .iter()
        .copied()
        .find(|scheme| scheme.description().name == name)
        .unwrap_or_else(|| panic!("{name} is a scheme of the family"))
}

/// The pure scheme of an ACVP parameter set, which has the internal functions.
fn pureScheme(parameterSet: &str) -> SLHDSA {
    let name = liboqsName(parameterSet, None);
    SLHDSA::pureSchemes
        .into_iter()
        .find(|scheme| scheme.description().name == name)
        .unwrap_or_else(|| panic!("{name} is a pure scheme"))
}

/// The schemes of the pure form and of each pre-hash form of a parameter set.
fn everyForm(parameterSet: &str) -> Vec<&'static dyn Signing> {
    let pureName = liboqsName(parameterSet, None);
    let suffix = pureName.strip_prefix("SLH_DSA_PURE").expect("a pure name");
    SLHDSA::schemes
        .iter()
        .copied()
        .filter(|scheme| scheme.description().name.ends_with(suffix))
        .collect()
}

/// Checks the key generation vectors of the groups whose sets pass a filter, with the pure
/// scheme or with every form of the set. Returns the number of vectors.
fn checkKeyGenerationVectors(isSelected: fn(&str) -> bool, isEveryForm: bool) -> usize {
    let document = document("SLH-DSA-keyGen-FIPS205.json");
    let mut count = 0;
    for group in groups(&document) {
        let parameterSet = text(group, "parameterSet");
        if !isSelected(parameterSet) {
            continue;
        }
        let schemes = if isEveryForm {
            everyForm(parameterSet)
        } else {
            vec![scheme(&liboqsName(parameterSet, None))]
        };
        assert_eq!(schemes.len(), if isEveryForm { 13 } else { 1 });
        for test in tests(group) {
            let secretKey = bytes(test, "sk");
            let mut seeds = bytes(test, "skSeed");
            seeds.extend(bytes(test, "skPrf"));
            seeds.extend(bytes(test, "pkSeed"));
            assert_eq!(secretKey[..seeds.len()], seeds);
            for scheme in &schemes {
                let name = scheme.description().name;
                // `vectors_sig.c` gives the expected secret key as the random stream.
                let keyPair = scheme
                    .generateKeyPair(&mut StreamRandom::new(secretKey.clone()))
                    .expect("a key pair");
                assert_eq!(
                    keyPair.publicKey,
                    bytes(test, "pk"),
                    "{name}, tcId {}",
                    identifier(test)
                );
                assert_eq!(
                    keyPair.secretKey.bytes(),
                    secretKey.as_slice(),
                    "{name}, tcId {}",
                    identifier(test)
                );
            }
            count += 1;
        }
    }
    count
}

fn isAnySet(_: &str) -> bool {
    true
}

fn isFastSet(parameterSet: &str) -> bool {
    parameterSet.ends_with('f')
}

fn isSmallSet(parameterSet: &str) -> bool {
    parameterSet.ends_with('s')
}

fn isFastSHA2Set(parameterSet: &str) -> bool {
    isFastSet(parameterSet) && parameterSet.starts_with("SLH-DSA-SHA2-")
}

fn isFastSHAKESet(parameterSet: &str) -> bool {
    isFastSet(parameterSet) && parameterSet.starts_with("SLH-DSA-SHAKE-")
}

#[test]
fn keyGenerationVectorsGiveTheirKeys() {
    assert_eq!(checkKeyGenerationVectors(isAnySet, false), 120);
}

#[test]
fn everyFormOfAFastSetGeneratesTheKeysOfItsVectors() {
    assert_eq!(checkKeyGenerationVectors(isFastSet, true), 60);
}

#[test]
#[ignore = "the 13 forms of the small sets generate 780 keys in two minutes of a debug build"]
fn everyFormOfASmallSetGeneratesTheKeysOfItsVectors() {
    assert_eq!(checkKeyGenerationVectors(isSmallSet, true), 60);
}

/// Checks the signature generation vectors of the groups whose sets pass a filter. Returns the
/// number of vectors.
fn checkSignatureVectors(isSelected: fn(&str) -> bool) -> usize {
    let document = document("SLH-DSA-sigGen-FIPS205.json");
    let mut count = 0;
    for group in groups(&document) {
        let parameterSet = text(group, "parameterSet");
        if !isSelected(parameterSet) {
            continue;
        }
        let isDeterministic = isTrue(group, "deterministic");
        let interface = text(group, "signatureInterface");
        let isPreHash = text(group, "preHash") == "preHash";
        for test in tests(group) {
            let secretKey = bytes(test, "sk");
            let n = secretKey.len() / 4;
            // A deterministic signature takes PK.seed as its randomness, as in the C program.
            let randomness = if isDeterministic {
                secretKey[2 * n..3 * n].to_vec()
            } else {
                bytes(test, "additionalRandomness")
            };
            let message = bytes(test, "message");
            let expected = bytes(test, "signature");
            if interface == "internal" {
                let scheme = pureScheme(parameterSet);
                assert_eq!(
                    scheme.signInternal(&message, &secretKey, &randomness),
                    Ok(expected),
                    "{parameterSet}, internal, tcId {}",
                    identifier(test)
                );
            } else {
                let name = liboqsName(parameterSet, isPreHash.then(|| text(test, "hashAlg")));
                let scheme = scheme(&name);
                let context = bytes(test, "context");
                assert_eq!(
                    scheme.signWithContext(
                        &message,
                        &context,
                        &secretKey,
                        &mut StreamRandom::new(randomness.clone())
                    ),
                    Ok(expected.clone()),
                    "{name}, tcId {}",
                    identifier(test)
                );
                if context.is_empty() {
                    assert_eq!(
                        scheme.sign(&message, &secretKey, &mut StreamRandom::new(randomness)),
                        Ok(expected),
                        "{name}, plain form, tcId {}",
                        identifier(test)
                    );
                }
            }
            count += 1;
        }
    }
    count
}

#[test]
fn signatureVectorsOfTheFastSHA2SetsGiveTheirSignatures() {
    assert_eq!(checkSignatureVectors(isFastSHA2Set), 156);
}

#[test]
fn signatureVectorsOfTheFastSHAKESetsGiveTheirSignatures() {
    assert_eq!(checkSignatureVectors(isFastSHAKESet), 156);
}

#[test]
#[ignore = "the 312 vectors of the small sets sign for eight minutes in a debug build"]
fn signatureVectorsOfTheSmallSetsGiveTheirSignatures() {
    assert_eq!(checkSignatureVectors(isSmallSet), 312);
}

#[test]
fn verificationVectorsGiveTheirVerdicts() {
    let document = document("SLH-DSA-sigVer-FIPS205.json");
    let mut verdicts = [0usize; 2];
    for group in groups(&document) {
        let parameterSet = text(group, "parameterSet");
        let interface = text(group, "signatureInterface");
        let isPreHash = text(group, "preHash") == "preHash";
        for test in tests(group) {
            let publicKey = bytes(test, "pk");
            let message = bytes(test, "message");
            let signature = bytes(test, "signature");
            let isPassing = isTrue(test, "testPassed");
            let label = format!(
                "{parameterSet}, {interface}, tcId {}, {}",
                identifier(test),
                text(test, "reason")
            );
            if interface == "internal" {
                let scheme = pureScheme(parameterSet);
                assert_eq!(
                    scheme.isValidSignatureInternal(&signature, &message, &publicKey),
                    isPassing,
                    "{label}"
                );
            } else {
                let name = liboqsName(parameterSet, isPreHash.then(|| text(test, "hashAlg")));
                let scheme = scheme(&name);
                let context = bytes(test, "context");
                assert_eq!(
                    scheme.isValidSignatureWithContext(&signature, &message, &context, &publicKey),
                    isPassing,
                    "{label}"
                );
                if context.is_empty() {
                    assert_eq!(
                        scheme.isValidSignature(&signature, &message, &publicKey),
                        isPassing,
                        "{label}, plain form"
                    );
                }
            }
            verdicts[usize::from(isPassing)] += 1;
        }
    }
    // Six of each seven vectors are invalid: a changed message, R, FORS or hypertree part, and
    // a signature one byte too long or too short.
    assert_eq!(verdicts, [432, 72]);
}

#[test]
fn liboqsNamesFollowTheNamesOfThePythonScript() {
    assert_eq!(
        liboqsName("SLH-DSA-SHA2-128s", None),
        "SLH_DSA_PURE_SHA2_128S"
    );
    assert_eq!(
        liboqsName("SLH-DSA-SHAKE-256f", Some("SHA3-384")),
        "SLH_DSA_SHA3_384_PREHASH_SHAKE_256F"
    );
    assert_eq!(
        liboqsName("SLH-DSA-SHA2-192s", Some("SHA2-512/224")),
        "SLH_DSA_SHA2_512_224_PREHASH_SHA2_192S"
    );
    assert_eq!(everyForm("SLH-DSA-SHAKE-192f").len(), 13);
}
