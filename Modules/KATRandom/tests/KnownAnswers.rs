//! Known answers of the two generators, with expected values from sources outside this code.

use OQSNativeDomain::RandomGenerating;
use OQSNativeKATRandom::{HQCKATRandom, NISTKATRandom};
use OQSNativeSHA3::SHAKE256;

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
        .collect()
}

/// The entropy of the liboqs and NIST known-answer programs: the bytes 0 to 47.
fn countingEntropy() -> [u8; 48] {
    core::array::from_fn(|index| index as u8)
}

/// The first two seeds of every NIST known-answer file. The first one is also inside the
/// secret key of `tests/KATs/sig_stfl/xmss/XMSS-SHA2_10_256.rsp` of liboqs.
#[test]
fn nistGeneratorGivesTheSeedsOfTheNISTKnownAnswerFiles() {
    let mut generator = NISTKATRandom::new(&countingEntropy(), None);
    let mut seed = [0u8; 48];
    generator.fillRandomBytes(&mut seed);
    assert_eq!(
        seed.to_vec(),
        bytes(
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
        )
    );
    generator.fillRandomBytes(&mut seed);
    assert_eq!(
        seed.to_vec(),
        bytes(
            "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC81ADDE6AEEB4A5A875C3BFCADFA958F"
        )
    );
}

#[test]
fn nistGeneratorOutputDependsOnHowRequestsSplitTheBytes() {
    let mut whole = NISTKATRandom::new(&countingEntropy(), None);
    let mut one = [0u8; 48];
    whole.fillRandomBytes(&mut one);
    let mut split = NISTKATRandom::new(&countingEntropy(), None);
    let mut first = [0u8; 32];
    let mut second = [0u8; 16];
    split.fillRandomBytes(&mut first);
    split.fillRandomBytes(&mut second);
    assert_eq!(&one[..32], &first);
    assert_ne!(
        &one[32..],
        &second,
        "each request ends with an update of the state"
    );
}

#[test]
fn nistGeneratorCloneSavesAndRestoresTheState() {
    let mut generator = NISTKATRandom::new(&countingEntropy(), None);
    let mut skipped = [0u8; 48];
    generator.fillRandomBytes(&mut skipped);
    let saved = generator.clone();
    let mut afterSave = [0u8; 100];
    generator.fillRandomBytes(&mut afterSave);
    let mut restored = saved;
    let mut afterRestore = [0u8; 100];
    restored.fillRandomBytes(&mut afterRestore);
    assert_eq!(afterSave, afterRestore);
    assert_eq!(generator.reseedCounter(), 3);
    assert_eq!(restored.reseedCounter(), 3);
}

#[test]
fn personalizationIsMixedIntoTheSeedMaterial() {
    let entropy = countingEntropy();
    let personalization = [0xA5u8; 48];
    let mut personal = NISTKATRandom::new(&entropy, Some(&personalization));
    let mut mixed = entropy;
    for (byte, mask) in mixed.iter_mut().zip(personalization) {
        *byte ^= mask;
    }
    let mut equivalent = NISTKATRandom::new(&mixed, None);
    let mut first = [0u8; 64];
    let mut second = [0u8; 64];
    personal.fillRandomBytes(&mut first);
    equivalent.fillRandomBytes(&mut second);
    assert_eq!(first, second, "personalization is a mask of the entropy");
    let mut plain = NISTKATRandom::new(&entropy, None);
    let mut third = [0u8; 64];
    plain.fillRandomBytes(&mut third);
    assert_ne!(first, third);
}

#[test]
fn emptyRequestStillAdvancesTheNISTState() {
    let mut generator = NISTKATRandom::new(&countingEntropy(), None);
    generator.fillRandomBytes(&mut []);
    let mut seed = [0u8; 48];
    generator.fillRandomBytes(&mut seed);
    assert_ne!(
        seed.to_vec(),
        bytes(
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
        )
    );
}

/// The HQC generator is SHAKE256 of the entropy, the personalization and the domain byte
/// zero. The expected stream comes from the SHAKE256 crate, which has its own known answers.
#[test]
fn hqcGeneratorIsSHAKE256OfTheSeedAndTheDomainByte() {
    let entropy = countingEntropy();
    let mut generator = HQCKATRandom::new(&entropy, None);
    let mut stream = [0u8; 300];
    for chunk in stream.chunks_mut(37) {
        generator.fillRandomBytes(chunk);
    }
    let mut input = entropy.to_vec();
    input.push(0);
    let mut expected = [0u8; 300];
    SHAKE256::hash(&input, &mut expected);
    assert_eq!(stream, expected);
    let personalization = [7u8; 48];
    let mut personal = HQCKATRandom::new(&entropy, Some(&personalization));
    let mut personalStream = [0u8; 64];
    personal.fillRandomBytes(&mut personalStream);
    let mut personalInput = entropy.to_vec();
    personalInput.extend_from_slice(&personalization);
    personalInput.push(0);
    let mut personalExpected = [0u8; 64];
    SHAKE256::hash(&personalInput, &mut personalExpected);
    assert_eq!(personalStream, personalExpected);
}

#[test]
fn hqcGeneratorCloneSavesTheState() {
    let mut generator = HQCKATRandom::new(&countingEntropy(), None);
    let mut skipped = [0u8; 48];
    generator.fillRandomBytes(&mut skipped);
    let mut saved = generator.clone();
    let mut first = [0u8; 48];
    let mut second = [0u8; 48];
    generator.fillRandomBytes(&mut first);
    saved.fillRandomBytes(&mut second);
    assert_eq!(first, second);
}
