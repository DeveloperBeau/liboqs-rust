//! The fuzz test of liboqs `tests/fuzz_test_sig.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error.
//!
//! Every byte string of the right length is a key or a signature of UOV, so no input fails to
//! decode. A secret key of random bytes signs, and a random signature or public key is not
//! valid. The sets of the larger shapes run fewer cases, because a key pair of OV-V takes a
//! large part of a second in a test build.

use OQSNativeAlgorithmTests::{FuzzRandom, SignatureFuzzTest};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeSHA3::SHAKE256;
use OQSNativeUOV::UOV;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x554F_565F_4655_5A5A;

/// The cases of a set of the shapes of OV-Is and OV-Ip.
const smallCaseCount: u64 = 16;

/// The cases of a set of the shapes of OV-III and OV-V.
const largeCaseCount: u64 = 4;

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

/// The vinegar variables v, the oil variables o and the elements of a byte of the four shapes.
const shapes: [(usize, usize, usize); 4] = [(96, 64, 2), (68, 44, 1), (112, 72, 1), (148, 96, 1)];

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestSigPassesForOVIs() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovIs, fuzzSeed, smallCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVIp() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovIp, fuzzSeed, smallCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVIII() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovIII, fuzzSeed, largeCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVV() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovV, fuzzSeed, largeCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVIsWithACompressedPublicKey() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovIsCompressedPublicKey, fuzzSeed, smallCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVIpWithACompressedPublicKey() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovIpCompressedPublicKey, fuzzSeed, smallCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVIIIWithACompressedPublicKey() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovIIICompressedPublicKey, fuzzSeed, largeCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVVWithACompressedPublicKey() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovVCompressedPublicKey, fuzzSeed, largeCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVIsWithCompressedKeys() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovIsCompressedKeys, fuzzSeed, smallCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVIpWithCompressedKeys() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovIpCompressedKeys, fuzzSeed, smallCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVIIIWithCompressedKeys() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovIIICompressedKeys, fuzzSeed, largeCaseCount),
        Ok(())
    );
}

#[test]
fn fuzzTestSigPassesForOVVWithCompressedKeys() {
    assert_eq!(
        SignatureFuzzTest::run(&UOV::ovVCompressedKeys, fuzzSeed, largeCaseCount),
        Ok(())
    );
}

#[test]
fn randomSecretKeysSignAndHostileSignaturesAreRefused() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for (index, scheme) in parameterSets.into_iter().enumerate() {
        let description = scheme.description();
        let (vinegarCount, oilCount, elementsPerByte) = shapes[index % 4];
        let entryLength = oilCount / elementsPerByte;
        let pointLength = (vinegarCount + oilCount) / elementsPerByte;
        for case in 0..4 {
            let failure = format!("{}, case {case} of seed {fuzzSeed:#x}", description.name);
            let message = randomBytes(&mut random, case * 13);
            // A secret key of random bytes, or a random seed of a compressed secret key, signs.
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let signature = scheme.sign(&message, &secretKey, &mut random);
            assert!(
                signature
                    .as_ref()
                    .is_ok_and(|bytes| bytes.len() == description.signatureLength),
                "{failure}: {signature:?}"
            );
            // A public key that accepts one signature only: its map is zero except for the
            // square of the first oil variable, which is the target of a salt of zeros.
            let mut target = vec![0u8; entryLength];
            let mut hash = SHAKE256::new();
            hash.absorb(&message);
            hash.absorb(&[0u8; 16]);
            hash.finalize().squeeze(&mut target);
            let mut publicKey = vec![0u8; description.publicKeyLength];
            let oilBlockStart = if index < 4 {
                publicKey.len() - entryLength * oilCount * (oilCount + 1) / 2
            } else {
                16
            };
            publicKey[oilBlockStart..oilBlockStart + entryLength].copy_from_slice(&target);
            let mut accepted = vec![0u8; description.signatureLength];
            accepted[vinegarCount / elementsPerByte] = 1;
            assert!(
                scheme.isValidSignature(&accepted, &message, &publicKey),
                "{failure}"
            );
            // The zero point, a point of ones, a random signature and the random-key signature
            // are refused.
            let mut zeroPoint = accepted.clone();
            zeroPoint[..pointLength].fill(0);
            let mut onesPoint = accepted.clone();
            onesPoint[..pointLength].fill(0xFF);
            let hostile = randomBytes(&mut random, description.signatureLength);
            for (label, candidate) in [
                ("the zero point", &zeroPoint),
                ("the point of ones", &onesPoint),
                ("a random signature", &hostile),
                (
                    "the random-key signature",
                    signature.as_ref().expect("a signature"),
                ),
            ] {
                assert!(
                    !scheme.isValidSignature(candidate, &message, &publicKey),
                    "{failure}: {label}"
                );
            }
        }
    }
}
