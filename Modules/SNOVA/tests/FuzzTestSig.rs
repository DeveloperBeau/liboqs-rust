//! The fuzz test of liboqs `tests/fuzz_test_sig.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error, and a
//! random signature or public key is never valid.

use OQSNativeAlgorithmTests::{FuzzRandom, SignatureFuzzTest};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeSNOVA::SNOVA;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x534E_4F56_415F_465A;

/// The cases of the liboqs program for each set. Case 0 draws only zeros and case 1 only ones.
/// A case of the largest sets takes a large part of a second in a test build, so each set runs
/// six cases, and the parity program runs the seeded variations in a release build.
const caseCount: u64 = 6;

const parameterSets: [&SNOVA; 12] = [
    &SNOVA::snova24x5x4,
    &SNOVA::snova24x5x4SHAKE,
    &SNOVA::snova24x5x4WithExpandedSecretKey,
    &SNOVA::snova24x5x4SHAKEWithExpandedSecretKey,
    &SNOVA::snova37x17x2,
    &SNOVA::snova25x8x3,
    &SNOVA::snova56x25x2,
    &SNOVA::snova49x11x3,
    &SNOVA::snova37x8x4,
    &SNOVA::snova24x5x5,
    &SNOVA::snova60x10x4,
    &SNOVA::snova29x6x5,
];

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestSigPassesForTheSetsOfRank4() {
    for scheme in [
        &SNOVA::snova24x5x4,
        &SNOVA::snova24x5x4SHAKE,
        &SNOVA::snova24x5x4WithExpandedSecretKey,
        &SNOVA::snova24x5x4SHAKEWithExpandedSecretKey,
        &SNOVA::snova37x8x4,
        &SNOVA::snova60x10x4,
    ] {
        assert_eq!(SignatureFuzzTest::run(scheme, fuzzSeed, caseCount), Ok(()));
    }
}

#[test]
fn fuzzTestSigPassesForTheSetsOfRanks2And3() {
    for scheme in [
        &SNOVA::snova37x17x2,
        &SNOVA::snova25x8x3,
        &SNOVA::snova56x25x2,
        &SNOVA::snova49x11x3,
    ] {
        assert_eq!(SignatureFuzzTest::run(scheme, fuzzSeed, caseCount), Ok(()));
    }
}

#[test]
fn fuzzTestSigPassesForTheSetsOfRank5() {
    for scheme in [&SNOVA::snova24x5x5, &SNOVA::snova29x6x5] {
        assert_eq!(SignatureFuzzTest::run(scheme, fuzzSeed, caseCount), Ok(()));
    }
}

#[test]
fn randomSecretKeysSignAndRandomSignaturesAndKeysAreRefused() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for scheme in parameterSets {
        let description = scheme.description();
        let name = description.name;
        let keyPair = scheme.generateKeyPair(&mut random).expect("key pair");
        let message = randomBytes(&mut random, 33);
        let signature = scheme
            .sign(&message, keyPair.secretKey.bytes(), &mut random)
            .expect("signature");
        for case in 0..3 {
            let failure = format!("{name}, case {case} of seed {fuzzSeed:#x}");
            // Any bytes of the right length are a secret key: two seeds, or an expanded key
            // that the C code does not check either.
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let hostileSigned = scheme.sign(&message, &secretKey, &mut random);
            assert!(
                hostileSigned
                    .as_ref()
                    .is_ok_and(|bytes| bytes.len() == description.signatureLength),
                "{failure}: {hostileSigned:?}"
            );
            let hostileSignature = randomBytes(&mut random, description.signatureLength);
            assert!(
                !scheme.isValidSignature(&hostileSignature, &message, &keyPair.publicKey),
                "{failure}"
            );
            // The salt of the real signature with random variables.
            let mut withSalt = hostileSignature.clone();
            let saltStart = description.signatureLength - 16;
            withSalt[saltStart..].copy_from_slice(&signature[saltStart..]);
            assert!(
                !scheme.isValidSignature(&withSalt, &message, &keyPair.publicKey),
                "{failure}"
            );
            // A public key with the public seed of the real one and random blocks P22.
            let mut publicKey = randomBytes(&mut random, description.publicKeyLength);
            publicKey[..16].copy_from_slice(&keyPair.publicKey[..16]);
            assert!(
                !scheme.isValidSignature(&signature, &message, &publicKey),
                "{failure}"
            );
        }
        assert!(scheme.isValidSignature(&signature, &message, &keyPair.publicKey));
    }
}
