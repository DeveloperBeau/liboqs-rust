//! Parity with the C library for keys that no key generation gives.
//!
//! mldsa-native decodes the vectors s1, s2 and t0 of a secret key with no range check, so it
//! signs with any bytes of the right length. Every byte string of the right length is a UOV
//! key, and a classic secret key whose block S is zero makes every attempt of a signature
//! fail. The SNOVA code unpacks an expanded secret key with no check either. The parity
//! variations sign only with generated keys, so these tests sign malformed keys on both sides
//! and compare the signatures, the failures and the verdicts on them. They also give both
//! sides UOV public keys made by hand, which accept one signature.

use OQSNative::{MLDSA, OQSError, SNOVA, Signing, UOV};
use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeParity::{LargeStack, ParityMismatch, VariationGenerator};
use OQSNativeSHA3::SHAKE256;

/// The seed of the malformed keys. A failure message names it.
const keySeed: u64 = 0x4D41_4C46_4F52_4D45;

/// The columns l, the rows k and the length of a packed polynomial of s1 or s2 of a set.
fn shape(name: &str) -> (usize, usize, usize) {
    match name {
        "ML-DSA-44" => (4, 4, 96),
        "ML-DSA-65" => (5, 6, 128),
        _ => (7, 8, 96),
    }
}

#[test]
fn mldsaSignsMalformedSecretKeysLikeTheCLibrary() {
    LargeStack::run(|| {
        for scheme in [&MLDSA::mldsa44, &MLDSA::mldsa65, &MLDSA::mldsa87] {
            let name = scheme.description().name;
            let (columnCount, rowCount, shortLength) = shape(name);
            let shortStart = 128;
            let errorStart = shortStart + columnCount * shortLength;
            let lowStart = errorStart + rowCount * shortLength;
            for case in 0..12u64 {
                let label = format!("{name}, case {case} of seed {keySeed:#x}");
                let mut generator = VariationGenerator::forCase(keySeed, name, case);
                let keyPair = scheme
                    .generateKeyPair(&mut NISTKATRandom::new(&generator.entropy(), None))
                    .expect("a key pair");
                let mut secretKey = keyPair.secretKey.bytes().to_vec();
                let region = match case % 4 {
                    // Every byte random, the seeds and tr too.
                    0 => 0..secretKey.len(),
                    // s1 with coefficients out of the range of eta.
                    1 => shortStart..errorStart,
                    // s2 with coefficients out of the range of eta.
                    2 => errorStart..lowStart,
                    // t0 with any 13-bit values.
                    _ => lowStart..secretKey.len(),
                };
                let replacement = generator.bytes(region.len());
                secretKey[region].copy_from_slice(&replacement);
                if case % 4 == 1 {
                    // The half bytes 15 and the 3-bit values 5 to 7 lie outside every range.
                    for byte in &mut secretKey[shortStart..shortStart + 8] {
                        *byte = 0xFF;
                    }
                }
                let messageLength = generator.messageLength();
                let message = generator.bytes(messageLength);
                let signingEntropy = generator.entropy();
                let cSignature = COracle::new(OracleRandomness::nist(signingEntropy))
                    .sign(name, &message, &secretKey);
                let rustSignature = scheme.sign(
                    &message,
                    &secretKey,
                    &mut NISTKATRandom::new(&signingEntropy, None),
                );
                let signature = cSignature
                    .unwrap_or_else(|error| panic!("{label}: the C signature fails: {error}"));
                let rustSignature = rustSignature
                    .unwrap_or_else(|error| panic!("{label}: the Rust signature fails: {error}"));
                if let Some(detail) = ParityMismatch::difference(&signature, &rustSignature) {
                    panic!("{label}: {detail}");
                }
                let cVerdict = COracle::new(OracleRandomness::nist([0; 48])).isValidSignature(
                    name,
                    &signature,
                    &message,
                    &keyPair.publicKey,
                );
                let rustVerdict = scheme.isValidSignature(&signature, &message, &keyPair.publicKey);
                assert_eq!(rustVerdict, cVerdict, "{label}");
            }
        }
    });
}

/// The twelve UOV sets, each with the vinegar variables v, the oil variables o and the elements
/// of a byte of its shape, from `params.h`.
const uovSets: [(&UOV, usize, usize, usize); 12] = [
    (&UOV::ovIs, 96, 64, 2),
    (&UOV::ovIp, 68, 44, 1),
    (&UOV::ovIII, 112, 72, 1),
    (&UOV::ovV, 148, 96, 1),
    (&UOV::ovIsCompressedPublicKey, 96, 64, 2),
    (&UOV::ovIpCompressedPublicKey, 68, 44, 1),
    (&UOV::ovIIICompressedPublicKey, 112, 72, 1),
    (&UOV::ovVCompressedPublicKey, 148, 96, 1),
    (&UOV::ovIsCompressedKeys, 96, 64, 2),
    (&UOV::ovIpCompressedKeys, 68, 44, 1),
    (&UOV::ovIIICompressedKeys, 112, 72, 1),
    (&UOV::ovVCompressedKeys, 148, 96, 1),
];

/// Signs a message with a secret key on both sides, each with the NIST generator of the same
/// entropy, and fails the test unless both give the same signature or the same error.
fn checkUOVSignature(
    scheme: &UOV,
    secretKey: &[u8],
    message: &[u8],
    entropy: [u8; 48],
    label: &str,
) {
    let name = scheme.description().name;
    let cSignature = COracle::new(OracleRandomness::nist(entropy)).sign(name, message, secretKey);
    let rustSignature = scheme.sign(message, secretKey, &mut NISTKATRandom::new(&entropy, None));
    match (cSignature, rustSignature) {
        (Ok(cSignature), Ok(rustSignature)) => {
            if let Some(detail) = ParityMismatch::difference(&cSignature, &rustSignature) {
                panic!("{label}: {detail}");
            }
        }
        (Err(cError), Err(rustError)) => assert_eq!(cError, rustError, "{label}"),
        (cSignature, rustSignature) => panic!(
            "{label}: C gives {:?} and Rust gives {:?}",
            cSignature.map(|_| ()),
            rustSignature.map(|_| ())
        ),
    }
}

#[test]
fn uovSignsSecretKeysOfAnyBytesLikeTheCLibrary() {
    LargeStack::run(|| {
        for (scheme, ..) in uovSets {
            let description = scheme.description();
            for case in 0..3u64 {
                let label = format!("{}, case {case} of seed {keySeed:#x}", description.name);
                let mut generator = VariationGenerator::forCase(keySeed, description.name, case);
                // Random bytes for the seed, O, P1 and S of a classic secret key, or for the seed
                // of a compressed secret key.
                let secretKey = generator.bytes(description.secretKeyLength);
                let messageLength = generator.messageLength();
                let message = generator.bytes(messageLength);
                checkUOVSignature(scheme, &secretKey, &message, generator.entropy(), &label);
            }
        }
    });
}

#[test]
fn uovRefusesASecretKeyWhoseLinearBlockIsZeroLikeTheCLibrary() {
    // With S zero, each of the 256 attempts meets a singular system, and both sides fail. The
    // loop is the same for each shape, so the test runs the two shapes of the smallest systems.
    LargeStack::run(|| {
        for (scheme, vinegarCount, oilCount, elementsPerByte) in
            [uovSets[0], uovSets[1], uovSets[4], uovSets[5]]
        {
            let description = scheme.description();
            let label = format!("{}, seed {keySeed:#x}", description.name);
            let mut generator = VariationGenerator::forCase(keySeed, description.name, 9);
            let mut secretKey = generator.bytes(description.secretKeyLength);
            let linearBlockLength = oilCount / elementsPerByte * vinegarCount * oilCount;
            let linearStart = secretKey.len() - linearBlockLength;
            secretKey[linearStart..].fill(0);
            let entropy = generator.entropy();
            let cSignature = COracle::new(OracleRandomness::nist(entropy)).sign(
                description.name,
                b"message",
                &secretKey,
            );
            assert_eq!(cSignature, Err(OQSError::operationFailed), "{label}");
            checkUOVSignature(scheme, &secretKey, b"message", entropy, &label);
        }
    });
}

#[test]
fn uovVerifiesPublicKeysMadeByHandLikeTheCLibrary() {
    // Every entry of the map of the key is zero, except the entry of the first oil variable
    // squared, which is the target of the signature, SHAKE256 of the message and the salt. The
    // point of the signature has that variable at one and every other variable at zero, so
    // both sides accept it. The same bit changed in two bytes of the entry, or in one byte,
    // makes both refuse it.
    LargeStack::run(|| {
        for (index, (scheme, vinegarCount, oilCount, elementsPerByte)) in
            uovSets.into_iter().enumerate()
        {
            let description = scheme.description();
            let name = description.name;
            let entryLength = oilCount / elementsPerByte;
            let mut generator = VariationGenerator::forCase(keySeed, name, 10);
            let message = generator.bytes(33);
            let salt = generator.bytes(16);
            let mut target = vec![0u8; entryLength];
            let mut hash = SHAKE256::new();
            hash.absorb(&message);
            hash.absorb(&salt);
            hash.finalize().squeeze(&mut target);
            let mut publicKey = vec![0u8; description.publicKeyLength];
            let oilBlockStart = if index < 4 {
                publicKey.len() - entryLength * oilCount * (oilCount + 1) / 2
            } else {
                // A compressed key: any public seed, because the vinegar values are zero.
                publicKey[..16].copy_from_slice(&generator.bytes(16));
                16
            };
            publicKey[oilBlockStart..oilBlockStart + entryLength].copy_from_slice(&target);
            let mut signature = vec![0u8; description.signatureLength - 16];
            signature[vinegarCount / elementsPerByte] = 0x01;
            signature.extend_from_slice(&salt);
            let mut twoBytes = publicKey.clone();
            twoBytes[oilBlockStart] ^= 0x04;
            twoBytes[oilBlockStart + entryLength - 1] ^= 0x04;
            let mut oneByte = publicKey.clone();
            oneByte[oilBlockStart + 1] ^= 0x80;
            for (key, expected) in [(&publicKey, true), (&twoBytes, false), (&oneByte, false)] {
                let cVerdict = COracle::new(OracleRandomness::nist([0; 48]))
                    .isValidSignature(name, &signature, &message, key);
                let rustVerdict = scheme.isValidSignature(&signature, &message, key);
                assert_eq!((cVerdict, rustVerdict), (expected, expected), "{name}");
            }
        }
    });
}

/// The seed of the malformed expanded keys of SNOVA. A failure message names it.
const expandedKeySeed: u64 = 0x534E_4F56_414B_4559;

#[test]
fn snovaSignsMalformedExpandedSecretKeysLikeTheCLibrary() {
    LargeStack::run(|| {
        for scheme in [
            &SNOVA::snova24x5x4WithExpandedSecretKey,
            &SNOVA::snova24x5x4SHAKEWithExpandedSecretKey,
        ] {
            let name = scheme.description().name;
            let mut failureCount = 0;
            for case in 0..6u64 {
                let label = format!("{name}, case {case} of seed {expandedKeySeed:#x}");
                let mut generator = VariationGenerator::forCase(expandedKeySeed, name, case);
                let keyPair = scheme
                    .generateKeyPair(&mut NISTKATRandom::new(&generator.entropy(), None))
                    .expect("a key pair");
                let mut secretKey = keyPair.secretKey.bytes().to_vec();
                // The packed matrices come before the 48 bytes of the seeds.
                let matricesEnd = secretKey.len() - 48;
                match case % 3 {
                    // Every byte random, the seeds too.
                    0 => {
                        let replacement = generator.bytes(secretKey.len());
                        secretKey.copy_from_slice(&replacement);
                    }
                    // Random matrices with the seeds of the key.
                    1 => {
                        let replacement = generator.bytes(matricesEnd);
                        secretKey[..matricesEnd].copy_from_slice(&replacement);
                    }
                    // Zero matrices, whose systems are all zero, so every attempt fails.
                    _ => secretKey[..matricesEnd].fill(0),
                }
                let messageLength = generator.messageLength();
                let message = generator.bytes(messageLength);
                let signingEntropy = generator.entropy();
                let cSignature = COracle::new(OracleRandomness::nist(signingEntropy))
                    .sign(name, &message, &secretKey);
                let rustSignature = scheme.sign(
                    &message,
                    &secretKey,
                    &mut NISTKATRandom::new(&signingEntropy, None),
                );
                let signature = match (cSignature, rustSignature) {
                    (Ok(signature), Ok(rustSignature)) => {
                        if let Some(detail) = ParityMismatch::difference(&signature, &rustSignature)
                        {
                            panic!("{label}: {detail}");
                        }
                        signature
                    }
                    (Err(_), Err(_)) => {
                        failureCount += 1;
                        continue;
                    }
                    (cResult, rustResult) => panic!(
                        "{label}: C gives {:?} and Rust gives {:?}",
                        cResult.map(|_| ()),
                        rustResult.map(|_| ())
                    ),
                };
                let cVerdict = COracle::new(OracleRandomness::nist([0; 48])).isValidSignature(
                    name,
                    &signature,
                    &message,
                    &keyPair.publicKey,
                );
                let rustVerdict = scheme.isValidSignature(&signature, &message, &keyPair.publicKey);
                assert_eq!(rustVerdict, cVerdict, "{label}");
            }
            // The zero matrices fail on both sides.
            assert_eq!(failureCount, 2, "{name}");
        }
    });
}
