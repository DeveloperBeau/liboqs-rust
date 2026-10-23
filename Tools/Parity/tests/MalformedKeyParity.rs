//! Parity with the C library for secret keys that no key generation gives.
//!
//! mldsa-native decodes the vectors s1, s2 and t0 of a secret key with no range check, so it
//! signs with any bytes of the right length. The parity variations sign only with generated
//! keys, so this test signs malformed keys on both sides and compares the signatures and the
//! verdicts on them.

use OQSNative::{MLDSA, Signing};
use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeParity::{LargeStack, ParityMismatch, VariationGenerator};

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
