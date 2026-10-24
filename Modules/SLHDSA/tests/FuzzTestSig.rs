//! The fuzz test of liboqs `tests/fuzz_test_sig.c` through `SignatureFuzzTest`, with seeded
//! cases, and the hostile inputs of SLH-DSA: random secret keys, signatures, public keys and
//! contexts give a defined result or a defined error.

use OQSNativeAlgorithmTests::{FuzzRandom, SignatureFuzzTest, SuiteSample};
use OQSNativeDomain::{RandomGenerating, Signing};
use OQSNativeEntities::OQSError;
use OQSNativeSLHDSA::{PreHash, SLHDSA};

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x534C_485F_4655_5A5A;

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestSigPassesForEachSchemeOfTheSuiteSample() {
    let mut count = 0;
    for scheme in SLHDSA::schemes {
        if SuiteSample::contains(scheme.description().name) {
            assert_eq!(SignatureFuzzTest::run(*scheme, fuzzSeed, 4), Ok(()));
            count += 1;
        }
    }
    assert_eq!(count, 18);
}

#[test]
#[ignore = "the 156 schemes sign for many minutes in a debug build, and parity run checks them in release builds"]
fn fuzzTestSigPassesForEveryScheme() {
    for scheme in SLHDSA::schemes {
        assert_eq!(SignatureFuzzTest::run(*scheme, fuzzSeed, 4), Ok(()));
    }
}

#[test]
fn randomSecretKeysSignAndRandomInputsAreRejectedWithoutAPanic() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for scheme in [
        SLHDSA::sha2128f,
        SLHDSA::shake128f,
        SLHDSA::sha2192f.preHashed(PreHash::sha3224),
    ] {
        let description = scheme.description();
        let keyPair = scheme.generateKeyPair(&mut random).expect("key pair");
        for case in 0..6 {
            let label = format!("{}, case {case} of seed {fuzzSeed:#x}", description.name);
            // Any secret key of the right length signs, as in the C code, which checks nothing.
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let message = randomBytes(&mut random, 1 + case * 97);
            let signature = scheme
                .sign(&message, &secretKey, &mut random)
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(signature.len(), description.signatureLength, "{label}");
            assert!(
                !scheme.isValidSignature(&signature, &message, &keyPair.publicKey),
                "{label}"
            );
            // A random signature and a random public key of the right length are rejected.
            let hostileSignature = randomBytes(&mut random, description.signatureLength);
            assert!(
                !scheme.isValidSignature(&hostileSignature, &message, &keyPair.publicKey),
                "{label}"
            );
            let hostileKey = randomBytes(&mut random, description.publicKeyLength);
            assert!(
                !scheme.isValidSignatureWithContext(&signature, &message, b"", &hostileKey),
                "{label}"
            );
            // A context of each length signs up to 255 bytes and is refused above.
            let contextLength = 200 + case * 20;
            let context = randomBytes(&mut random, contextLength);
            let result =
                scheme.signWithContext(&message, &context, keyPair.secretKey.bytes(), &mut random);
            if contextLength <= 255 {
                let signature = result.unwrap_or_else(|error| panic!("{label}: {error}"));
                assert!(
                    scheme.isValidSignatureWithContext(
                        &signature,
                        &message,
                        &context,
                        &keyPair.publicKey
                    ),
                    "{label}"
                );
            } else {
                assert_eq!(result, Err(OQSError::contextTooLong), "{label}");
            }
        }
    }
}
