//! The fuzz test of liboqs `tests/fuzz_test_sig_stfl_lms.c` through `StatefulSignatureFuzzTest`,
//! with seeded cases, and hostile secret keys of LMS: a hostile input gives a defined result or
//! a defined error, and never a panic.
//!
//! The C program verifies the values of the response files of `LMS_SHA256_H5_W2` and
//! `LMS_SHA256_H5_W8_H5_W8` with the bytes of a fuzz input written over them. The shared program
//! runs those cases on each set with a response file, and adds hostile signatures, public keys
//! and secret keys. A hostile secret key of random bytes almost never holds a valid parameter
//! set, so the test of this file also writes the parameter set of a set into random keys.

use OQSNativeAlgorithmTests::{
    FuzzRandom, StatefulKnownAnswerDigests, StatefulSignatureFuzzTest, TestVectorFiles,
};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{OQSError, SecretBytes};
use OQSNativeLMS::LMS;

/// The seed of every fuzz case. A failure message names it with the case.
const fuzzSeed: u64 = 0x4C4D_535F_4655_5A5A;

/// The cases of each set.
const caseCount: u64 = 24;

/// A store that keeps the last saved key.
#[derive(Default)]
struct KeepingStore {
    saved: Option<Vec<u8>>,
}

impl KeyStatePersisting for KeepingStore {
    fn persist(&mut self, secretKey: &[u8]) -> Result<(), OQSError> {
        self.saved = Some(secretKey.to_vec());
        Ok(())
    }
}

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestSigStflLMSPassesForEverySetWithAResponseFile() {
    // The C program fuzzes `LMS_SHA256_H5_W2` and `LMS_SHA256_H5_W8_H5_W8`. The 15 sets of
    // height 25 and of two levels other than the two of RFC 8554 have no response file.
    let mut count = 0;
    for scheme in LMS::schemes {
        let name = scheme.description().name;
        if StatefulKnownAnswerDigests::digest(name).is_none() {
            continue;
        }
        let file = TestVectorFiles::responseFile(name).unwrap_or_else(|text| panic!("{text}"));
        assert_eq!(
            StatefulSignatureFuzzTest::run(*scheme, &file, fuzzSeed, caseCount),
            Ok(()),
            "{name}, seed {fuzzSeed:#x}"
        );
        count += 1;
    }
    assert_eq!(count, 18);
}

#[test]
fn hostileSecretKeysGiveASignatureOrADefinedErrorAndNeverAPanic() {
    // Random keys, and random keys with the parameter set of the scheme, so that the count and
    // the seed are random. Each gives a signature with its saved key, or a defined error that
    // leaves the key as it was.
    for scheme in [LMS::lmsSHA256H5W8, LMS::lmsSHA256H5W8H5W8] {
        let mut signatureCount = 0;
        let name = scheme.description().name;
        let parameterSet: [u8; 8] = if name == "LMS_SHA256_H5_W8" {
            [0x54, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        } else {
            [0x54, 0x54, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        };
        for case in 0..caseCount {
            let label = format!("{name}, case {case} of seed {fuzzSeed:#x}");
            let mut random = FuzzRandom::forCase(fuzzSeed, case);
            let mut bytes = randomBytes(&mut random, 64 + (case as usize % 3));
            if case % 2 == 0 {
                bytes[8..16].copy_from_slice(&parameterSet);
                // A count inside the key in half of these cases, so that they sign.
                if case % 4 == 0 {
                    bytes[..8].copy_from_slice(&(case % 31).to_be_bytes());
                }
            }
            let message = randomBytes(&mut random, case as usize * 5);
            let mut hostile = SecretBytes::new(bytes.clone());
            let mut store = KeepingStore::default();
            match scheme.sign(&message, &mut hostile, &mut store) {
                Ok(signature) => {
                    signatureCount += 1;
                    assert_eq!(
                        signature.len(),
                        scheme.description().signatureLength,
                        "{label}"
                    );
                    assert_eq!(store.saved.as_deref(), Some(hostile.bytes()), "{label}");
                }
                Err(error) => {
                    assert!(
                        matches!(error, OQSError::operationFailed | OQSError::keyExhausted),
                        "{label}: {error:?}"
                    );
                    assert_eq!(hostile.bytes(), bytes.as_slice(), "{label}");
                    assert!(store.saved.is_none(), "{label}");
                }
            }
            // The counts read only the private key.
            let remaining = scheme.remainingSignatureCount(&bytes);
            let total = scheme.totalSignatureCount(&bytes);
            assert_eq!(remaining.is_ok(), total.is_ok(), "{label}");
        }
        // The cases with a count inside the key sign, and every other case is refused.
        assert_eq!(signatureCount, caseCount / 4, "{name}, seed {fuzzSeed:#x}");
    }
}
