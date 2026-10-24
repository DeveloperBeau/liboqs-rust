//! The fuzz test of liboqs `tests/fuzz_test_sig_stfl_xmss.c` through `StatefulSignatureFuzzTest`,
//! with seeded cases, and hostile secret keys of XMSS and XMSS^MT: a hostile input gives a
//! defined result or a defined error, and never a panic.
//!
//! The C program verifies the values of the response files of XMSS-SHA2_10_256 and
//! XMSSMT-SHA2_20/2_256 with the bytes of a fuzz input written over them. The shared program
//! runs those cases on each set, and adds hostile signatures, public keys and secret keys. A
//! hostile secret key of random bytes almost never holds the identifier of a set, so the test of
//! this file keeps the identifier of the set and forges the index and the BDS states after it.

use OQSNativeAlgorithmTests::{
    FuzzRandom, ResponseFile, StatefulSignatureFuzzTest, TestVectorFiles,
};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{OQSError, SecretBytes};
use OQSNativeXMSS::{XMSS, XMSSMT};

/// The seed of every fuzz case. A failure message names it with the case.
const fuzzSeed: u64 = 0x584D_5353_4655_5A5A;

/// The cases of each target.
const caseCount: u64 = 24;

/// The two schemes of `fuzz_test_sig_stfl_xmss.c`, which the first byte of its input picks.
const fuzzTargets: [&dyn StatefulSigning; 2] =
    [&XMSS::sha2Height10Bits256, &XMSSMT::sha2Height20Layers2];

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

/// The response file of a scheme in the liboqs source of the oracle.
fn responseFile(scheme: &dyn StatefulSigning) -> String {
    TestVectorFiles::responseFile(scheme.description().name)
        .unwrap_or_else(|message| panic!("{message}"))
}

/// The secret key of the response file of a scheme.
fn responseSecretKey(scheme: &dyn StatefulSigning) -> Vec<u8> {
    let description = scheme.description();
    let text = responseFile(scheme);
    let file = ResponseFile::new(&text);
    let (_, position) = file
        .value("pk = ", 0, description.publicKeyLength)
        .expect("pk");
    let (secretKey, _) = file
        .value("sk = ", position, description.secretKeyLength)
        .expect("sk");
    secretKey
}

#[test]
fn fuzzTestSigStflXMSSPassesForEverySet() {
    // The C program fuzzes the two sets of `fuzzTargets`, and the cases of every set take
    // seconds.
    for scheme in XMSS::schemes.iter().chain(XMSSMT::schemes) {
        assert_eq!(
            StatefulSignatureFuzzTest::run(*scheme, &responseFile(*scheme), fuzzSeed, caseCount),
            Ok(()),
            "{}, seed {fuzzSeed:#x}",
            scheme.description().name
        );
    }
}

#[test]
fn hostileSecretKeysGiveASignatureOrADefinedErrorAndNeverAPanic() {
    for scheme in fuzzTargets {
        let name = scheme.description().name;
        let description = scheme.description();
        let secretKey = responseSecretKey(scheme);
        let identifier = &secretKey[..4];
        for case in 0..caseCount {
            let mut random = FuzzRandom::forCase(fuzzSeed, case);
            let mut bytes = match case % 3 {
                // Random bytes: the identifier is almost never a set of the variant.
                0 => randomBytes(&mut random, description.secretKeyLength),
                // The identifier of the set and random bytes after it.
                1 => {
                    let mut bytes = randomBytes(&mut random, description.secretKeyLength);
                    bytes[..4].copy_from_slice(identifier);
                    bytes
                }
                // The key of the response file with a few random bytes in its BDS states.
                _ => {
                    let mut bytes = secretKey.clone();
                    for _ in 0..4 {
                        let position = 4 + (random.nextWord() % (bytes.len() as u64 - 4)) as usize;
                        bytes[position] = random.nextWord() as u8;
                    }
                    bytes
                }
            };
            if case % 3 != 0 {
                // A small index keeps the key away from its end in most cases.
                bytes[4..7].fill(0);
            }
            let message = randomBytes(&mut random, (case * 5) as usize);
            let mut hostile = SecretBytes::new(bytes.clone());
            let mut store = KeepingStore::default();
            match scheme.sign(&message, &mut hostile, &mut store) {
                Ok(signature) => {
                    assert!(
                        signature.len() <= description.signatureLength,
                        "{name}, case {case} of seed {fuzzSeed:#x}"
                    );
                    assert_eq!(store.saved.as_deref(), Some(hostile.bytes()));
                }
                Err(OQSError::keyExhausted) => {
                    assert!(hostile.bytes()[4..].iter().all(|byte| *byte == 0));
                    assert_eq!(hostile.bytes()[..4], bytes[..4]);
                }
                Err(error) => {
                    assert_eq!(
                        error,
                        OQSError::operationFailed,
                        "{name}, case {case} of seed {fuzzSeed:#x}"
                    );
                    assert_eq!(hostile.bytes(), bytes.as_slice(), "{name}, case {case}");
                    assert!(store.saved.is_none());
                }
            }
            // The counts read only the identifier and the index.
            let remaining = scheme.remainingSignatureCount(&bytes);
            let total = scheme.totalSignatureCount(&bytes);
            assert_eq!(remaining.is_ok(), total.is_ok(), "{name}, case {case}");
            if let Err(error) = total {
                assert_eq!(error, OQSError::operationFailed);
            }
        }
    }
}
