//! The fuzz test of liboqs `tests/fuzz_test_sig_stfl_xmss.c`, with seeded cases, and hostile
//! secret keys: a hostile input gives a defined result or a defined error, and never a panic.
//!
//! The C program verifies mutations of the public key, the message and the signature of count 0
//! of the response files of XMSS-SHA2_10_256 and XMSSMT-SHA2_20/2_256. Each case here makes such
//! a mutation from a seeded source.

use OQSNativeAlgorithmTests::{FuzzRandom, ResponseFile, TestVectorFiles};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{OQSError, SecretBytes};
use OQSNativeXMSS::{XMSS, XMSSMT};

/// The seed of every fuzz case. A failure message names it with the case.
const fuzzSeed: u64 = 0x584D_5353_4655_5A5A;

/// The cases of each target.
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

/// The public key, the secret key, the message and the signature of count 0 of the response
/// file of a set.
fn responseVectors(scheme: &dyn StatefulSigning) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let description = scheme.description();
    let text =
        TestVectorFiles::responseFile(description.name).unwrap_or_else(|error| panic!("{error}"));
    let file = ResponseFile::new(&text);
    let (publicKey, position) = file
        .value("pk = ", 0, description.publicKeyLength)
        .expect("pk");
    let (secretKey, position) = file
        .value("sk = ", position, description.secretKeyLength)
        .expect("sk");
    let (message, position) = file.value("msg = ", position, 33).expect("msg");
    let (signature, _) = file
        .value("sm = ", position, description.signatureLength)
        .expect("sm");
    (publicKey, secretKey, message, signature)
}

#[test]
fn fuzzTestSigStflXMSSRefusesEveryMutationOfTheKnownAnswerVectors() {
    let schemes: [&dyn StatefulSigning; 2] =
        [&XMSS::sha2Height10Bits256, &XMSSMT::sha2Height20Layers2];
    for scheme in schemes {
        let name = scheme.description().name;
        let (publicKey, _, message, signature) = responseVectors(scheme);
        assert!(
            scheme.isValidSignature(&signature, &message, &publicKey),
            "{name}"
        );
        for case in 0..caseCount {
            let mut random = FuzzRandom::forCase(fuzzSeed, case);
            let (mut key, mut signed, mut text) =
                (publicKey.clone(), signature.clone(), message.clone());
            match case % 4 {
                // `fuzz_sig_stfl_xmss`: the fuzz bytes overwrite the start of the public key,
                // then of the signature, then of the message.
                0 => {
                    let total = key.len() + signed.len() + text.len();
                    let length = 1 + (random.nextWord() % total as u64) as usize;
                    let mut bytes = randomBytes(&mut random, length).into_iter();
                    for target in [&mut key, &mut signed, &mut text] {
                        for (byte, fuzz) in target.iter_mut().zip(bytes.by_ref()) {
                            *byte = fuzz;
                        }
                    }
                }
                // The identifier stays, and random bytes overwrite a part of the signature.
                1 => {
                    let start = (random.nextWord() % signed.len() as u64) as usize;
                    let length = 1 + (random.nextWord() % 64) as usize;
                    let end = (start + length).min(signed.len());
                    let bytes = randomBytes(&mut random, end - start);
                    signed[start..end].copy_from_slice(&bytes);
                }
                // A random signature of the right length.
                2 => signed = randomBytes(&mut random, signed.len()),
                // Random bytes over the root and the public seed of the public key.
                _ => {
                    let bytes = randomBytes(&mut random, key.len() - 4);
                    key[4..].copy_from_slice(&bytes);
                }
            }
            let isUnchanged = key == publicKey && signed == signature && text == message;
            assert_eq!(
                scheme.isValidSignature(&signed, &text, &key),
                isUnchanged,
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
        }
    }
}

#[test]
fn hostileSecretKeysGiveASignatureOrADefinedErrorAndNeverAPanic() {
    let schemes: [&dyn StatefulSigning; 2] =
        [&XMSS::sha2Height10Bits256, &XMSSMT::sha2Height20Layers2];
    for scheme in schemes {
        let name = scheme.description().name;
        let description = scheme.description();
        let (_, secretKey, _, _) = responseVectors(scheme);
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
