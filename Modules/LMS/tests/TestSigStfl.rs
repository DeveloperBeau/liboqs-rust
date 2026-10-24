//! The correctness test of liboqs `tests/test_sig_stfl.c` through
//! `StatefulSignatureCorrectnessTest`, and the tests of the LMS family: the key pairs and the
//! signatures of the C library, the random request, the secret key after each signature, the
//! counts, the end of a key, a failed save, each rejection path, both sides of each verdict of
//! a verification, and the working key.
//!
//! The known answers come from the C library of the oracle with the NIST known-answer
//! generator seeded with the bytes 0 to 47, and the message `the quick brown fox`. A C program
//! printed the `OutputDigest` of each signature and of each key. It is not part of the
//! repository.

use OQSNativeAlgorithmTests::{
    FuzzRandom, OutputDigest, ResponseFile, StatefulSignatureCorrectnessTest, StatefulTreeHeight,
    TestVectorFiles,
};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{OQSError, SecretBytes};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeLMS::LMS;

/// The message of the known answers.
const baseMessage: &[u8] = b"the quick brown fox";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// The correctness program.

/// The seed of the random source of the correctness program. A failure message names it.
const correctnessSeed: u64 = 0x4C4D_535F_5445_5354;

/// Runs the correctness program of `tests/test_sig_stfl.c` on each set whose largest tree has
/// at most a height. liboqs runs the program on LMS without a response file, so each run makes
/// its key pairs. Returns the failures.
fn correctnessFailures(largestHeight: u32) -> Vec<String> {
    LMS::schemes
        .iter()
        .filter(|scheme| {
            StatefulTreeHeight::largest(scheme.description().name)
                .is_some_and(|height| height <= largestHeight)
        })
        .filter_map(|scheme| {
            let mut random = FuzzRandom::seeded(correctnessSeed);
            StatefulSignatureCorrectnessTest::run(*scheme, &mut random, None)
                .err()
                .map(|message| format!("{message}, seed {correctnessSeed:#x}"))
        })
        .collect()
}

#[test]
fn testSigStflPassesForEachSetOfTreesOfHeight5() {
    let failures = correctnessFailures(5);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "the correctness program makes three key pairs of each set, and the 9 sets with trees of height 10 take minutes in a test build: run it with --release"]
fn testSigStflPassesForEachSetOfTreesOfHeight10() {
    let failures = correctnessFailures(10);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// The family.

/// The NIST known-answer generator seeded with the bytes 0 to 47.
fn knownAnswerRandom() -> NISTKATRandom {
    NISTKATRandom::new(&core::array::from_fn(|index| index as u8), None)
}

/// A store that keeps each saved key, or refuses every save.
struct RecordingStore {
    saved: Vec<Vec<u8>>,
    isRefusing: bool,
}

impl RecordingStore {
    fn accepting() -> Self {
        RecordingStore {
            saved: Vec::new(),
            isRefusing: false,
        }
    }

    fn refusing() -> Self {
        RecordingStore {
            saved: Vec::new(),
            isRefusing: true,
        }
    }
}

impl KeyStatePersisting for RecordingStore {
    fn persist(&mut self, secretKey: &[u8]) -> Result<(), OQSError> {
        if self.isRefusing {
            return Err(OQSError::operationFailed);
        }
        self.saved.push(secretKey.to_vec());
        Ok(())
    }
}

/// A random source that records the length of each request.
struct RecordingRandom {
    inner: NISTKATRandom,
    requests: Vec<usize>,
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.requests.push(bytes.len());
        self.inner.fillRandomBytes(bytes);
    }
}

/// The key pair and the first signatures of a set in the C library.
struct KnownAnswer {
    scheme: LMS,
    /// The public key in hexadecimal.
    publicKey: &'static str,
    /// The `OutputDigest` of the serialized secret key of 10980 bytes.
    secretKey: &'static str,
    /// The `OutputDigest` of each signature and of the advanced key that the store gets.
    signatures: &'static [(&'static str, &'static str)],
}

/// The secret key of a set from the generator, with a count written into it. The count is the
/// only part of the key that a signature changes, before the last signature.
fn secretKeyAt(scheme: &LMS, count: u64) -> SecretBytes {
    let keyPair = scheme
        .generateKeyPair(&mut knownAnswerRandom())
        .expect("a key pair");
    let mut secretKey = keyPair.secretKey;
    secretKey.mutableBytes()[..8].copy_from_slice(&count.to_be_bytes());
    secretKey
}

fn checkKnownAnswer(answer: &KnownAnswer) {
    let scheme = &answer.scheme;
    let name = scheme.description().name;
    let keyPair = scheme
        .generateKeyPair(&mut knownAnswerRandom())
        .expect("a key pair");
    assert_eq!(hex(&keyPair.publicKey), answer.publicKey, "{name}");
    assert_eq!(keyPair.secretKey.bytes().len(), 10980, "{name}");
    assert_eq!(
        OutputDigest::of(keyPair.secretKey.bytes()),
        answer.secretKey,
        "{name}"
    );
    let mut secretKey = keyPair.secretKey.clone();
    for (count, (signatureDigest, advancedDigest)) in answer.signatures.iter().enumerate() {
        let mut store = RecordingStore::accepting();
        let signature = scheme
            .sign(baseMessage, &mut secretKey, &mut store)
            .expect("a signature");
        assert_eq!(
            signature.len(),
            scheme.description().signatureLength,
            "{name}"
        );
        assert_eq!(
            OutputDigest::of(&signature),
            *signatureDigest,
            "{name}, signature {count}"
        );
        assert_eq!(store.saved.len(), 1, "{name}");
        assert_eq!(
            OutputDigest::of(&store.saved[0]),
            *advancedDigest,
            "{name}, key {count}"
        );
        assert_eq!(&store.saved[0][..], secretKey.bytes(), "{name}");
        // The advanced key differs from the key before only in its count.
        assert_eq!(
            u64::from_be_bytes(secretKey.bytes()[..8].try_into().expect("8 bytes")),
            count as u64 + 1
        );
        assert_eq!(&secretKey.bytes()[8..], &keyPair.secretKey.bytes()[8..]);
        assert!(scheme.isValidSignature(&signature, baseMessage, &keyPair.publicKey));
    }
}

#[test]
fn keyPairsAndSignaturesOfHeight5AreTheOnesOfTheCLibrary() {
    let answers = [
        KnownAnswer {
            scheme: LMS::lmsSHA256H5W1,
            publicKey: "000000010000000500000001056a8c266f9ef97ed08541dbd2e1ffa12b41753f07b387b33f42d1715f0baedf34660eb03c5c432591d83b0f00c43478",
            secretKey: "7295568086ed360117b4e85dcae4bb3aebb9b3e490c3cdb0e5f6cfb868ed8d31",
            signatures: &[
                (
                    "b4af988451f3cc6df7b38c61155dfe5d6ad650cf5c3c71dcb475d84a799ba700",
                    "244b51fbbb5d63318d133f9225cdb95ea09120b15b00627acd07ef6b8bf8930b",
                ),
                (
                    "b4ea542b4834f4417813e972b39be377e77329ac2ed041b6a6db73296afe4a47",
                    "99ba97a8e8f40daa9bf110b31ba97e00da65c94ef9b1a11b1831f3bed36f5ce3",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H5W2,
            publicKey: "000000010000000500000002056a8c266f9ef97ed08541dbd2e1ffa1a57971ed14a3cd1a528e27771c77b8e9c2f443e5dcf3f5045d8f925441528af2",
            secretKey: "177593de80945d89d135286c14470128201f914aab511b5a872853eb7c40cce3",
            signatures: &[
                (
                    "91cec5b4ad7bda2005ac3b53706df76fc180b8754d62c51e8265c40e95f4213f",
                    "33c82de3c153633b3a9980bf84177d0cc140b4d3f7e65cac9b5478766f633331",
                ),
                (
                    "d059c70e920febb854e05a3b4bda821eca24e598644ae3f54eaa0110f00d30ab",
                    "81b53f95cd321fd00d4b329dc1fd7fc69cea15bb4e78f2742764de0ea7805582",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H5W4,
            publicKey: "000000010000000500000003056a8c266f9ef97ed08541dbd2e1ffa1fb39e1e60e6dbe7f123d0354687bdf68fceb9977c21a37484e0896ec33198d94",
            secretKey: "e73d733631634968c22155fdab027d3fef4dfe17a83b2f2502e938bfc5bffc8a",
            signatures: &[
                (
                    "a03a69b05a949049bf7215ee67d711ce8b10566c337be69fb8ba3126c93905fc",
                    "6c620eda15b0080ef807537bfeae34aa346f155b905826c268e23e3021f0c6ed",
                ),
                (
                    "1f31256f2e8a5afa28feefddf6dc1a52cacee8a67eaca194cb0f851ecfb2c5ac",
                    "0f1bf968f612f2e4d0c125d1eeb9a1e9ad5d83f7bec0131c1eeea0e1e98d4c3d",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H5W8,
            publicKey: "000000010000000500000004056a8c266f9ef97ed08541dbd2e1ffa1bbbc42e0a4141c407bd56a6d260ef91a7cc6d5f8e8bec690ec69cddd1eeeb3c7",
            secretKey: "3534d1cc029a9818b508ad14f57c19a26ff24a10efce4f7c119963f8786e1c84",
            signatures: &[
                (
                    "ec93edda47cc36596b022f7fb3fa29f59ed81ba8e5240231b86b007a6ebeab3b",
                    "32d8880e2f0d58b5cf47d6978daf28aa757c9e10e902aeaddfbace559ee281ab",
                ),
                (
                    "8695208b9779105aa3db3fdf8142beedd669802848c9939b0fab5ad92f143a5a",
                    "cbb5425b7cd5f338ee0ba712a727cb237f7ff6cbad9b56e6f219945299952fe4",
                ),
            ],
        },
    ];
    for answer in &answers {
        checkKnownAnswer(answer);
    }
}

#[test]
fn keyPairsAndSignaturesOfHeight10AreTheOnesOfTheCLibrary() {
    let answers = [
        KnownAnswer {
            scheme: LMS::lmsSHA256H10W1,
            publicKey: "000000010000000600000001056a8c266f9ef97ed08541dbd2e1ffa1fba68785667375d67e3c47562a7f47ccfad55e9771049909b39841e4929a3b93",
            secretKey: "2d6002abc214406a35d3c0bd2ae9015a6f120b36910c174ab7c3df91ee0f99af",
            signatures: &[
                (
                    "d4d3328dfbb17815fae06001d9777c02b3981e046cec183d2112a086798c53c3",
                    "885fba5d7a8737738a2a6295a6b15be60ea6119ce32d662dad97b8cdc05232ab",
                ),
                (
                    "79e678c8d7fada1d7a5d40c1e54093149f1049fd4a27ae3fce806aa20a5e1081",
                    "9744c0f3acb0d025daa1bf30995a0a4c954b0934573c9a9f2872d8b59777ca81",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H10W2,
            publicKey: "000000010000000600000002056a8c266f9ef97ed08541dbd2e1ffa10394836808954294a3bda6609804bf30309cd0f0d4ac8a6a62bd311efeaa01bd",
            secretKey: "56614553c3a9e2ed713f634d4bbc5df5da7337254818c0a76f0830530d4373d3",
            signatures: &[
                (
                    "4384552e6692ed066eb1abb2aa7b8fbb9d25c5128cf273628736c3c8d20621f4",
                    "6b435f2540d8148a32f24944a78529eb86936ff585b391c9f86b7a2a6b2c474b",
                ),
                (
                    "b9b4c308d6eee3a0acb3dfdfd5e275f05bd6a727b53cd74877ba10ce9cabe084",
                    "9613fa58af3048d693195be9e2de4a1211418ecf2db033a73d06b324d3003d6c",
                ),
            ],
        },
    ];
    for answer in &answers {
        checkKnownAnswer(answer);
    }
}

#[test]
fn keyPairsAndSignaturesOfTwoLevelsAreTheOnesOfTheCLibrary() {
    let answers = [
        KnownAnswer {
            scheme: LMS::lmsSHA256H5W8H5W8,
            publicKey: "000000020000000500000004056a8c266f9ef97ed08541dbd2e1ffa1bbbc42e0a4141c407bd56a6d260ef91a7cc6d5f8e8bec690ec69cddd1eeeb3c7",
            secretKey: "b0527df54039d14dcd71a81a919e887c26fe88b083394cd3bc67e25dc9f92a71",
            signatures: &[
                (
                    "8cc1fde774217d80687bfb418f5c6d1990142c05fe4d4cbbb21dfccb9f1c29af",
                    "8e4720ba2328ecd407acb1e15e2372923dfcc0ce86c4e44c527bf6e3df815337",
                ),
                (
                    "ac148d8b4e31d7200904186c05be6bbe677b1ffc7247e202402dd8671730fced",
                    "f7b981b8ff18ca3d024d1e530b53655a606d260c63cc9d2a38eb5437f68bff3d",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H10W4H5W8,
            publicKey: "000000020000000600000003056a8c266f9ef97ed08541dbd2e1ffa10031465dceed7143d127e7e205d1120feccb819e4246ab2452fab4a35b87a46f",
            secretKey: "85b75b8d19e96ad772f348726fd29ee84bc3ff6266a719c44380e35d75e7c920",
            signatures: &[(
                "8f5d10e481e6309f8f231ee71ae220aafcd5b96ddce2702e59ed85177c2d986a",
                "b4b24dc7eb50dcd99ee6d0d8897beae1d491db3845e2673b642622ce7d46de09",
            )],
        },
    ];
    for answer in &answers {
        checkKnownAnswer(answer);
    }
}

#[test]
fn theSecretKeyIsThePrivateKeyOfHashSigsAndItsAuxData() {
    let keyPair = LMS::lmsSHA256H5W8H5W8
        .generateKeyPair(&mut knownAnswerRandom())
        .expect("a key pair");
    let secretKey = keyPair.secretKey.bytes();
    // The count 0, the parameter set, then the 48 random bytes as the seed and I.
    let mut randomBytes = [0u8; 48];
    knownAnswerRandom().fillRandomBytes(&mut randomBytes);
    assert_eq!(&secretKey[..8], &[0; 8]);
    assert_eq!(
        &secretKey[8..16],
        &[0x54, 0x54, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    assert_eq!(&secretKey[16..64], &randomBytes);
    // The public key holds the level count, the typecodes of the top tree and its I.
    assert_eq!(
        &keyPair.publicKey[..12],
        &[0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 4]
    );
    assert_eq!(&keyPair.publicKey[12..28], &randomBytes[32..]);
    // The aux data of a top tree of height 5 saves depths 1 and 3: the marker, 2 and 8
    // nodes, the HMAC, and zeros after them.
    let auxiliaryData = &secretKey[64..];
    assert_eq!(&auxiliaryData[..4], &[0x80, 0, 0, 0x0A]);
    assert!(
        auxiliaryData[4 + 320..4 + 352]
            .iter()
            .any(|byte| *byte != 0)
    );
    assert!(auxiliaryData[4 + 352..].iter().all(|byte| *byte == 0));
}

#[test]
fn aKeyPairDrawsOneRequestOf48BytesAndASignatureNone() {
    for scheme in [LMS::lmsSHA256H5W1, LMS::lmsSHA256H5W8H5W8] {
        let mut recording = RecordingRandom {
            inner: knownAnswerRandom(),
            requests: Vec::new(),
        };
        let mut keyPair = scheme.generateKeyPair(&mut recording).expect("a key pair");
        assert_eq!(recording.requests, vec![48]);
        scheme
            .sign(
                baseMessage,
                &mut keyPair.secretKey,
                &mut RecordingStore::accepting(),
            )
            .expect("a signature");
        assert_eq!(recording.requests, vec![48]);
    }
}

#[test]
fn theCountsFollowEachSignatureAndTheLastSignatureEndsTheKey() {
    // The C library at the counts 29, 30 and 31 of `LMS_SHA256_H5_W8`, whose highest count is
    // 31: the signature, the remaining and the total count after it, and the `OutputDigest` of
    // the stored key. liboqs counts from the highest sequence number, so a key at the count 31
    // has 0 signatures left by its count and still signs once.
    let scheme = LMS::lmsSHA256H5W8;
    let expected = [
        (
            29,
            "a83ba386813e2437ba28908fff834d435ce1ab014919bef9041d201fd39c72dc",
            Ok(1),
            "605fa8c3c3ab373b69a2f0e09afa3b5bc37376c24a3390a9033de1653c431084",
        ),
        (
            30,
            "4d6e51a808400b5b12c36032a7dee98007d774d15d52008be64e677c1be05de4",
            Ok(0),
            "1a017a63a5f3c61cf81962703c6169f771fd12776c85baab9cc03814dee03aed",
        ),
        (
            31,
            "ae18cf2b288d85799f60e596cede982e3b10298a79de9381bd5b4b117bb5c2f7",
            Err(OQSError::keyExhausted),
            "e9d44b2b5dd15e2d13e0e06ba007b9cd7f5e7d40245a84f713a6e7328bdf036d",
        ),
    ];
    let fresh = secretKeyAt(&scheme, 0);
    assert_eq!(scheme.remainingSignatureCount(fresh.bytes()), Ok(31));
    assert_eq!(scheme.totalSignatureCount(fresh.bytes()), Ok(31));
    let mut secretKey = secretKeyAt(&scheme, 29);
    assert_eq!(scheme.remainingSignatureCount(secretKey.bytes()), Ok(2));
    for (count, signatureDigest, remaining, storedDigest) in expected {
        let mut store = RecordingStore::accepting();
        let signature = scheme
            .sign(baseMessage, &mut secretKey, &mut store)
            .expect("a signature");
        assert_eq!(
            OutputDigest::of(&signature),
            signatureDigest,
            "count {count}"
        );
        assert_eq!(
            OutputDigest::of(&store.saved[0]),
            storedDigest,
            "count {count}"
        );
        assert_eq!(scheme.remainingSignatureCount(secretKey.bytes()), remaining);
        assert_eq!(
            scheme.totalSignatureCount(secretKey.bytes()),
            remaining.map(|_| 31),
            "count {count}"
        );
    }
    // After the last signature hash-sigs fills the private key with 0xFF and keeps the aux
    // data, and the key signs no more.
    assert_eq!(&secretKey.bytes()[..64], &[0xFF; 64]);
    assert_eq!(&secretKey.bytes()[64..], &fresh.bytes()[64..]);
    let usedKey = secretKey.bytes().to_vec();
    let mut store = RecordingStore::accepting();
    assert_eq!(
        scheme.sign(baseMessage, &mut secretKey, &mut store),
        Err(OQSError::keyExhausted)
    );
    assert!(store.saved.is_empty());
    assert_eq!(secretKey.bytes(), &usedKey[..]);
    assert_eq!(
        scheme.workingKey(secretKey.bytes()).map(|_| ()),
        Err(OQSError::keyExhausted)
    );
}

#[test]
fn aFailedSaveReleasesNoSignatureAndTheKeyStillAdvances() {
    let scheme = LMS::lmsSHA256H5W8;
    let mut secretKey = secretKeyAt(&scheme, 0);
    let mut refusing = RecordingStore::refusing();
    assert_eq!(
        scheme.sign(baseMessage, &mut secretKey, &mut refusing),
        Err(OQSError::persistenceFailed)
    );
    // The C library advances the key in memory before the store, so the key never signs
    // twice with one state.
    assert_eq!(scheme.remainingSignatureCount(secretKey.bytes()), Ok(30));
    let signature = scheme
        .sign(
            baseMessage,
            &mut secretKey,
            &mut RecordingStore::accepting(),
        )
        .expect("a signature");
    // The second signature of the C library, with the leaf 1.
    assert_eq!(
        OutputDigest::of(&signature),
        "8695208b9779105aa3db3fdf8142beedd669802848c9939b0fab5ad92f143a5a"
    );
    // The same holds for a working key.
    let mut workingKey = scheme
        .workingKey(secretKeyAt(&scheme, 0).bytes())
        .expect("a working key");
    assert_eq!(
        workingKey.sign(baseMessage, &mut RecordingStore::refusing()),
        Err(OQSError::persistenceFailed)
    );
    assert_eq!(workingKey.secretKey().bytes()[7], 1);
    assert_eq!(
        workingKey.sign(baseMessage, &mut RecordingStore::accepting()),
        Ok(signature)
    );
}

#[test]
fn aSecretKeyShorterThanThePrivateKeyIsALengthError() {
    let scheme = LMS::lmsSHA256H5W8;
    let validKey = secretKeyAt(&scheme, 0);
    for length in [0, 1, 63] {
        let error = Err(OQSError::invalidLength {
            expected: 64,
            actual: length,
        });
        let mut secretKey = SecretBytes::new(validKey.bytes()[..length].to_vec());
        let mut store = RecordingStore::accepting();
        assert_eq!(
            scheme
                .sign(baseMessage, &mut secretKey, &mut store)
                .map(|_| ()),
            error
        );
        assert!(store.saved.is_empty());
        assert_eq!(
            scheme
                .remainingSignatureCount(secretKey.bytes())
                .map(|_| ()),
            error
        );
        assert_eq!(
            scheme.totalSignatureCount(secretKey.bytes()).map(|_| ()),
            error
        );
        assert_eq!(scheme.workingKey(secretKey.bytes()).map(|_| ()), error);
    }
    // The private key alone, without aux data, is a valid secret key, as in the C code.
    let mut privateKeyOnly = SecretBytes::new(validKey.bytes()[..64].to_vec());
    let mut store = RecordingStore::accepting();
    let signature = scheme
        .sign(baseMessage, &mut privateKeyOnly, &mut store)
        .expect("a signature");
    assert_eq!(
        OutputDigest::of(&signature),
        "ec93edda47cc36596b022f7fb3fa29f59ed81ba8e5240231b86b007a6ebeab3b"
    );
    assert_eq!(store.saved[0].len(), 64);
}

#[test]
fn malformedAndUsedPrivateKeysAreRefusedWithTheErrorOfTheirKind() {
    let scheme = LMS::lmsSHA256H5W8;
    let validKey = secretKeyAt(&scheme, 0);
    let changed = |place: usize, byte: u8| {
        let mut bytes = validKey.bytes().to_vec();
        bytes[place] = byte;
        bytes
    };
    let cases = [
        // An unknown tree typecode, an unknown one-time typecode, no level, and a byte after
        // the end of the parameter set: the `OQS_ERROR` of `hss_get_parameter_set`.
        (changed(8, 0xA4), OQSError::operationFailed),
        (changed(8, 0x55), OQSError::operationFailed),
        (changed(8, 0xFF), OQSError::operationFailed),
        (changed(10, 0x54), OQSError::operationFailed),
        // A count above the highest count, 31.
        (changed(7, 32), OQSError::keyExhausted),
        (changed(0, 1), OQSError::keyExhausted),
    ];
    for (bytes, error) in cases {
        let mut secretKey = SecretBytes::new(bytes.clone());
        let mut store = RecordingStore::accepting();
        assert_eq!(
            scheme.sign(baseMessage, &mut secretKey, &mut store),
            Err(error),
            "{:02x?}",
            &bytes[..16]
        );
        assert!(store.saved.is_empty());
        assert_eq!(secretKey.bytes(), &bytes[..]);
        assert_eq!(scheme.remainingSignatureCount(&bytes), Err(error));
        assert_eq!(scheme.totalSignatureCount(&bytes), Err(error));
        assert_eq!(scheme.workingKey(&bytes).map(|_| ()), Err(error));
    }
    // The highest count is still valid, and the next one past it is not.
    let mut lastKey = SecretBytes::new(changed(7, 31));
    assert!(
        scheme
            .sign(baseMessage, &mut lastKey, &mut RecordingStore::accepting())
            .is_ok()
    );
}

#[test]
fn aKeyOfAnotherParameterSetSignsWithItsOwnSetAsTheCLibraryDoes() {
    // hash-sigs reads the parameter set from the key, so the C library signs a fresh key of
    // `LMS_SHA256_H5_W8` under the names `LMS_SHA256_H5_W1` and `LMS_SHA256_H5_W8_H5_W8` with
    // its first signature of `LMS_SHA256_H5_W8`, and counts 30 and 31 after it.
    let key = secretKeyAt(&LMS::lmsSHA256H5W8, 0);
    for scheme in [LMS::lmsSHA256H5W1, LMS::lmsSHA256H5W8H5W8] {
        let mut secretKey = key.clone();
        let signature = scheme
            .sign(
                baseMessage,
                &mut secretKey,
                &mut RecordingStore::accepting(),
            )
            .expect("a signature");
        assert_eq!(signature.len(), 1296);
        assert_eq!(
            OutputDigest::of(&signature),
            "ec93edda47cc36596b022f7fb3fa29f59ed81ba8e5240231b86b007a6ebeab3b"
        );
        assert_eq!(scheme.remainingSignatureCount(secretKey.bytes()), Ok(30));
        assert_eq!(scheme.totalSignatureCount(secretKey.bytes()), Ok(31));
    }
    // A key whose signature is longer than the signature of the scheme would overflow the
    // signature buffer of the C code, so the port refuses it before it signs.
    let mut longKey = secretKeyAt(&LMS::lmsSHA256H5W1, 0);
    let original = longKey.bytes().to_vec();
    assert_eq!(
        LMS::lmsSHA256H5W8.sign(baseMessage, &mut longKey, &mut RecordingStore::accepting()),
        Err(OQSError::operationFailed)
    );
    assert_eq!(longKey.bytes(), &original[..]);
}

/// The public key, the message and the signature of a response file of liboqs.
fn responseFileValues(name: &str, signatureLength: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let text = TestVectorFiles::responseFile(name).unwrap_or_else(|text| panic!("{text}"));
    let file = ResponseFile::new(&text);
    let value = |marker: &str, length: usize| file.value(marker, 0, length).expect(marker).0;
    (
        value("pk = ", file.valueLength("pk = ")),
        value("msg = ", file.valueLength("msg = ")),
        value("sm = ", signatureLength),
    )
}

#[test]
fn theTestCasesOfRFC8554VerifyAndEachChangeIsRefused() {
    for scheme in [LMS::lmsSHA256H5W8H5W8, LMS::lmsSHA256H10W4H5W8] {
        let name = scheme.description().name;
        let (publicKey, testMessage, signature) =
            responseFileValues(name, scheme.description().signatureLength);
        assert_eq!(publicKey.len(), 60);
        assert!(
            scheme.isValidSignature(&signature, &testMessage, &publicKey),
            "{name}"
        );
        // A change in each part: the level count, the first LMS signature, the signed public
        // key, the bottom signature and its authentication path.
        let length = signature.len();
        for place in [
            0,
            3,
            4,
            7,
            8,
            11,
            12,
            43,
            44,
            length / 2,
            length - 33,
            length - 1,
        ] {
            let mut changed = signature.clone();
            changed[place] ^= 1;
            assert!(
                !scheme.isValidSignature(&changed, &testMessage, &publicKey),
                "{name}, byte {place}"
            );
        }
        let mut changedMessage = testMessage.clone();
        changedMessage[0] ^= 1;
        assert!(!scheme.isValidSignature(&signature, &changedMessage, &publicKey));
        for place in [3, 7, 11, 12, 59] {
            let mut changedKey = publicKey.clone();
            changedKey[place] ^= 1;
            assert!(
                !scheme.isValidSignature(&signature, &testMessage, &changedKey),
                "{name}, key byte {place}"
            );
        }
        assert!(!scheme.isValidSignature(&signature[..length - 1], &testMessage, &publicKey));
        let mut longer = signature.clone();
        longer.push(0);
        assert!(!scheme.isValidSignature(&longer, &testMessage, &publicKey));
        let mut longerKey = publicKey.clone();
        longerKey.push(0);
        assert!(!scheme.isValidSignature(&signature, &testMessage, &longerKey));
        assert!(!scheme.isValidSignature(&[], &testMessage, &publicKey));
        assert!(!scheme.isValidSignature(&signature, &testMessage, &[]));
    }
}

#[test]
fn aLeafIndexPastTheEndOfItsTreeIsNotValid() {
    // The leaf index q of the bottom signature of a key of one level is the second word. The
    // C code refuses an index of 2^h or more, and the largest index must not overflow the
    // node number either.
    let scheme = LMS::lmsSHA256H5W8;
    let keyPair = scheme
        .generateKeyPair(&mut knownAnswerRandom())
        .expect("a key pair");
    let mut secretKey = keyPair.secretKey.clone();
    let signature = scheme
        .sign(
            baseMessage,
            &mut secretKey,
            &mut RecordingStore::accepting(),
        )
        .expect("a signature");
    assert!(scheme.isValidSignature(&signature, baseMessage, &keyPair.publicKey));
    for index in [31u32, 32, 33, 1 << 31, u32::MAX - 31, u32::MAX] {
        let mut changed = signature.clone();
        changed[4..8].copy_from_slice(&index.to_be_bytes());
        assert!(
            !scheme.isValidSignature(&changed, baseMessage, &keyPair.publicKey),
            "leaf {index}"
        );
    }
}

#[test]
fn aRawLMSPublicKeyAndItsHSSFormBothVerify() {
    // The response file of `LMS_SHA256_H5_W1` holds the raw LMS public key of 56 bytes, and
    // the reader puts the four zero bytes of the level count in front of its raw signature.
    let scheme = LMS::lmsSHA256H5W1;
    let (rawKey, testMessage, signature) = responseFileValues("LMS_SHA256_H5_W1", 8688);
    assert_eq!(rawKey.len(), 56);
    assert_eq!(&signature[..4], &[0; 4]);
    assert!(scheme.isValidSignature(&signature, &testMessage, &rawKey));
    let mut hssKey = vec![0, 0, 0, 1];
    hssKey.extend_from_slice(&rawKey);
    assert!(scheme.isValidSignature(&signature, &testMessage, &hssKey));
    // A raw key with another first word reads as neither form.
    let mut changedType = rawKey.clone();
    changedType[3] = 6;
    assert!(!scheme.isValidSignature(&signature, &testMessage, &changedType));
    // The HSS form needs the level count of the signature.
    let mut twoLevels = hssKey.clone();
    twoLevels[3] = 2;
    assert!(!scheme.isValidSignature(&signature, &testMessage, &twoLevels));
    // A raw key cut short reads with zeros after it, and its root no longer matches.
    assert!(!scheme.isValidSignature(&signature, &testMessage, &rawKey[..55]));
}

#[test]
fn verificationAcceptsAValidSignatureOfAnyLMSSetAsTheCLibraryDoes() {
    // The C library at the count 32 of the key of `LMS_SHA256_H5_W8_H5_W8` from the generator:
    // the first signature of the second bottom tree. Its verification under the name
    // `LMS_SHA256_H5_W1` accepts it too, because the key and the signature carry their
    // parameter sets.
    let scheme = LMS::lmsSHA256H5W8H5W8;
    let publicKey = scheme
        .generateKeyPair(&mut knownAnswerRandom())
        .expect("a key pair")
        .publicKey;
    let mut secretKey = secretKeyAt(&scheme, 32);
    let countMessage = [0, 0, 0, 32];
    let signature = scheme
        .sign(
            &countMessage,
            &mut secretKey,
            &mut RecordingStore::accepting(),
        )
        .expect("a signature");
    assert_eq!(
        OutputDigest::of(&signature),
        "2a6d7fcc8dbc6c55a8029ec2718825ed9d5e1489d09a2685c5a792dfbac39bd1"
    );
    assert!(scheme.isValidSignature(&signature, &countMessage, &publicKey));
    assert!(LMS::lmsSHA256H5W1.isValidSignature(&signature, &countMessage, &publicKey));
    // Each change that the C library refuses: the level count, q, the one-time typecode and
    // C of the top signature, its chains and tree typecode, the signed public key, the bottom
    // signature and the last byte of its path.
    for place in [
        0, 3, 4, 7, 8, 11, 12, 43, 44, 1131, 1135, 1136, 1291, 1292, 1295, 1296, 1300, 1347, 1348,
        1352, 1355, 1356, 2643,
    ] {
        let mut changed = signature.clone();
        changed[place] ^= 1;
        assert!(
            !scheme.isValidSignature(&changed, &countMessage, &publicKey),
            "byte {place}"
        );
    }
}

#[test]
fn aWorkingKeySignsEachCountAsTheCLibraryDoes() {
    // The C library at the counts 30 to 34 of the key of `LMS_SHA256_H5_W8_H5_W8` from the
    // generator, for the message of the four bytes of the count. The bottom tree ends at the
    // count 31, so the working key loaded at 30 changes to the next bottom tree.
    let scheme = LMS::lmsSHA256H5W8H5W8;
    let expected = [
        "0893f1f2bf38280e09e227b0522ff883241712ea09a737fc0f0f6a8811c4943e",
        "7076b8e032e432511bc302f4801fd9186ae0641fe5363615caa9d0957438de47",
        "2a6d7fcc8dbc6c55a8029ec2718825ed9d5e1489d09a2685c5a792dfbac39bd1",
        "f51552b05ff6fae858c26499c0351ec14559540b47f506a23a28fe47948702cf",
        "b944726d623088176e2bd78d8cf74702dab6e51ed289e51216c8b0aace6331fd",
    ];
    let startKey = secretKeyAt(&scheme, 30);
    let mut workingKey = scheme.workingKey(startKey.bytes()).expect("a working key");
    for (count, signatureDigest) in (30u64..).zip(expected) {
        let mut store = RecordingStore::accepting();
        let signature = workingKey
            .sign(&(count as u32).to_be_bytes(), &mut store)
            .expect("a signature");
        assert_eq!(
            OutputDigest::of(&signature),
            signatureDigest,
            "count {count}"
        );
        let mut advanced = startKey.bytes().to_vec();
        advanced[..8].copy_from_slice(&(count + 1).to_be_bytes());
        assert_eq!(store.saved[0], advanced, "count {count}");
    }
    // A working key from the count 0 gives the first two signatures of the C library.
    let mut workingKey = scheme
        .workingKey(secretKeyAt(&scheme, 0).bytes())
        .expect("a working key");
    let mut store = RecordingStore::accepting();
    let first = workingKey
        .sign(baseMessage, &mut store)
        .expect("a signature");
    let second = workingKey
        .sign(baseMessage, &mut store)
        .expect("a signature");
    assert_eq!(
        OutputDigest::of(&first),
        "8cc1fde774217d80687bfb418f5c6d1990142c05fe4d4cbbb21dfccb9f1c29af"
    );
    assert_eq!(
        OutputDigest::of(&second),
        "ac148d8b4e31d7200904186c05be6bbe677b1ffc7247e202402dd8671730fced"
    );
}

#[test]
fn aWorkingKeySignsEveryCountOfAKeyAndThenNoMore() {
    // Every signature of a key of one tree from one working key equals the signature of a
    // fresh load at its count, and the key ends with the 32nd signature.
    let scheme = LMS::lmsSHA256H5W1;
    let keyPair = scheme
        .generateKeyPair(&mut knownAnswerRandom())
        .expect("a key pair");
    let mut workingKey = scheme
        .workingKey(keyPair.secretKey.bytes())
        .expect("a working key");
    let mut freshKey = keyPair.secretKey.clone();
    for count in 0..32u32 {
        let countMessage = count.to_be_bytes();
        let mut store = RecordingStore::accepting();
        let signature = workingKey
            .sign(&countMessage, &mut store)
            .expect("a signature");
        let fresh = scheme
            .sign(
                &countMessage,
                &mut freshKey,
                &mut RecordingStore::accepting(),
            )
            .expect("a signature");
        assert_eq!(signature, fresh, "count {count}");
        assert_eq!(store.saved[0], freshKey.bytes(), "count {count}");
        assert!(scheme.isValidSignature(&signature, &countMessage, &keyPair.publicKey));
    }
    assert_eq!(&workingKey.secretKey().bytes()[..64], &[0xFF; 64]);
    let mut store = RecordingStore::accepting();
    assert_eq!(
        workingKey.sign(baseMessage, &mut store),
        Err(OQSError::keyExhausted)
    );
    assert!(store.saved.is_empty());
}
