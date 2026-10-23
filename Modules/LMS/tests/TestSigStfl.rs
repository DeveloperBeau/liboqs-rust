//! The tests of the LMS family for liboqs `tests/test_sig_stfl.c`: the key pairs and the
//! signatures of the C library, the random request, the secret key after each signature, the
//! counts, the end of a key, a failed save, each rejection path, both sides of each verdict of
//! a verification, the working key, and hostile inputs.
//!
//! The known answers come from the C library of the oracle with the NIST known-answer
//! generator seeded with the bytes 0 to 47, and the message `the quick brown fox`.

use OQSNativeAlgorithmTests::{FuzzRandom, ResponseFile, TestVectorFiles};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{OQSError, SecretBytes};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeLMS::LMS;
use OQSNativeSHA2::SHA256;

/// The message of the known answers.
const baseMessage: &[u8] = b"the quick brown fox";

/// The seed of the hostile inputs. A failure message names it.
const fuzzSeed: u64 = 0x4C4D_535F_4655_5A5A;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(&SHA256::hash(bytes))
}

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
    /// The SHA-256 of the serialized secret key of 10980 bytes.
    secretKey: &'static str,
    /// The SHA-256 of each signature and of the advanced key that the store gets.
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
        digest(keyPair.secretKey.bytes()),
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
            digest(&signature),
            *signatureDigest,
            "{name}, signature {count}"
        );
        assert_eq!(store.saved.len(), 1, "{name}");
        assert_eq!(
            digest(&store.saved[0]),
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
            secretKey: "bd68a79dd0428068bc042ef9c6cdb6b7a761d2ec57a74f54e9a3ca397c924750",
            signatures: &[
                (
                    "f50eb7b195bdddf58bcb5926437fffde6a7bc87e8690445a5633ee7c773374ba",
                    "70b2731782bb4f8cd7953cd8838a1a50e329ed3401794216ef585f7c6915244d",
                ),
                (
                    "6d2ac8cc3595d9f28f5f8469fd397cf443e70e5b8db473a114f379b4971ec48f",
                    "2f1510578a4ace673f44e0486177c5afc0670dda2e0f3ea1f21ad781c43cac52",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H5W2,
            publicKey: "000000010000000500000002056a8c266f9ef97ed08541dbd2e1ffa1a57971ed14a3cd1a528e27771c77b8e9c2f443e5dcf3f5045d8f925441528af2",
            secretKey: "273a54c9727757bc89d276916f7a398fd9263e9dca437f591a1f4499cb85517f",
            signatures: &[
                (
                    "ff7467a9f20cd1c67409500e5d1eb7dbe06b3f8ac1d1a34fcd3ff2e5356b21ce",
                    "1eee649147999a6708fc3551d03666eddcceb2b411d80423fd493232cb0cd325",
                ),
                (
                    "ab89020012d247434d046a516894016b2a3d53f1ce735daeb1e92c6d42dda481",
                    "61bd74838c481074718f713542c426b9bc78b8e144e7529eacbbe8728c63f1c9",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H5W4,
            publicKey: "000000010000000500000003056a8c266f9ef97ed08541dbd2e1ffa1fb39e1e60e6dbe7f123d0354687bdf68fceb9977c21a37484e0896ec33198d94",
            secretKey: "d55958072d1425786c8c57a35fc891adb0847f56dbc6f6f9c4b41f9fceb030ec",
            signatures: &[
                (
                    "8287bbfb048c0956bf387638692069266447f3a8eae5695114f44eee3716b919",
                    "6bbea5550ba30957d22ab4e1fcd016f09d57654ec8e53e9b936c80de5aa3b416",
                ),
                (
                    "0905ab5c54856d3ad61a195e0edfe27609d0341fcc7aee8e85f1614506e29a29",
                    "3ec3415b09cb518e6902ebb16b666c6709e80303c84951a71ada47878d27109f",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H5W8,
            publicKey: "000000010000000500000004056a8c266f9ef97ed08541dbd2e1ffa1bbbc42e0a4141c407bd56a6d260ef91a7cc6d5f8e8bec690ec69cddd1eeeb3c7",
            secretKey: "f6542bff9f5530e992d6a113566b95bac8921a3428e4b1be3ba44948e5810e0e",
            signatures: &[
                (
                    "190c69e61f1d49cf964368320b388bf4acc0efef8b5fb3ea0fc5df3723f5c5dc",
                    "f65db80346ccc192545c3216afd42cd5b57920ca905561ed621eacb8f38f4592",
                ),
                (
                    "712e8c04dcfa4a80ba0a37e76ef3b05e41e48179ae84210edb4a93dbe0912a00",
                    "3b5d41ae304047adce20e835d1322fd058fe7e99115622d09950ade8375d33a6",
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
            secretKey: "ecde4e33c970dd0720d98919eb17cd3f16a8856df9a769d94d59769a231824c4",
            signatures: &[
                (
                    "d55ea394a7bb2347c1eb443df31166bafe1e0b50e4b0c7b3501208baa04d4a8f",
                    "a1fcf60665a782372c0fc2d1187652a822018266d82a63ef9fa2739b742a9e00",
                ),
                (
                    "5e5b9407b529036b08c008c707b98fa5e9cd5bece393d1b83df314ad692265fe",
                    "e5ea9bbc553fa8f9282138cd2048ca084e37d3913c3d25ec57d53799aff17fb9",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H10W2,
            publicKey: "000000010000000600000002056a8c266f9ef97ed08541dbd2e1ffa10394836808954294a3bda6609804bf30309cd0f0d4ac8a6a62bd311efeaa01bd",
            secretKey: "86cbebc3205d1ebd7cfbb9267fd2c3317d705c16d90931fbc4bf5c16cc7c71da",
            signatures: &[
                (
                    "b27f2c436108358d1c08f319f634f1844410710861f6804cf41d1c678421862b",
                    "99a951d7714dd76e28f789c15761cef31fcddaf6c5ef4780bcc02b3f37399dd5",
                ),
                (
                    "40a524430d831a583ec8d0af913019cc19b3fe200a9da3e4aef1013a959e6014",
                    "67944a092de8c44b597505ed4eb7acf711e9498d59bae7de9ca2464b2ddea39f",
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
            secretKey: "a206c63b1d6a07138a0870ffcb06016db695378e0db126a226044935fd586b28",
            signatures: &[
                (
                    "d601b5f83def4f119158181879ecb222c31b70fa7c907538a7dca1d3c51dd8c6",
                    "cedcd3c76c9ac34b71329e11b643167cf9048e084c3dbd67803505fb3f83f71c",
                ),
                (
                    "07147675378924111698be96aab033fe15609afa4c9f0cfc070ecb1c18a309a5",
                    "3fa0d5e8470679fb20ccc22d9df0262751144706c9551aaf9e4aaf0edf12a0b1",
                ),
            ],
        },
        KnownAnswer {
            scheme: LMS::lmsSHA256H10W4H5W8,
            publicKey: "000000020000000600000003056a8c266f9ef97ed08541dbd2e1ffa10031465dceed7143d127e7e205d1120feccb819e4246ab2452fab4a35b87a46f",
            secretKey: "54dca0b9bbb5a2b6b9c7a5035cdc591b835e7aa63b6466b3b0cc2e1a9525427f",
            signatures: &[(
                "a3a13a16435da2248d654c3bb370a24cec9d880cae430d04f027195c6cb64e69",
                "2b6f4ec742baf429039392492c704efbbf859c38bfd2c0be9fa11579962cf637",
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
    // 31: the signature, the remaining and the total count after it, and the SHA-256 of the
    // stored key. liboqs counts from the highest sequence number, so a key at the count 31 has
    // 0 signatures left by its count and still signs once.
    let scheme = LMS::lmsSHA256H5W8;
    let expected = [
        (
            29,
            "80a979d098ffa1eb211565fc33acc1813d02b36957c2bef5128aff8efc754c06",
            Ok(1),
            "973eb9bbe69490a6eda894816cf8534b57dfca9ffe42ee74d1dc2cadcd72d98e",
        ),
        (
            30,
            "d63776aecad4cb1b93caf0e72a39dcbafbafe4cb9ec9e8e9ed725957fa9367a7",
            Ok(0),
            "eb7ddd226ee06cb0da7404a7be43b1beccd35b9ad6755364fa5d8cfc48c9a618",
        ),
        (
            31,
            "0fb933672460d24c19bf59f1b5491449b8b3c29c081d9ce93d5b750b9f401a3a",
            Err(OQSError::keyExhausted),
            "81605303268b8a0838a431689133d44d47f58bdd44da3682f46a60c0ef0f61ed",
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
        assert_eq!(digest(&signature), signatureDigest, "count {count}");
        assert_eq!(digest(&store.saved[0]), storedDigest, "count {count}");
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
        digest(&signature),
        "712e8c04dcfa4a80ba0a37e76ef3b05e41e48179ae84210edb4a93dbe0912a00"
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
        digest(&signature),
        "190c69e61f1d49cf964368320b388bf4acc0efef8b5fb3ea0fc5df3723f5c5dc"
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
            digest(&signature),
            "190c69e61f1d49cf964368320b388bf4acc0efef8b5fb3ea0fc5df3723f5c5dc"
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
        digest(&signature),
        "5ab69d47f7402058b87abce5a390562576c01928b35b41ed9af66e9a1696aa7a"
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
        "7b9ec198f610dfe4ebd39de6211fc65ed30934b067dc7ac697effe1f7a14877f",
        "e28c5b224f46a899aa739f4fcf5d281ce73f8699c5b43954d3243f5280e9f09c",
        "5ab69d47f7402058b87abce5a390562576c01928b35b41ed9af66e9a1696aa7a",
        "5af75b8b5415329e62edf0f15d90cc5607cbf564aae8a393346dcb1766e975c1",
        "0833edd74c6ba65f121d5897223682e7a217fff9de93a1041e8e9a0314fd0c53",
    ];
    let startKey = secretKeyAt(&scheme, 30);
    let mut workingKey = scheme.workingKey(startKey.bytes()).expect("a working key");
    for (count, signatureDigest) in (30u64..).zip(expected) {
        let mut store = RecordingStore::accepting();
        let signature = workingKey
            .sign(&(count as u32).to_be_bytes(), &mut store)
            .expect("a signature");
        assert_eq!(digest(&signature), signatureDigest, "count {count}");
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
        digest(&first),
        "d601b5f83def4f119158181879ecb222c31b70fa7c907538a7dca1d3c51dd8c6"
    );
    assert_eq!(
        digest(&second),
        "07147675378924111698be96aab033fe15609afa4c9f0cfc070ecb1c18a309a5"
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

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn hostileSignaturesKeysAndSecretKeysGiveADefinedResult() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for scheme in [LMS::lmsSHA256H5W8, LMS::lmsSHA256H5W8H5W8] {
        let description = scheme.description();
        let name = description.name;
        let keyPair = scheme
            .generateKeyPair(&mut knownAnswerRandom())
            .expect("a key pair");
        let mut secretKey = keyPair.secretKey.clone();
        let validSignature = scheme
            .sign(
                baseMessage,
                &mut secretKey,
                &mut RecordingStore::accepting(),
            )
            .expect("a signature");
        for case in 0..40u64 {
            let label = format!("{name}, case {case} of seed {fuzzSeed:#x}");
            let length = FuzzRandom::wrongLength(case, description.signatureLength);
            for signature in [
                randomBytes(&mut random, description.signatureLength),
                randomBytes(&mut random, length),
            ] {
                assert!(
                    !scheme.isValidSignature(&signature, baseMessage, &keyPair.publicKey),
                    "{label}"
                );
            }
            // A valid signature whose words of structure stay, with random bytes elsewhere.
            let mut hostile = validSignature.clone();
            let place = 12 + (random.nextWord() as usize) % (hostile.len() - 12);
            hostile[place] = hostile[place].wrapping_add(1 + (case as u8 % 255));
            assert!(
                !scheme.isValidSignature(&hostile, baseMessage, &keyPair.publicKey),
                "{label}, byte {place}"
            );
            let hostileKey = randomBytes(&mut random, 60);
            assert!(
                !scheme.isValidSignature(&validSignature, baseMessage, &hostileKey),
                "{label}"
            );
            // Random secret keys have no valid parameter set, and some have one with a random
            // count: each gives a defined error and leaves the key as it was.
            let mut hostileSecretKey = randomBytes(&mut random, 64 + (case as usize % 3));
            if case % 2 == 0 {
                hostileSecretKey[8..16]
                    .copy_from_slice(&[0x54, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            }
            let original = hostileSecretKey.clone();
            let mut wrapped = SecretBytes::new(hostileSecretKey);
            let result = scheme.sign(baseMessage, &mut wrapped, &mut RecordingStore::accepting());
            assert!(
                matches!(
                    result,
                    Err(OQSError::operationFailed) | Err(OQSError::keyExhausted)
                ),
                "{label}: {result:?}"
            );
            assert_eq!(wrapped.bytes(), &original[..], "{label}");
        }
    }
}
