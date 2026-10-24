//! The correctness test of liboqs `tests/test_sig_stfl.c` through
//! `StatefulSignatureCorrectnessTest`, and the tests of XMSS and XMSS^MT: the key pairs, the key
//! after each signature, the edges of the index and of the identifier, the store of the advanced
//! key, the counts and each rejection path.
//!
//! The known answers come from the C library of the oracle. A C program made the key pair of each
//! response file with the NIST generator seeded with the bytes 0 to 47, signed sequences of
//! messages, and signed the edge cases below, and printed the `OutputDigest` of each signature
//! and of each key. Valgrind reported no access outside the buffers of the C code for any of these
//! cases. The program is not part of the repository.

use OQSNativeAlgorithmTests::{
    FuzzRandom, OutputDigest, ResponseFile, StatefulSignatureCorrectnessTest, StatefulTreeHeight,
    TestVectorFiles,
};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{OQSError, SecretBytes};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeXMSS::{XMSS, XMSSMT};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A store that records each saved key, or refuses each save.
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

/// The entropy of the known-answer generator of the response files: the bytes 0 to 47.
fn countingEntropy() -> [u8; 48] {
    std::array::from_fn(|index| index as u8)
}

/// The key pair of the response file of a scheme, which is the key pair of the NIST generator
/// seeded with the bytes 0 to 47.
fn responseKeyPair(scheme: &dyn StatefulSigning) -> (Vec<u8>, SecretBytes) {
    let description = scheme.description();
    let text =
        TestVectorFiles::responseFile(description.name).unwrap_or_else(|error| panic!("{error}"));
    let file = ResponseFile::new(&text);
    let (publicKey, position) = file
        .value("pk = ", 0, description.publicKeyLength)
        .expect("pk");
    let (secretKey, _) = file
        .value("sk = ", position, description.secretKeyLength)
        .expect("sk");
    (publicKey, SecretBytes::new(secretKey))
}

/// The message of signature k of a sequence: 1 + 13 k mod 50 bytes, byte i being
/// 31 k + 7 i + 1 mod 256, as the C program makes it.
fn sequenceMessage(k: usize) -> Vec<u8> {
    let length = 1 + (13 * k) % 50;
    (0..length)
        .map(|index| (k * 31 + index * 7 + 1) as u8)
        .collect()
}

/// Writes an index into a key after its identifier, in the index bytes of the set.
fn withIndex(key: &[u8], indexLength: usize, index: u64) -> SecretBytes {
    let mut bytes = key.to_vec();
    bytes[4..4 + indexLength].copy_from_slice(&index.to_be_bytes()[8 - indexLength..]);
    SecretBytes::new(bytes)
}

// The correctness program.

/// The seed of the random source of the correctness program. A failure message names it.
const correctnessSeed: u64 = 0x5445_5354_5354_464C;

/// Runs the correctness program of `tests/test_sig_stfl.c` on each set whose name passes a
/// filter, with the response file of the set, as `test_cmdline.py` of liboqs runs it, on every
/// processor. Returns the failures.
fn correctnessFailures(isSelected: fn(&str) -> bool) -> Vec<String> {
    let schemes: Vec<&dyn StatefulSigning> = XMSS::schemes
        .iter()
        .chain(XMSSMT::schemes)
        .copied()
        .filter(|scheme| isSelected(scheme.description().name))
        .collect();
    let next = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism().map_or(1, usize::from);
    std::thread::scope(|scope| {
        for _ in 0..workers.min(schemes.len()) {
            scope.spawn(|| {
                while let Some(scheme) = schemes.get(next.fetch_add(1, Ordering::SeqCst)) {
                    let name = scheme.description().name;
                    let file = TestVectorFiles::responseFile(name)
                        .unwrap_or_else(|message| panic!("{message}"));
                    let mut random = FuzzRandom::seeded(correctnessSeed);
                    if let Err(message) =
                        StatefulSignatureCorrectnessTest::run(*scheme, &mut random, Some(&file))
                    {
                        let failure = format!("{message}, seed {correctnessSeed:#x}");
                        failures.lock().expect("the failure list").push(failure);
                    }
                }
            });
        }
    });
    failures.into_inner().expect("the failure list")
}

/// True for a set whose key pairs in the correctness program build no tree above height 5. The
/// program reads the key pairs of the sets of large trees from the response file, and the
/// XMSS^MT sets of 4, 8 and 12 layers have trees of height 5.
fn buildsNoTreeAboveHeight5(name: &str) -> bool {
    StatefulSignatureCorrectnessTest::responseFileKeyPairSchemes.contains(&name)
        || StatefulTreeHeight::largest(name).is_some_and(|height| height <= 5)
}

#[test]
fn testSigStflPassesForEachSetThatBuildsNoTreeAboveHeight5() {
    let failures = correctnessFailures(buildsNoTreeAboveHeight5);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "the correctness program makes three key pairs of each set, and the key pairs of the 13 sets with trees of height 10 take four minutes of processor time"]
fn testSigStflPassesForEverySet() {
    let failures = correctnessFailures(|_| true);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// Key pairs.

/// The C digests of the public key and of the secret key of the key pair of the NIST generator
/// seeded with the bytes 0 to 47, for the sets of height 10 whose response file liboqs made
/// with other random bytes: the 192-bit sets and XMSS-SHAKE256_10_256.
const keyPairDigests: [(&str, &str, &str); 3] = [
    (
        "XMSS-SHA2_10_192",
        "bf37ecee10e183ae393b4eae839e0a9734aae70b7e3475b794c3d5e37586e54c",
        "a58114ad882e868e2848bda7b9f3be560c3297ac20b19d90e50b95e828505a6d",
    ),
    (
        "XMSS-SHAKE256_10_192",
        "3c51a5fe7cd8f9a89e6f1d66f1815045e4e073babfa159a4a9715abe54a27e38",
        "d0409fe37e83560e377b790d499bc96f226935936b15b97cd549acec627ad94d",
    ),
    (
        "XMSS-SHAKE256_10_256",
        "277a97317eef8831efc599682cfffca3139bc0f211e90332c46f22a1e98c9fa4",
        "8d8b0ccab5415b8559043293e280df5287265fb97186246b399224fbfc73c176",
    ),
];

/// Checks the key pair of the NIST generator seeded with the bytes 0 to 47 against the C
/// library: the key pair of the response file, or the digests of `keyPairDigests`.
fn checkKeyPair(scheme: &dyn StatefulSigning) {
    let name = scheme.description().name;
    let keyPair = scheme
        .generateKeyPair(&mut NISTKATRandom::new(&countingEntropy(), None))
        .expect("key pair");
    let expected = match keyPairDigests.iter().find(|(set, _, _)| *set == name) {
        Some((_, publicKey, secretKey)) => (publicKey.to_string(), secretKey.to_string()),
        None => {
            let (publicKey, secretKey) = responseKeyPair(scheme);
            (
                OutputDigest::of(&publicKey),
                OutputDigest::of(secretKey.bytes()),
            )
        }
    };
    assert_eq!(
        (
            OutputDigest::of(&keyPair.publicKey),
            OutputDigest::of(keyPair.secretKey.bytes())
        ),
        expected,
        "{name}"
    );
}

#[test]
fn aKeyPairOfTheKnownAnswerGeneratorIsTheKeyPairOfTheCLibrary() {
    // One XMSS set of height 10 and the XMSS^MT sets of height 5, which a test build makes in
    // seconds. `keyPairsOfEverySetOfHeight10AreTheKeyPairsOfTheCLibrary` covers the rest.
    checkKeyPair(&XMSS::sha2Height10Bits192);
    checkKeyPair(&XMSSMT::sha2Height20Layers4);
    checkKeyPair(&XMSSMT::shake128Height20Layers4);
}

#[test]
#[ignore = "a key generation of height 10 takes seconds in a test build: run it with --release"]
fn keyPairsOfEverySetOfHeight10AreTheKeyPairsOfTheCLibrary() {
    let schemes: [&dyn StatefulSigning; 19] = [
        &XMSS::sha2Height10Bits256,
        &XMSS::shake128Height10Bits256,
        &XMSS::sha2Height10Bits512,
        &XMSS::shake256Height10Bits512,
        &XMSS::sha2Height10Bits192,
        &XMSS::shake256Height10Bits192,
        &XMSS::shake256Height10Bits256,
        &XMSSMT::sha2Height20Layers2,
        &XMSSMT::sha2Height20Layers4,
        &XMSSMT::sha2Height40Layers4,
        &XMSSMT::sha2Height40Layers8,
        &XMSSMT::sha2Height60Layers6,
        &XMSSMT::sha2Height60Layers12,
        &XMSSMT::shake128Height20Layers2,
        &XMSSMT::shake128Height20Layers4,
        &XMSSMT::shake128Height40Layers4,
        &XMSSMT::shake128Height40Layers8,
        &XMSSMT::shake128Height60Layers6,
        &XMSSMT::shake128Height60Layers12,
    ];
    for scheme in schemes {
        checkKeyPair(scheme);
    }
}

#[test]
fn aKeyPairDrawsTwoSeedsAndThenThePublicSeed() {
    // `xmss_core_keypair` draws SK_SEED and SK_PRF in one request of 2 n bytes, then PUB_SEED.
    let mut recording = RecordingRandom {
        inner: NISTKATRandom::new(&countingEntropy(), None),
        requests: Vec::new(),
    };
    let keyPair = XMSSMT::sha2Height20Layers4
        .generateKeyPair(&mut recording)
        .expect("key pair");
    assert_eq!(recording.requests, vec![64, 32]);
    // The key holds the identifier, the index 0, the two seeds of the first request, the root
    // and the public seed of the second request, and the public key is the identifier, the root
    // and the public seed.
    let mut generator = NISTKATRandom::new(&countingEntropy(), None);
    let mut seeds = [0u8; 64];
    generator.fillRandomBytes(&mut seeds);
    let mut publicSeed = [0u8; 32];
    generator.fillRandomBytes(&mut publicSeed);
    let secretKey = keyPair.secretKey.bytes();
    assert_eq!(secretKey[..7], [0, 0, 0, 2, 0, 0, 0]);
    assert_eq!(secretKey[7..71], seeds);
    assert_eq!(secretKey[71..103], keyPair.publicKey[4..36]);
    assert_eq!(secretKey[103..135], publicSeed);
    assert_eq!(keyPair.publicKey[..4], [0, 0, 0, 2]);
    assert_eq!(keyPair.publicKey[36..], publicSeed);
}

// The key after each signature.

/// Signs `count` messages from the key of the response file and compares the chain digest
/// `OutputDigest(chain || signature || saved key)` of each checkpoint with the C library, where
/// chain is the text of the link before. Each signature is checked against the public key, and
/// the saved key is the key in memory.
fn checkSequence(
    scheme: &dyn StatefulSigning,
    count: usize,
    checkpoints: &[(usize, u64, &str)],
    invalidSignatures: &[usize],
) {
    let name = scheme.description().name;
    let (publicKey, mut secretKey) = responseKeyPair(scheme);
    // Each link of the chain is the digest of the text of the link before, the signature and the
    // saved key, so one value checks every signature up to a checkpoint.
    let mut chain = String::new();
    let mut store = RecordingStore::accepting();
    let mut checkpoint = checkpoints.iter().peekable();
    for k in 0..count {
        let message = sequenceMessage(k);
        let signature = scheme
            .sign(&message, &mut secretKey, &mut store)
            .unwrap_or_else(|error| panic!("{name}, signature {k}: {error}"));
        assert_eq!(
            scheme.isValidSignature(&signature, &message, &publicKey),
            !invalidSignatures.contains(&k),
            "{name}, signature {k}"
        );
        let saved = store.saved.last().expect("a saved key");
        assert_eq!(saved.as_slice(), secretKey.bytes(), "{name}, signature {k}");
        chain = OutputDigest::of(&[chain.as_bytes(), &signature, saved].concat());
        if let Some((after, remaining, expected)) =
            checkpoint.next_if(|(after, _, _)| *after == k + 1)
        {
            assert_eq!(chain, *expected, "{name}, after {after} signatures");
            assert_eq!(
                scheme.remainingSignatureCount(secretKey.bytes()),
                Ok(*remaining),
                "{name}, after {after} signatures"
            );
        }
    }
    assert!(
        checkpoint.next().is_none(),
        "{name}: every checkpoint was reached"
    );
    assert_eq!(store.saved.len(), count);
}

#[test]
fn eachSignatureOfXMSSAdvancesTheKeyAsTheCLibraryDoes() {
    // Forty signatures move the BDS state through each height of tau up to 5.
    checkSequence(
        &XMSS::sha2Height10Bits256,
        40,
        &[
            (
                1,
                1022,
                "9072bd3b03abc943e45de407b34bd214b24014613ce65c4eca35d6d900e65aef",
            ),
            (
                2,
                1021,
                "814fb8ec0ac43fdaf7e203af4393cc1a2b6cc877d6121a5fac9a922a274851f1",
            ),
            (
                3,
                1020,
                "614a6303ba65588d13f5cc16ca490ca4a199b200feeaea84d27520d1e2ed242a",
            ),
            (
                4,
                1019,
                "b13111c2524a2248c1239c808d5fb2365ad3c8114a70570c948e5aa32f742881",
            ),
            (
                5,
                1018,
                "d727230176c3079ac535af3c79c8dd703483b5b9a2ab4d92c9476ed9a3aa2ef0",
            ),
            (
                6,
                1017,
                "05853c5facb27151e09da0e60dd5aa88b9e46b549213abe2ec504c8d97217aa5",
            ),
            (
                7,
                1016,
                "e25c29cb1c3bc09df80e69dfd119c3db67f8663f095767cddf5512f16e36d00a",
            ),
            (
                8,
                1015,
                "cf86c12f16fa05a898c921dd88aa0f2e5b6eb2b5d17c77cf1dedfe8c07b73409",
            ),
            (
                16,
                1007,
                "09e5b2369aadc00fb062526e38677e9775cef4953487e16f6e5fb22b0f793caa",
            ),
            (
                31,
                992,
                "9493acfe12d0c54eb41339999c2eadd48c9225971adede3c4c97c57c74e0b3e5",
            ),
            (
                32,
                991,
                "38bd8e8b634261fd40624ddbd68ca727f25224da0d1831be14144dfb127b4d06",
            ),
            (
                33,
                990,
                "63a7dc4254049c6b72c5be0f5f5d508026a4bf525a76e7d379fc1d23b7f6666e",
            ),
            (
                40,
                983,
                "1cbbbcb1fa9ebbd756f64020f9dee4f0d61f031f797c17c63d254ad5f428e0ab",
            ),
        ],
        &[],
    );
}

#[test]
fn eachSignatureOfXMSSMTAdvancesTheKeyAsTheCLibraryDoes() {
    // The trees of height 5 of the lowest layer end after 32 and 64 signatures, so their next
    // trees take their places and the layer above signs their roots.
    checkSequence(
        &XMSSMT::sha2Height20Layers4,
        70,
        &[
            (
                1,
                1048574,
                "53d21929a177c47d98730508d27b5a0282c30e4be38fff5beafbbade955b3088",
            ),
            (
                2,
                1048573,
                "0d68346606ca9d4115b35569d84d9c3a3df078ced92e2b1b943cc93db893257d",
            ),
            (
                3,
                1048572,
                "382f0c6266d969cb6fba5388926733d42cb69837eec915bc5358dec88948aa3e",
            ),
            (
                4,
                1048571,
                "b1bd84f8b34814376993efbdf246754393b9b2e8ded7a04ebdff09137ab420f7",
            ),
            (
                5,
                1048570,
                "c7633acd3cf06c85aaafb8f5ffcc0a7be10cc4a87f695d1e32fea2451bb7758d",
            ),
            (
                6,
                1048569,
                "9434980e6b148ef89b4507ccdddf6531fb6b78b73e23714dce5865c30394b7b0",
            ),
            (
                7,
                1048568,
                "81283ff1ea811d310a2e948647b2d065471fc54bb994795cbaef38c85e55150c",
            ),
            (
                8,
                1048567,
                "32aadddfb4d69b4cd8387ce3548bd780e6ec2a15c71351b9293041f799b1fafd",
            ),
            (
                16,
                1048559,
                "30bb2692f8d0d7cbdef619e2173c3bcbdef4ade5004797f55fea2d2faacf604f",
            ),
            (
                31,
                1048544,
                "c8cf0875ff4a1c21dbbf9264a47c4fccaf7db62271fc49d631eb5dc8c3b8afd2",
            ),
            (
                32,
                1048543,
                "4d3ada6a91cc0816e9d4d9e7432d8961204b61427ec698959068828d9420ede4",
            ),
            (
                33,
                1048542,
                "06c04b673467b9900f6956a0e5d43f21b939302bd189351c1811389626a39713",
            ),
            (
                40,
                1048535,
                "ee360432c65647c8f5f1ca32a85998299cb7fee39e4a8229cb95f844e86b01fc",
            ),
            (
                64,
                1048511,
                "cc641bbb94623808520852440a61fc905a8cf52f517b9a59748c481b0f190c91",
            ),
            (
                70,
                1048505,
                "65e4a5db94f1356660fec081f50b03a087c4b7e8f4d761b4cfd10bbeef5a71e0",
            ),
        ],
        &[],
    );
}

#[test]
fn eachSignatureOfAnXMSSMTSetOfEightLayersAdvancesTheKeyAsTheCLibraryDoes() {
    checkSequence(
        &XMSSMT::shake128Height40Layers8,
        40,
        &[
            (
                1,
                1099511627774,
                "df1eecbd13fe0aef666a12ff4c1b5794365b801c2c839e2eabdea8fddfa00cfc",
            ),
            (
                2,
                1099511627773,
                "2adffcd47839b3fc3d4538a3e2452d55eaddd4730a54dc86a8d3da6d4187e86d",
            ),
            (
                3,
                1099511627772,
                "44a714e3cbbc751984c537b1ff8852506c26efb0fa0d3995e6c2bb865358ec32",
            ),
            (
                4,
                1099511627771,
                "ec335decfd726675a9505c407bb09e4807a778a4692cd0fcb1919b89d2c0b7ba",
            ),
            (
                5,
                1099511627770,
                "935984d31af2579c63db323984f9d7a6d95bbbe01b15ad15766fa66d9e0c06ee",
            ),
            (
                6,
                1099511627769,
                "124c30068b8efb1c10dfe2b6a5aaed90752bbba1f9e10de4bf608953c32ea968",
            ),
            (
                7,
                1099511627768,
                "677185bed04376c53de5e3a0568eb1d16b737fd51d9a6e4f6ee532d8caba6d23",
            ),
            (
                8,
                1099511627767,
                "0750aa17b34778b158e64ca6c5f06198919149778e0f2fc68a315cee5894c18f",
            ),
            (
                16,
                1099511627759,
                "5814d19d2c1cf5befb4a418e58e3b76d9a6c60b1c402eb74c14f19c53535d69c",
            ),
            (
                31,
                1099511627744,
                "be3379a9947734ebffea65354c7797b55c41fcf19738704c3d6f798815495a3d",
            ),
            (
                32,
                1099511627743,
                "0db9c406b016e0b3530331ced2a53fb7edf8250dc2b10615e48b76192450150e",
            ),
            (
                33,
                1099511627742,
                "c21b7adfb23a38c953cc62647e7999faafd9f3f3f61b050de00ebd7b6ac21bec",
            ),
            (
                40,
                1099511627735,
                "0d779c325440a5bda3e8b441c76cc52ae7476b7afd9d2c24ecd19392b980b7f0",
            ),
        ],
        &[],
    );
}

#[test]
#[ignore = "1024 signatures take minutes in a test build: run it with --release"]
fn everySignatureOfAnXMSSKeyAdvancesTheKeyAsTheCLibraryDoes() {
    // The whole life of a key of height 10. The last index signs with the key that the C code
    // wiped, so that signature, the 1024th, is not valid, as in the C library.
    checkSequence(
        &XMSS::sha2Height10Bits256,
        1024,
        &[
            (
                1000,
                23,
                "2ef6a2cab341ef37f0f70dffae453018276dbd8268b2ee7e0b864dc21f11e362",
            ),
            (
                1023,
                0,
                "bfa8ef0d3ea43ec7539e1db04fcd9315b021ef92ca81453a8cfba88adada1cda",
            ),
            (
                1024,
                u64::MAX,
                "a5803fd23a67b278f7d2c81f1041142a3b9893728acc504d190ec826c0a34f0f",
            ),
        ],
        &[1023],
    );
}

#[test]
#[ignore = "1100 signatures take minutes in a test build: run it with --release"]
fn signaturesPastTheFirstTreeOfTheSecondLayerAdvanceTheKeyAsTheCLibraryDoes() {
    // After 1024 signatures the trees of the two lowest layers end at once.
    checkSequence(
        &XMSSMT::sha2Height20Layers4,
        1100,
        &[
            (
                1000,
                1047575,
                "c90d23d659914037409574e6c95d021195fb758289a7f643bbdd5ac090f37e83",
            ),
            (
                1023,
                1047552,
                "2596d889bf9efdc9eec5886845baab413c2bc507e57cf1576bca8dc2c875a23f",
            ),
            (
                1024,
                1047551,
                "91a3523a4aafce758974cecb866f42e2475bef6fe8873fc08316f22165039e41",
            ),
            (
                1100,
                1047475,
                "c530e5a28ae4ebc5c5b4e30d7d572dad5f31601c8d7f156d9586cb837bfb758f",
            ),
        ],
        &[],
    );
}

// Edge cases of the index and the identifier.

/// The outcome of two signatures of message 7 with a key, as the C program prints it: the result,
/// the digest of each signature and the digest of the key in memory after each.
struct TwoSignatures {
    first: Result<String, OQSError>,
    firstKey: String,
    remaining: Result<u64, OQSError>,
    total: Result<u64, OQSError>,
    second: Result<String, OQSError>,
    secondKey: String,
}

fn signTwice(scheme: &dyn StatefulSigning, mut secretKey: SecretBytes) -> TwoSignatures {
    let message = sequenceMessage(7);
    let mut store = RecordingStore::accepting();
    let first = scheme
        .sign(&message, &mut secretKey, &mut store)
        .map(|signature| OutputDigest::of(&signature));
    if first.is_ok() {
        assert_eq!(
            store.saved.last().map(Vec::as_slice),
            Some(secretKey.bytes())
        );
    }
    let firstKey = OutputDigest::of(secretKey.bytes());
    let remaining = scheme.remainingSignatureCount(secretKey.bytes());
    let total = scheme.totalSignatureCount(secretKey.bytes());
    let second = scheme
        .sign(&message, &mut secretKey, &mut store)
        .map(|signature| OutputDigest::of(&signature));
    let secondKey = OutputDigest::of(secretKey.bytes());
    TwoSignatures {
        first,
        firstKey,
        remaining,
        total,
        second,
        secondKey,
    }
}

#[test]
fn theLastIndexSignsWithTheWipedKeyAndTheNextIndexIsExhausted() {
    let (_, key) = responseKeyPair(&XMSS::sha2Height10Bits256);
    // At the last index the C code wipes the key, signs with the zeroed seeds, and writes back
    // the index 1024 and the counters of the state. The count wraps below zero.
    let outcome = signTwice(&XMSS::sha2Height10Bits256, withIndex(key.bytes(), 4, 1023));
    assert_eq!(
        outcome.first.as_deref(),
        Ok("2e610917b14e370ced8caab84c34bd0ac20769c28db3ad03b62bb03a9ae5d646")
    );
    assert_eq!(
        outcome.firstKey,
        "513ae5ec00b1b88da117053c0894a655e2e4b461ae2625da1f33991bccda1ebc"
    );
    assert_eq!(outcome.remaining, Ok(u64::MAX));
    assert_eq!(outcome.total, Ok(1023));
    // Past the last index the signature fails, and the key is zero after its identifier.
    assert_eq!(outcome.second, Err(OQSError::keyExhausted));
    assert_eq!(
        outcome.secondKey,
        "7a247c3f72cf170ada48bdf1a6f39d1e12c37a1160683fe43d767b82c80189e8"
    );
}

#[test]
fn anIndexPastTheLastWipesTheKeyWhichThenSignsFromIndexZero() {
    let (_, key) = responseKeyPair(&XMSS::sha2Height10Bits256);
    for index in [1024, u64::from(u32::MAX)] {
        let wiped = withIndex(key.bytes(), 4, index);
        let mut expected = vec![0u8; wiped.bytes().len()];
        expected[..4].copy_from_slice(&[0, 0, 0, 1]);
        let mut secretKey = wiped.clone();
        let mut store = RecordingStore::accepting();
        assert_eq!(
            XMSS::sha2Height10Bits256.sign(b"message", &mut secretKey, &mut store),
            Err(OQSError::keyExhausted),
            "index {index}"
        );
        assert_eq!(secretKey.bytes(), expected.as_slice(), "index {index}");
        assert!(store.saved.is_empty());
        // The wiped key has the index 0, so the C library counts 1023 signatures left and signs
        // again, with zero seeds.
        let outcome = signTwice(&XMSS::sha2Height10Bits256, wiped);
        assert_eq!(outcome.first, Err(OQSError::keyExhausted));
        assert_eq!(
            outcome.firstKey,
            "7a247c3f72cf170ada48bdf1a6f39d1e12c37a1160683fe43d767b82c80189e8"
        );
        assert_eq!(outcome.remaining, Ok(1023));
        assert_eq!(
            outcome.second.as_deref(),
            Ok("8857f3827fa7c1f4ee4a47aa2a5cac02a21c0b9e92db26065db2aabc991452d7")
        );
        assert_eq!(
            outcome.secondKey,
            "0dfca24c426a75a7dfdf2147842e3a527964cf93c925e87ed4460a2e66977df7"
        );
    }
}

#[test]
fn anIndexThatTheStateDoesNotFollowSignsAsTheCLibraryDoes() {
    let (_, key) = responseKeyPair(&XMSS::sha2Height10Bits256);
    let outcome = signTwice(&XMSS::sha2Height10Bits256, withIndex(key.bytes(), 4, 500));
    assert_eq!(
        outcome.first.as_deref(),
        Ok("686d39bc39abcd32e8a1490f2e111bb5d89e24d753b70420873d4ac8a18cb0eb")
    );
    assert_eq!(
        outcome.firstKey,
        "509b9b0ffa7e94655b7547b8fb154eebad4ec8c5453c937bcbab63d164af6b73"
    );
    assert_eq!(outcome.remaining, Ok(522));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("dc2d4e2986247ab210ce8cbe002a7263fd956fab9ae08dbe80a0f3d066fb4097")
    );
    assert_eq!(
        outcome.secondKey,
        "621e0079d0b727ea723ddd79058dba158dff3a807b58841055a6dde19f67ec52"
    );
}

#[test]
fn theIdentifierOfTheKeyChoosesTheParametersAndTheSetChoosesTheHash() {
    let (_, key) = responseKeyPair(&XMSS::sha2Height10Bits256);
    // The identifier of XMSS-SHAKE_10_256 has the same lengths, so the key signs with SHA-256 and
    // keeps its identifier.
    let mut shakeKey = key.bytes().to_vec();
    shakeKey[3] = 0x07;
    let outcome = signTwice(&XMSS::sha2Height10Bits256, SecretBytes::new(shakeKey));
    let signature = "8eea1f62f2a2f5f21f7713653b90d0d9dd84662127a5a8dc600a6cc17cd59078";
    assert_eq!(outcome.first.as_deref(), Ok(signature));
    assert_eq!(
        outcome.firstKey,
        "c4a2bf9d70d84d36f6e6eafa1c67e840e7913ea0fa7d9194a73cad95e6b4171b"
    );
    assert_eq!((outcome.remaining, outcome.total), (Ok(1022), Ok(1023)));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("f9ffda2a3ab628325d2c66e37ca45725d3a163cf63a3dbfbb9c1325acb2af7b7")
    );
    assert_eq!(
        outcome.secondKey,
        "0392905d40c2dcfc9b018e9a4f4574b6d75328501ac8a952e1e9b253576a694b"
    );
    // A key of height 10 in the larger buffer of XMSS-SHA2_16_256 signs with height 10, and its
    // signature is the 2500 bytes of the smaller set.
    let mut wide = key.bytes().to_vec();
    wide.resize(XMSS::sha2Height16Bits256.description().secretKeyLength, 0);
    let mut secretKey = SecretBytes::new(wide.clone());
    let mut store = RecordingStore::accepting();
    let signed = XMSS::sha2Height16Bits256
        .sign(&sequenceMessage(7), &mut secretKey, &mut store)
        .expect("a signature");
    assert_eq!(signed.len(), 2500);
    let outcome = signTwice(&XMSS::sha2Height16Bits256, SecretBytes::new(wide));
    assert_eq!(outcome.first.as_deref(), Ok(signature));
    assert_eq!(
        outcome.firstKey,
        "a83dc860c42b3b601c3d3d69480a473d2e799c3f320b6490d8cd2bbbdc23aa93"
    );
    assert_eq!((outcome.remaining, outcome.total), (Ok(1022), Ok(1023)));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("f9ffda2a3ab628325d2c66e37ca45725d3a163cf63a3dbfbb9c1325acb2af7b7")
    );
    assert_eq!(
        outcome.secondKey,
        "d3399400b03438219ba3806084d5643e9b7230e29b63a0bb6dfec83f0fb94e02"
    );
}

#[test]
fn theEdgesOfTheIndexOfXMSSMTSignAsTheCLibraryDoes() {
    let (_, key) = responseKeyPair(&XMSSMT::sha2Height20Layers4);
    let scheme = &XMSSMT::sha2Height20Layers4;
    // The last index, then past it.
    let outcome = signTwice(scheme, withIndex(key.bytes(), 3, (1 << 20) - 1));
    assert_eq!(
        outcome.first.as_deref(),
        Ok("29f2360a574084218b2ad83232c903c7bd2c038b18ccbd7b6242530b762ab8e1")
    );
    assert_eq!(
        outcome.firstKey,
        "b80e642b33d6ba7f1080debe0e9946169f196bed26b290a09e339cd0eea33683"
    );
    assert_eq!(outcome.remaining, Ok(u64::MAX));
    assert_eq!(outcome.second, Err(OQSError::keyExhausted));
    let wipedKey = "7ebd63c4a271f574a9ba1ebe6e2aaf8c488e97447c2813a265148971309889b8";
    assert_eq!(outcome.secondKey, wipedKey);
    let outcome = signTwice(scheme, withIndex(key.bytes(), 3, 1 << 20));
    assert_eq!(outcome.first, Err(OQSError::keyExhausted));
    assert_eq!(outcome.firstKey, wipedKey);
    assert_eq!(outcome.remaining, Ok(1048575));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("5ab9ede81db042f508ea108f7db6c9207d53f138898c403eac0030c30ad51e0e")
    );
    assert_eq!(
        outcome.secondKey,
        "6b58525612ae6cf29a522446fd56165affc29f94848542f58d8fe2c9b1c71bb4"
    );
    // The ends of one, two and three trees at once: the next trees of the fresh key are empty,
    // and at the end of three trees the count of the updates goes below zero.
    for (index, signature, firstKey, remaining, second, secondKey) in [
        (
            31,
            "53afb6aadd731d58922192c0f3d7a11c10356333b6ec1328a3456f219a3da248",
            "23a98d625d1afdbd6b5f09164417c78bef13abe4007fc483c7619d731690ffe4",
            1048543,
            "d8cb0544afb37c626db1d360ef6a2f6c87d045e3c15847d8933cc01b9995443f",
            "cf932849b2137e3a13ceb8bbe69e02cef0ac7034d78b5b47a5b5ddad8be4c1f1",
        ),
        (
            1023,
            "7c9c59493c2338d36c4f4cce9d8661b86ee415da801d637f6bda3e38d8431e9d",
            "e990ac79c3cb2fd7752eb2d7a7fc974ccd303d4e1a1c799bfd805ebcd74f614f",
            1047551,
            "3a42f3cb8f3d03ed93d7737cf3170ae7980dc75a3597466a0dc364dd2708e1ae",
            "52c5ae4e0402730def3ee6fdccc8d3b765a9491d58bcdc66ebedcedc16645756",
        ),
        (
            32767,
            "f919a81d04a4f91e54097b25e2190472b298cfb0d3e2fd55037fff09c9a0fa12",
            "42e5382d62f6402071d3e641e456090bf42c0f645340c87c6dd09c603703fa93",
            1015807,
            "8ea5455f5860eb0dc4748e70f702354299c527444a2b24c6f6a23cf47d26bfaf",
            "786aa74a8e6ab38469fc75ed6f1a8e3967f7be5dabaf42c474c637ac7f7cc237",
        ),
    ] {
        let outcome = signTwice(scheme, withIndex(key.bytes(), 3, index));
        assert_eq!(outcome.first.as_deref(), Ok(signature), "index {index}");
        assert_eq!(outcome.firstKey, firstKey, "index {index}");
        assert_eq!(outcome.remaining, Ok(remaining), "index {index}");
        assert_eq!(outcome.second.as_deref(), Ok(second), "index {index}");
        assert_eq!(outcome.secondKey, secondKey, "index {index}");
    }
}

#[test]
fn updatesBelowZeroReachTheNextTreesOfTheLayersAboveAsInTheCLibrary() {
    // At index 32767 of XMSSMT-SHA2_40/8_256 three trees end at once, and the count of updates
    // wraps below zero, so the layers above get the updates of a large count. At the last index
    // the index 2^40 does not fit in 5 bytes, and the key wraps to index 0.
    let (_, key) = responseKeyPair(&XMSSMT::sha2Height40Layers8);
    let scheme = &XMSSMT::sha2Height40Layers8;
    for (index, signature, firstKey, remaining, second, secondKey) in [
        (
            32767,
            "fb24856c48b92df3c1782735a21829c3f034729a8f0497ac4b8b8b9d1326cfc5",
            "0b6235db87aa2be476ebf1e675c94c9342b9242d71403d730e7ddfe8c6177e4b",
            1099511595007,
            "abffddd59b43ce62cbac5f95314481eea911ee5d024e5ee028a051cfe335aa75",
            "809d3cd2c052ea83b2768886dc9e8cb4117db7e765bafa2f0515caa3c2b153af",
        ),
        (
            (1 << 40) - 1,
            "a614060f727bfcda234deaab6404cb3fad65eb9be9ea32b90c795fffed414b5b",
            "3c173f1699c2fcc92049b8d40f493a54d5412fc396174f9bb90f2e4d88e195b0",
            1099511627775,
            "6a6bdaaa440cf7355e2413b1584ffe7c38ab2c8a7c2758f71f0cc91f02aa0b0c",
            "52db8ec99c569108396b9ddd629614b3d596b547c192a6c1647aa401637f015b",
        ),
    ] {
        let outcome = signTwice(scheme, withIndex(key.bytes(), 5, index));
        assert_eq!(outcome.first.as_deref(), Ok(signature), "index {index}");
        assert_eq!(outcome.firstKey, firstKey, "index {index}");
        assert_eq!(outcome.remaining, Ok(remaining), "index {index}");
        assert_eq!(outcome.second.as_deref(), Ok(second), "index {index}");
        assert_eq!(outcome.secondKey, secondKey, "index {index}");
    }
}

#[test]
fn theTreeIndexOfTheUpdatesOfALayerPassesThrough32BitsAsInTheCCode() {
    // From index 2^52 on, the tree index of layer 0 of XMSSMT-SHA2_60/3_256 has more than 32
    // bits. The C code passes it through `uint32_t` for the updates of the current tree, and not
    // for its WOTS+ signature or for the next tree.
    let (_, key) = responseKeyPair(&XMSSMT::sha2Height60Layers3);
    let outcome = signTwice(
        &XMSSMT::sha2Height60Layers3,
        withIndex(key.bytes(), 8, (1 << 52) + 5),
    );
    assert_eq!(
        outcome.first.as_deref(),
        Ok("8093dcb720e4fff71914686e8ad9a292c9eb001536ee338846a862b5333f0e9e")
    );
    assert_eq!(
        outcome.firstKey,
        "4c0b2ba457fd01f41a25c1ac9a9bec7227036c25cb23116bc33f865772cc995c"
    );
    assert_eq!(outcome.remaining, Ok(1_148_417_904_979_476_473));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("758cc020758b82d6ce82952ec7846003158440e4685ab548cedf663b06bad8a1")
    );
    assert_eq!(
        outcome.secondKey,
        "d9452f8e96e6c1f204164415034f4e194e9318a15e3907060b78c1a60474ef23"
    );
}

// Rejection paths.

#[test]
fn eachOperationRefusesASecretKeyOfAnotherLength() {
    let schemes: [&dyn StatefulSigning; 2] =
        [&XMSS::sha2Height10Bits256, &XMSSMT::sha2Height20Layers2];
    for scheme in schemes {
        let length = scheme.description().secretKeyLength;
        for wrongLength in [0, 4, length - 1, length + 1] {
            let error = Err(OQSError::invalidLength {
                expected: length,
                actual: wrongLength,
            });
            let mut secretKey = SecretBytes::zeroed(wrongLength);
            let mut store = RecordingStore::accepting();
            assert_eq!(
                scheme
                    .sign(b"message", &mut secretKey, &mut store)
                    .map(|_| ()),
                error
            );
            assert!(store.saved.is_empty());
            assert_eq!(
                scheme.remainingSignatureCount(secretKey.bytes()),
                error.map(|()| 0)
            );
            assert_eq!(
                scheme.totalSignatureCount(secretKey.bytes()),
                error.map(|()| 0)
            );
        }
    }
}

#[test]
fn aKeyWhoseIdentifierIsNoSetOfTheVariantIsRefused() {
    let (_, key) = responseKeyPair(&XMSS::sha2Height10Bits256);
    // 0x16 is past the XMSS table, and the C library leaves the key as it is.
    for identifier in [0u32, 0x16, 0xFF, 0x0100_0001] {
        let mut bytes = key.bytes().to_vec();
        bytes[..4].copy_from_slice(&identifier.to_be_bytes());
        let mut secretKey = SecretBytes::new(bytes.clone());
        let mut store = RecordingStore::accepting();
        assert_eq!(
            XMSS::sha2Height10Bits256.sign(b"message", &mut secretKey, &mut store),
            Err(OQSError::operationFailed),
            "{identifier:#x}"
        );
        assert_eq!(secretKey.bytes(), bytes.as_slice());
        assert_eq!(
            XMSS::sha2Height10Bits256.remainingSignatureCount(&bytes),
            Err(OQSError::operationFailed)
        );
        assert_eq!(
            XMSS::sha2Height10Bits256.totalSignatureCount(&bytes),
            Err(OQSError::operationFailed)
        );
    }
    // The digest of the key of identifier 0x16 that the C library keeps.
    let mut bytes = key.bytes().to_vec();
    bytes[3] = 0x16;
    assert_eq!(
        OutputDigest::of(&bytes),
        "8d017a199f5ba323a6cd25a744f1f96240790603eb7087764f9b156bdde83765"
    );
    // The identifiers of XMSS^MT are another table: 0x16 there is XMSSMT-SHAKE_60/3_256.
    let (_, mtKey) = responseKeyPair(&XMSSMT::sha2Height20Layers2);
    let mut bytes = mtKey.bytes().to_vec();
    bytes[3] = 0x39;
    assert_eq!(
        XMSSMT::sha2Height20Layers2.totalSignatureCount(&bytes),
        Err(OQSError::operationFailed)
    );
    bytes[3] = 0x16;
    assert_eq!(
        XMSSMT::sha2Height20Layers2.totalSignatureCount(&bytes),
        Ok((1 << 60) - 1)
    );
}

#[test]
fn aKeyWhoseIdentifierOverrunsTheBuffersOfTheCCodeIsRefused() {
    let (_, key) = responseKeyPair(&XMSS::sha2Height10Bits256);
    // XMSS-SHA2_16_256 needs a longer key and a longer signature, XMSS-SHA2_10_192 another hash
    // length, and XMSS-SHA2_10_512 both. The C code overruns its buffers with each of them. The
    // counts read only the index, so they still give the counts of the identifier.
    for (identifier, total) in [(0x02u8, (1u64 << 16) - 1), (0x0d, 1023), (0x04, 1023)] {
        let mut bytes = key.bytes().to_vec();
        bytes[3] = identifier;
        let mut secretKey = SecretBytes::new(bytes.clone());
        let mut store = RecordingStore::accepting();
        assert_eq!(
            XMSS::sha2Height10Bits256.sign(b"message", &mut secretKey, &mut store),
            Err(OQSError::operationFailed),
            "{identifier:#x}"
        );
        assert_eq!(secretKey.bytes(), bytes.as_slice());
        assert!(store.saved.is_empty());
        assert_eq!(
            XMSS::sha2Height10Bits256.totalSignatureCount(&bytes),
            Ok(total)
        );
    }
    // A key of XMSSMT-SHA2_20/4_256 fits the larger buffer of XMSSMT-SHA2_60/3_256, but its
    // signature of 9251 bytes overruns the 8392 bytes of that set. The identifier of
    // XMSSMT-SHA2_60/3_256 in a key of XMSSMT-SHA2_20/4_256 needs a longer key.
    let (_, mtKey) = responseKeyPair(&XMSSMT::sha2Height20Layers4);
    let mut longSignature = mtKey.bytes().to_vec();
    longSignature.resize(XMSSMT::sha2Height60Layers3.description().secretKeyLength, 0);
    let mut longKey = mtKey.bytes().to_vec();
    longKey[3] = 0x06;
    let cases: [(&dyn StatefulSigning, Vec<u8>, u64); 2] = [
        (&XMSSMT::sha2Height60Layers3, longSignature, (1 << 20) - 1),
        (&XMSSMT::sha2Height20Layers4, longKey, (1 << 60) - 1),
    ];
    for (scheme, bytes, total) in cases {
        let name = scheme.description().name;
        let mut secretKey = SecretBytes::new(bytes.clone());
        let mut store = RecordingStore::accepting();
        assert_eq!(
            scheme.sign(b"message", &mut secretKey, &mut store),
            Err(OQSError::operationFailed),
            "{name}"
        );
        assert_eq!(secretKey.bytes(), bytes.as_slice(), "{name}");
        assert!(store.saved.is_empty(), "{name}");
        assert_eq!(scheme.totalSignatureCount(&bytes), Ok(total), "{name}");
    }
}

#[test]
fn aFailedSaveReleasesNoSignatureAndTheKeyInMemoryStillAdvances() {
    // Each set, its index bytes and the count after one signature.
    let cases: [(&dyn StatefulSigning, usize, u64); 2] = [
        (&XMSS::sha2Height10Bits256, 4, 1022),
        (&XMSSMT::sha2Height20Layers2, 3, (1 << 20) - 2),
    ];
    for (scheme, indexLength, remaining) in cases {
        let name = scheme.description().name;
        let (publicKey, mut secretKey) = responseKeyPair(scheme);
        let original = secretKey.bytes().to_vec();
        let mut refusing = RecordingStore::refusing();
        assert_eq!(
            scheme.sign(b"message", &mut secretKey, &mut refusing),
            Err(OQSError::persistenceFailed),
            "{name}"
        );
        // The C library advances the key before it calls the store, so the key in memory never
        // signs twice with one index.
        let mut indexOne = vec![0u8; indexLength];
        indexOne[indexLength - 1] = 1;
        assert_ne!(secretKey.bytes(), original.as_slice(), "{name}");
        assert_eq!(secretKey.bytes()[4..4 + indexLength], indexOne, "{name}");
        assert_eq!(
            scheme.remainingSignatureCount(secretKey.bytes()),
            Ok(remaining),
            "{name}"
        );
        // The next signature uses index 1, which is signature 1 of the sequence of the C library
        // after the key of signature 0.
        let mut store = RecordingStore::accepting();
        let signature = scheme
            .sign(b"message", &mut secretKey, &mut store)
            .expect("a signature");
        assert_eq!(signature[..indexLength], indexOne, "{name}");
        assert!(
            scheme.isValidSignature(&signature, b"message", &publicKey),
            "{name}"
        );
        assert_eq!(store.saved, vec![secretKey.bytes().to_vec()], "{name}");
        // The same key without the refused save gives the same key after its second signature.
        let mut direct = SecretBytes::new(original);
        let mut discarding = RecordingStore::accepting();
        scheme
            .sign(b"message", &mut direct, &mut discarding)
            .expect("a signature");
        scheme
            .sign(b"message", &mut direct, &mut discarding)
            .expect("a signature");
        assert_eq!(direct.bytes(), secretKey.bytes(), "{name}");
    }
}

#[test]
fn aForgedStateThatLeavesTheKeyIsRefusedAndKeepsTheKey() {
    let scheme = &XMSS::sha2Height10Bits256;
    let (_, key) = responseKeyPair(scheme);
    // The layout of xmss_core_fast.c for n = 32 and h = 10: the identifier, the index and the
    // four values of n bytes, then the stack of 11 nodes, the stack offset at 488, the 11 stack
    // levels, the 10 nodes of the path, the 5 kept nodes and, from 983, the 10 treehash
    // instances of 39 bytes: the height, the next index, the stack usage, the completion and
    // the node.
    let treeHash = |instance: usize| 983 + 39 * instance;
    let cases: [(&str, Vec<(usize, u8)>); 2] = [
        // An unfinished instance with one node on an empty stack reads the level before the
        // stack levels.
        (
            "stack usage without a stack",
            vec![(treeHash(0) + 5, 1), (treeHash(0) + 6, 0)],
        ),
        // A stack offset of 2^32 - 1 puts the next node 2^32 - 32 bytes after the stack.
        (
            "stack offset",
            vec![
                (488, 0xFF),
                (489, 0xFF),
                (490, 0xFF),
                (491, 0xFF),
                (treeHash(1) + 6, 0),
                (treeHash(1), 1),
            ],
        ),
    ];
    for (name, changes) in cases {
        let mut bytes = key.bytes().to_vec();
        for (offset, value) in changes {
            bytes[offset] = value;
        }
        let mut secretKey = SecretBytes::new(bytes.clone());
        let mut store = RecordingStore::accepting();
        assert_eq!(
            scheme.sign(b"message", &mut secretKey, &mut store),
            Err(OQSError::operationFailed),
            "{name}"
        );
        assert_eq!(secretKey.bytes(), bytes.as_slice(), "{name}");
        assert!(store.saved.is_empty(), "{name}");
    }
    // XMSSMT-SHA2_20/4_256 adds a leaf to the next tree of the lowest layer at each signature.
    // Its state is state 4 of 625 bytes after the 135 bytes of the identifier, the index and the
    // seeds, so its stack offset is at 2827. An offset of 2^32 - 1 puts the leaf outside the key.
    let (_, key) = responseKeyPair(&XMSSMT::sha2Height20Layers4);
    let mut bytes = key.bytes().to_vec();
    bytes[2827..2831].copy_from_slice(&[0xFF; 4]);
    let mut secretKey = SecretBytes::new(bytes.clone());
    let mut store = RecordingStore::accepting();
    assert_eq!(
        XMSSMT::sha2Height20Layers4.sign(b"message", &mut secretKey, &mut store),
        Err(OQSError::operationFailed)
    );
    assert_eq!(secretKey.bytes(), bytes.as_slice());
    // The same key with the stack offset 0 of a fresh key signs.
    bytes[2827..2831].copy_from_slice(&[0; 4]);
    let mut secretKey = SecretBytes::new(bytes);
    assert!(
        XMSSMT::sha2Height20Layers4
            .sign(b"message", &mut secretKey, &mut store)
            .is_ok()
    );
}

// Verification.

#[test]
fn verificationRefusesEachInputOfAnotherLengthOrIdentifierAndAcceptsTheRightOnes() {
    let schemes: [&dyn StatefulSigning; 2] =
        [&XMSS::sha2Height10Bits256, &XMSSMT::sha2Height20Layers2];
    for scheme in schemes {
        let name = scheme.description().name;
        let (publicKey, mut secretKey) = responseKeyPair(scheme);
        let signature = scheme
            .sign(b"message", &mut secretKey, &mut RecordingStore::accepting())
            .expect("a signature");
        assert!(
            scheme.isValidSignature(&signature, b"message", &publicKey),
            "{name}"
        );
        assert!(!scheme.isValidSignature(&signature[1..], b"message", &publicKey));
        let mut longer = signature.clone();
        longer.push(0);
        assert!(!scheme.isValidSignature(&longer, b"message", &publicKey));
        assert!(!scheme.isValidSignature(&signature, b"message", &publicKey[1..]));
        let mut longerKey = publicKey.clone();
        longerKey.push(0);
        assert!(!scheme.isValidSignature(&signature, b"message", &longerKey));
        assert!(!scheme.isValidSignature(&[], b"message", &publicKey));
        assert!(!scheme.isValidSignature(&signature, b"message", &[]));
        // The identifier of another set in the public key, as in GHSA-2wxh-55qf-c7wg, is refused
        // before the signature is read, so the valid signature fails with it.
        let mut otherIdentifier = publicKey.clone();
        otherIdentifier[3] ^= 0x03;
        assert!(
            !scheme.isValidSignature(&signature, b"message", &otherIdentifier),
            "{name}"
        );
        assert!(!scheme.isValidSignature(&vec![0u8; signature.len()], b"test", &publicKey));
    }
}

#[test]
fn aChangeInEachPartOfASignatureOrOfThePublicKeyIsRefused() {
    let schemes: [&dyn StatefulSigning; 2] =
        [&XMSS::sha2Height10Bits256, &XMSSMT::sha2Height20Layers2];
    for scheme in schemes {
        let name = scheme.description().name;
        let (publicKey, mut secretKey) = responseKeyPair(scheme);
        let message = sequenceMessage(3);
        let signature = scheme
            .sign(&message, &mut secretKey, &mut RecordingStore::accepting())
            .expect("a signature");
        let length = signature.len();
        // The index, R, the first WOTS+ chain, the last authentication node and the middle.
        for position in [0, 3, 5, 40, length / 2, length - 33, length - 1] {
            for bit in [0, 7] {
                let mut changed = signature.clone();
                changed[position] ^= 1 << bit;
                assert!(
                    !scheme.isValidSignature(&changed, &message, &publicKey),
                    "{name}: byte {position}, bit {bit}"
                );
            }
        }
        // The root and the public seed of the public key.
        for position in [4, 35, 36, publicKey.len() - 1] {
            let mut changedKey = publicKey.clone();
            changedKey[position] ^= 0x10;
            assert!(
                !scheme.isValidSignature(&signature, &message, &changedKey),
                "{name}"
            );
        }
        let mut changedMessage = message.clone();
        changedMessage[0] ^= 1;
        assert!(!scheme.isValidSignature(&signature, &changedMessage, &publicKey));
        assert!(
            scheme.isValidSignature(&signature, &message, &publicKey),
            "{name}"
        );
    }
}

// Counts.

#[test]
fn theCountsOfAFreshKeyAreTwoToTheHeightMinusOne() {
    let schemes: [(&dyn StatefulSigning, u64); 6] = [
        (&XMSS::sha2Height10Bits256, (1 << 10) - 1),
        (&XMSS::shake256Height20Bits512, (1 << 20) - 1),
        (&XMSS::sha2Height16Bits192, (1 << 16) - 1),
        (&XMSSMT::sha2Height20Layers4, (1 << 20) - 1),
        (&XMSSMT::shake128Height40Layers2, (1 << 40) - 1),
        (&XMSSMT::sha2Height60Layers12, (1 << 60) - 1),
    ];
    for (scheme, total) in schemes {
        let name = scheme.description().name;
        let (_, secretKey) = responseKeyPair(scheme);
        assert_eq!(
            scheme.totalSignatureCount(secretKey.bytes()),
            Ok(total),
            "{name}"
        );
        assert_eq!(
            scheme.remainingSignatureCount(secretKey.bytes()),
            Ok(total),
            "{name}"
        );
    }
}

#[test]
fn theRemainingCountIsTheLastIndexMinusTheIndexOfTheKey() {
    // The 3 index bytes of XMSSMT-SHA2_20/4_256 hold indices past the last index 2^20 - 1, and
    // the unsigned subtraction of the C code wraps for them.
    let (_, key) = responseKeyPair(&XMSSMT::sha2Height20Layers4);
    let scheme = &XMSSMT::sha2Height20Layers4;
    for (index, remaining) in [
        (0u64, 1_048_575u64),
        (1, 1_048_574),
        (1_048_575, 0),
        (1_048_576, 18_446_744_073_709_551_615),
        (16_777_215, 18_446_744_073_693_822_976),
    ] {
        let secretKey = withIndex(key.bytes(), 3, index);
        assert_eq!(
            scheme.remainingSignatureCount(secretKey.bytes()),
            Ok(remaining),
            "index {index}"
        );
        assert_eq!(scheme.totalSignatureCount(secretKey.bytes()), Ok(1_048_575));
    }
}
