//! The correctness test of liboqs `tests/test_sig_stfl.c` through
//! `StatefulSignatureCorrectnessTest`, and the tests of XMSS and XMSS^MT: the key pairs, the key
//! after each signature, the edges of the index and of the identifier, the store of the advanced
//! key, the counts and each rejection path.
//!
//! The known answers come from the C library of the oracle. A C program made the key pair of each
//! response file with the NIST generator seeded with the bytes 0 to 47, signed sequences of
//! messages, and signed the edge cases below, and printed the SHA-256 of each signature and of
//! each key. Valgrind reported no access outside the buffers of the C code for any of these
//! cases. The program is not part of the repository.

use OQSNativeAlgorithmTests::{
    FuzzRandom, ResponseFile, StatefulSignatureCorrectnessTest, StatefulTreeHeight, TestVectorFiles,
};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{OQSError, SecretBytes};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSHA2::SHA256;
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(&SHA256::hash(bytes))
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
        "7434fea2e6c3b44d1c2abdc5942c6260ebe019af5cbe1caac68ecc631bb4e8a0",
        "ae3a2ea965aa13f2f4ca23f22ecbf196ca745f4ff543c1a8a81700373e084a7b",
    ),
    (
        "XMSS-SHAKE256_10_192",
        "403a3785b54d7633226772b7ddf4edc8baffe47ef2fcf49455eeb75fe4e53d1c",
        "e712e495be4c16ac84b8adfba0478b050347fe7131c18de58c6d09bbfb2a3fce",
    ),
    (
        "XMSS-SHAKE256_10_256",
        "a34696ef84db2dd196321f7c5085b38d896fc69d8b84a203d74b998a1f6a1d28",
        "c0a516e75bbdf1a272b37a5a7c0141168df350567a8fd5b2121e3bb8dac9abce",
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
            (digest(&publicKey), digest(secretKey.bytes()))
        }
    };
    assert_eq!(
        (
            digest(&keyPair.publicKey),
            digest(keyPair.secretKey.bytes())
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
/// SHA-256(chain || signature || saved key) of each checkpoint with the C library. Each signature
/// is checked against the public key, and the saved key is the key in memory.
fn checkSequence(
    scheme: &dyn StatefulSigning,
    count: usize,
    checkpoints: &[(usize, u64, &str)],
    invalidSignatures: &[usize],
) {
    let name = scheme.description().name;
    let (publicKey, mut secretKey) = responseKeyPair(scheme);
    let mut chain = [0u8; 32];
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
        let mut hash = SHA256::new();
        hash.absorb(&chain);
        hash.absorb(&signature);
        hash.absorb(saved);
        chain = hash.finalize();
        if let Some((after, remaining, expected)) =
            checkpoint.next_if(|(after, _, _)| *after == k + 1)
        {
            assert_eq!(hex(&chain), *expected, "{name}, after {after} signatures");
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
                "a3c0973561c6fc8c151ec59d8c152417dc596c08fac1999258fd509d9ef83e55",
            ),
            (
                2,
                1021,
                "1732e75b8e6e6eefc43e7e43e7ba506084ffe6b7deae53ab7ca6501dfb99cfdb",
            ),
            (
                3,
                1020,
                "abe822c69ca285c18eb0572f3200997c7043b4ee7dfc2a2c9da7166298a21231",
            ),
            (
                4,
                1019,
                "23157ef371e41744e8fb838028ff303eacac6969027aad756812af6e119a4d34",
            ),
            (
                5,
                1018,
                "66b1e6f953bc46ba79af660dea005ea5c6a0f6140ee5dcdaab7f647419cc7df1",
            ),
            (
                6,
                1017,
                "5ad66fad31787619bb8cd9fcc745b2c7aeacff4121d82074e325cf46f3bb0373",
            ),
            (
                7,
                1016,
                "16ca6c93611a3c2944cee5701031b8146d6647484d8496a2aeb84911573308ea",
            ),
            (
                8,
                1015,
                "0363065cd5953330dced56ee55fc19e9a5812a33f8d417bd35c61958485802d1",
            ),
            (
                16,
                1007,
                "0c09524d70e575afdd6441be1f992cd9bde6d9bfbbc302996278cd0a9f2b0ffd",
            ),
            (
                31,
                992,
                "e96ec164090cba72b7cdd8eecb17a6b2f89d0ce8399efd69c463e352d452e63e",
            ),
            (
                32,
                991,
                "aebf3447c71a5d14960f93c729f208bb5a8c52f8df3b30533051a3884dcfe43f",
            ),
            (
                33,
                990,
                "ebd608d1c85444f60c6bcda90be729f95678e24060a562bfd1ade5510dc540ca",
            ),
            (
                40,
                983,
                "a54f84fe60def1795fcc6787cc3c12a6ddef8d586a6a3cc3923d11d9bf956a80",
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
                "cbdf6fe0c5acefa2ffc1f0a37f8b4c4adee99ae9e8cebd16a558625d76db2a90",
            ),
            (
                2,
                1048573,
                "b6ef195cfb1fb51b26cc8f590bc1741b584e55502db3916c208b0edab1bd17da",
            ),
            (
                3,
                1048572,
                "a8655fd11600eb3674e3fed1b51e41426e45d14762091bfd0fa4bf94c130c746",
            ),
            (
                4,
                1048571,
                "a8d41172b1f206e9e3711612735e39046ee720276c25e0571ec47ab1eba307d0",
            ),
            (
                5,
                1048570,
                "2a6b16b3c139dfe78bf1175d64a348ffb459429f2cf0afbee9512e43c36bd3e1",
            ),
            (
                6,
                1048569,
                "30a44bb7a54884b1c0ec4df808ff03bfdfc2378d40924d0db86cd63bd6266e1b",
            ),
            (
                7,
                1048568,
                "6eea4d4b214b721aa7e404811a205404553ef339f189cc8aa61342c5512f0c4a",
            ),
            (
                8,
                1048567,
                "2438e0a23dd3f623e139564e8e2fc02c9474068c187d1f93b164e750697e8a76",
            ),
            (
                16,
                1048559,
                "3b7ae143febee8ea2c4c40fabe078fe765ed2dac2d62a8d2da389e415aeb49fc",
            ),
            (
                31,
                1048544,
                "36c99d080ffe9480e8e802ab6d21bbc4760b8d161803e0cca82d93c76930797c",
            ),
            (
                32,
                1048543,
                "d4cf66e86f3de7780428deeefda39d131f8129580c3d98fd462dd966d8bf5420",
            ),
            (
                33,
                1048542,
                "bf6792d62bcc648730ebd9e598e815ae606661ab8892b84d08831332e7288df6",
            ),
            (
                40,
                1048535,
                "5dc3fc0a10db58d09727974efe66eb2f7f8f1047496146f2e73fdd41cba3b1ac",
            ),
            (
                64,
                1048511,
                "0afd0389fc148cdaa1abc309e5528c1b3ed688fcee1e763c65ecc055b043745e",
            ),
            (
                70,
                1048505,
                "c45c7675b8b100bf9f917797f9fbb8266edf727de7a518bdd38c17cdbfd1e63e",
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
                "3f6340f334c32509054c83f8af12e532c6e1cba8cfaa57a4ffb3d197755bec65",
            ),
            (
                2,
                1099511627773,
                "76e226fdf7cdeadde858f1b4cddcee16543a82327c10812f5d011e46328bf0ff",
            ),
            (
                3,
                1099511627772,
                "60510a75b940a78c5306a78036e8e3b1a64ce51dbf9251e735bf67a9213586a4",
            ),
            (
                4,
                1099511627771,
                "7a3140df38f8121e5de0ca797d8289a8f5c663c6ebc218f8fbe162e14702ca39",
            ),
            (
                5,
                1099511627770,
                "6ff01b7d7d34417cfe346e3a47192652e8047c89d0e124c54776b53c4e5e34ab",
            ),
            (
                6,
                1099511627769,
                "30df8a64331674c5c71e59fe546fdbebb5cbc0d7b166f3bcee0dc8f6d2915565",
            ),
            (
                7,
                1099511627768,
                "8ad224cfad558ce140c2ba6a0e0db906ec2c8d447cc8c060bdbc1b0fbf25f866",
            ),
            (
                8,
                1099511627767,
                "84d144f565acae302abb54186fd386e32e0710e81bc4db6dcf9c8b1953dffed5",
            ),
            (
                16,
                1099511627759,
                "82dfe86912adec8498cbab9a6b4accdd501716b86f91f537e4a54ca9101e68c3",
            ),
            (
                31,
                1099511627744,
                "27a0a459a1a83ef99f2ec960b0434210d73d6e43fe7a836dccf2dad8e61c2097",
            ),
            (
                32,
                1099511627743,
                "ae116cb94f418fdd1ad646663f0a332e24cc5680f5dcdb3533d3e3c20b960808",
            ),
            (
                33,
                1099511627742,
                "fb7f107adfe4dcd06de7e4a72638d43b2f46423f242e99d0053f2389a97ad94d",
            ),
            (
                40,
                1099511627735,
                "2b4cdd701edbfc184c57e08a751c6a0ae96c898b9b06283c6b0adeb7a2b89854",
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
                "a621461ea8ca0440088fc18e122bddbec0c4525dde2f19eaa733076dedb104a4",
            ),
            (
                1023,
                0,
                "a27455c3647c10d2343a18bc8fcb9a79495a006c3467c809e5652767e3f08201",
            ),
            (
                1024,
                u64::MAX,
                "befcd6edb4f7bdc8a7eef499c25efb9ef4f70ea0e4b9daa365eae7e967562d45",
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
                "c0b2f5efdc606180b948b08639d1172be57c41afead9fae37728cf47373605a7",
            ),
            (
                1023,
                1047552,
                "62ecb798d3568415b774da4bd58b9773d331b74878c085b0158eb9aff737a70c",
            ),
            (
                1024,
                1047551,
                "1130e571829b37cb4be106a759648115ce1b314744822bcf8387cb1fbcc6a717",
            ),
            (
                1100,
                1047475,
                "0999f134bd30dde7903e0c1c7a4a7ed7fd7e11c4147eae61fec9f4f34488e485",
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
        .map(|signature| digest(&signature));
    if first.is_ok() {
        assert_eq!(
            store.saved.last().map(Vec::as_slice),
            Some(secretKey.bytes())
        );
    }
    let firstKey = digest(secretKey.bytes());
    let remaining = scheme.remainingSignatureCount(secretKey.bytes());
    let total = scheme.totalSignatureCount(secretKey.bytes());
    let second = scheme
        .sign(&message, &mut secretKey, &mut store)
        .map(|signature| digest(&signature));
    let secondKey = digest(secretKey.bytes());
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
        Ok("92e2d9d62426388c44443554c7f96703432567b2257696da0bd306f75af25e1e")
    );
    assert_eq!(
        outcome.firstKey,
        "0d654f77fe2594247d76d14500a4cca49e22f19740b3662eea89a58fae3947a3"
    );
    assert_eq!(outcome.remaining, Ok(u64::MAX));
    assert_eq!(outcome.total, Ok(1023));
    // Past the last index the signature fails, and the key is zero after its identifier.
    assert_eq!(outcome.second, Err(OQSError::keyExhausted));
    assert_eq!(
        outcome.secondKey,
        "64fd85e028c7c27dc0ce5404d79cd25ae788cf9e1d18fb55a69b5027f49101f5"
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
            "64fd85e028c7c27dc0ce5404d79cd25ae788cf9e1d18fb55a69b5027f49101f5"
        );
        assert_eq!(outcome.remaining, Ok(1023));
        assert_eq!(
            outcome.second.as_deref(),
            Ok("517b289c66156de9e1d161730ae28ccbbffac1bebcebbf83b0898d7378b2ff27")
        );
        assert_eq!(
            outcome.secondKey,
            "b125c7568908b59338f8b784c9fc14ad4efd9e26b0c52fc3dc3e35f630b09e7d"
        );
    }
}

#[test]
fn anIndexThatTheStateDoesNotFollowSignsAsTheCLibraryDoes() {
    let (_, key) = responseKeyPair(&XMSS::sha2Height10Bits256);
    let outcome = signTwice(&XMSS::sha2Height10Bits256, withIndex(key.bytes(), 4, 500));
    assert_eq!(
        outcome.first.as_deref(),
        Ok("45782c048f636d103fe2bc829e45107035fad48b107e1fa12b6ec2d51e02a153")
    );
    assert_eq!(
        outcome.firstKey,
        "30c5859a262a1eac59baa2c6d80f5eda5d0b3835732565c7ec7ff3a466a8d61d"
    );
    assert_eq!(outcome.remaining, Ok(522));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("2aa41dfe80d8346a437c8d534f932e40fe4a5ee96316af93c1551bce53fb8349")
    );
    assert_eq!(
        outcome.secondKey,
        "3f82338d76026bfb7eda338cd3417f13c7a9f8f3afcad56097c9ba10d5b687f7"
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
    let signature = "51d0d336bf8d49d520a16cbe0b9936fefe02b1e659c18ffc67a329503240aaab";
    assert_eq!(outcome.first.as_deref(), Ok(signature));
    assert_eq!(
        outcome.firstKey,
        "100083ddd976ce03f60a31ea1e5309cf2b530eb27c1969a7ab1ae8bc97d711f4"
    );
    assert_eq!((outcome.remaining, outcome.total), (Ok(1022), Ok(1023)));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("7d002217bfb95f366a3358f8bcc8070d2e27f1d3a5f192ca0cb78f06579aebd3")
    );
    assert_eq!(
        outcome.secondKey,
        "de0b7a30812ce53b4d7b7ffd3f689b71ac530f9b243f565f13fc57254c9d479e"
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
        "0ae57156f4920d0bb9d4b2566aed57c34cfe84f3661729fc26112c10f19e6fd6"
    );
    assert_eq!((outcome.remaining, outcome.total), (Ok(1022), Ok(1023)));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("7d002217bfb95f366a3358f8bcc8070d2e27f1d3a5f192ca0cb78f06579aebd3")
    );
    assert_eq!(
        outcome.secondKey,
        "30b479c25796cf442f611c375ca7ac49aa204c9be05c4f1f97250979a5fdc1b9"
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
        Ok("80c96a6fa7239c359385da2a7385c4029c7d1451f35d53fde68f19ca5b3fd16f")
    );
    assert_eq!(
        outcome.firstKey,
        "18f69fb9a9b7a79ebcd1180a915ba40e6441b55f94e77901efc5b59caadccc70"
    );
    assert_eq!(outcome.remaining, Ok(u64::MAX));
    assert_eq!(outcome.second, Err(OQSError::keyExhausted));
    let wipedKey = "e63cf2fa968a2f0741e400680ef3e752b92946d31c753f3d3f3f239bf46c35cb";
    assert_eq!(outcome.secondKey, wipedKey);
    let outcome = signTwice(scheme, withIndex(key.bytes(), 3, 1 << 20));
    assert_eq!(outcome.first, Err(OQSError::keyExhausted));
    assert_eq!(outcome.firstKey, wipedKey);
    assert_eq!(outcome.remaining, Ok(1048575));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("b45b6c6f442255d69f9f95ccbf9c96ec792294403af3f86bac39fb8c0953947a")
    );
    assert_eq!(
        outcome.secondKey,
        "3ae561ea6d2591266ba22143a3dbbc3e4fa18b79e56a6571a123cfd87c52017a"
    );
    // The ends of one, two and three trees at once: the next trees of the fresh key are empty,
    // and at the end of three trees the count of the updates goes below zero.
    for (index, signature, firstKey, remaining, second, secondKey) in [
        (
            31,
            "03079f063fd9defc9c3889e993a6c3ed86c79c02a91d0f9829be1204701b315e",
            "0b14d5d775047b6050cdcdbf1c2d9ba21749a9d8301b3af60934b63392ce86b3",
            1048543,
            "c9535569f70a6a821e25508a00ac184eb3607e32f8b02f01243d9d879308bc05",
            "9a1c63ea16fcd8f81be2d0ccf201b54917e02541717fd62eb6d19a8550d3d2d0",
        ),
        (
            1023,
            "1882b97658f8084c06182e114ce79234f4fc6b14b1a17c49c1bf01936e3d6516",
            "88a7acd4dd1d6d121fb55a3b81111d15b7244c66606562cde8c49c03f1676942",
            1047551,
            "c5586944f8999cd84f2840d6f6ac99452ab79432db1efa42d32029447eb88503",
            "25ab09dd18bc5f182d2973ea2b7b967f7b1113fd6a9370fc12810e7472dc8cfd",
        ),
        (
            32767,
            "9808cee427692faa947aecc59e7148ce6b1296ae4a2ce510d8eced0574dc905a",
            "098089b01fcfd2760adf151c759022ce5a33c3cab01ee2df34c30ea02220aa5f",
            1015807,
            "97b9af92cb0913ca18ccdeca1441801b095b9b99ac7f45d3325be0abb532bea3",
            "ddcaf78a7f99af50790231afea1f9234edbff36abbb57606276b092fc5170153",
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
            "45dc798486ee14634453d405804a81505f8a5fea9c14f7f9db8de2106592666a",
            "7d66f885a4c1e805cc37484f7f8e2ca302e3b127dbcbdbfd2bf3dbfe1bc0d6b5",
            1099511595007,
            "3ea2e5782e356b4ab53faecffee2ef9fc77e5c532892a7eb7466be0b6e928ddb",
            "3db4ff7b7b7087f27bed5b6650d884e174d8d563bee0294e937c6b3ac3ed9a37",
        ),
        (
            (1 << 40) - 1,
            "688e474e38f77108da6dd723bc96b3588574b2e55a9c3eb338bcdf967473e161",
            "e20f6edfe5fbba6da192981a610ba5a0902ba558d2cfa3131cc1a69adf60a5a1",
            1099511627775,
            "4c82c94763aa4121cd43a5c4cdd4a16955e1f11eecd7e6651e5a61dfbbaa93ea",
            "185744c86bbdaab8e928115713aec3abcf2a08c2b8a3e63df00f424ef3682ef2",
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
        Ok("12e0c47f1e7dbbe9694168f627a1af40aff2ea5614f6460c7f89d18c161359db")
    );
    assert_eq!(
        outcome.firstKey,
        "c5875810a6052e36dfea4d1b9e31ca28bcb416e2c0ccb07ead31ed8a5a2fd96a"
    );
    assert_eq!(outcome.remaining, Ok(1_148_417_904_979_476_473));
    assert_eq!(
        outcome.second.as_deref(),
        Ok("7cedb6a2e6a5dc308db1040fddc19c661ee6d9830e657c43a6321ada205a08fe")
    );
    assert_eq!(
        outcome.secondKey,
        "48160b48c5099ea679c2b512a3c58e875b3fea64dffeb8865ad4e05f08b5c866"
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
        digest(&bytes),
        "6d852d137b65c17c65b7073c971e9b3d48fa8d1089f2b44df3ccc1b7de13168c"
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
