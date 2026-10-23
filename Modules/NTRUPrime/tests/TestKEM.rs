//! The correctness test of liboqs `tests/test_kem.c`, and the rejection paths of sntrup761.
//!
//! Decapsulation decrypts the short `r`, encrypts it again with the public key and the hash of
//! the public key of the secret key, and compares the two ciphertexts, the folded byte
//! differences gathered with an or. A difference gives the session key with the prefix 0 of
//! the rejection value `rho` of the secret key, `Hash_prefix(0, Hash_prefix(3, rho) || c)`, and
//! else the session key with the prefix 1 of the encoded `r`. Decryption also replaces an `r`
//! that does not have the weight `w` by a fixed short polynomial. A ciphertext with such an `r`
//! needs the internal encryption, so its test is in `NTRUPrime.rs`.

use OQSNativeAlgorithmTests::KEMCorrectnessTest;
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeNTRUPrime::NTRUPrime;
use OQSNativeSHA2::SHA512;

const mechanism: &NTRUPrime = &NTRUPrime::sntrup761;

/// The lengths of `sntrup761.c`: a small polynomial, a public key and a rounded polynomial.
const smallLength: usize = 191;
const publicKeyLength: usize = 1158;
const roundedLength: usize = 1007;

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

/// A random source that gives the bytes of the NIST DRBG and records each request.
struct RecordingRandom {
    source: NISTKATRandom,
    requests: Vec<Vec<u8>>,
}

impl RecordingRandom {
    fn new(seed: u8) -> Self {
        RecordingRandom {
            source: random(seed),
            requests: Vec::new(),
        }
    }

    fn requestLengths(&self) -> Vec<usize> {
        self.requests.iter().map(Vec::len).collect()
    }
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.source.fillRandomBytes(bytes);
        self.requests.push(bytes.to_vec());
    }
}

/// The first 32 bytes of `SHA-512(prefix || parts)`, `Hash_prefix`.
fn prefixedHash(prefix: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = SHA512::new();
    hash.absorb(&[prefix]);
    for part in parts {
        hash.absorb(part);
    }
    hash.finalize()[..32].to_vec()
}

/// The rejection secret of a ciphertext: the session key of the prefix 0 and of `rho`.
fn rejectionSecret(secretKey: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let rho = &secretKey[2 * smallLength + publicKeyLength..][..smallLength];
    prefixedHash(0, &[&prefixedHash(3, &[rho]), ciphertext])
}

/// The encoded short polynomial of the random bytes of an encapsulation: 761 little-endian
/// words, of which the first 286 get the marks 0 or 2 and the others the mark 1, sorted, each
/// mark minus 1 a coefficient, four coefficients plus 1 in each byte, `Short_fromlist` and
/// `Small_encode`.
fn encodedShort(request: &[u8]) -> Vec<u8> {
    let mut words: Vec<u32> = request
        .chunks_exact(4)
        .enumerate()
        .map(|(index, word)| {
            let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            if index < 286 {
                word & !1
            } else {
                (word & !2) | 1
            }
        })
        .collect();
    words.sort_unstable();
    let coefficients: Vec<u8> = words.iter().map(|word| (word & 3) as u8).collect();
    coefficients
        .chunks(4)
        .map(|group| {
            group
                .iter()
                .enumerate()
                .map(|(index, value)| value << (2 * index))
                .sum()
        })
        .collect()
}

fn decapsulated(ciphertext: &[u8], secretKey: &[u8]) -> Vec<u8> {
    mechanism
        .decapsulate(ciphertext, secretKey)
        .expect("no error")
        .bytes()
        .to_vec()
}

/// A key pair and an encapsulation, with the random bytes of the encapsulation.
struct Exchange {
    publicKey: Vec<u8>,
    secretKey: Vec<u8>,
    ciphertext: Vec<u8>,
    sharedSecret: Vec<u8>,
    request: Vec<u8>,
}

fn exchange(seed: u8) -> Exchange {
    let keyPair = mechanism
        .generateKeyPair(&mut random(seed))
        .expect("key pair");
    let mut recording = RecordingRandom::new(seed.wrapping_add(100));
    let encapsulation = mechanism
        .encapsulate(&keyPair.publicKey, &mut recording)
        .expect("encapsulation");
    Exchange {
        publicKey: keyPair.publicKey,
        secretKey: keyPair.secretKey.bytes().to_vec(),
        ciphertext: encapsulation.ciphertext,
        sharedSecret: encapsulation.sharedSecret.bytes().to_vec(),
        request: recording.requests[0].clone(),
    }
}

#[test]
fn testKEMPassesForSntrup761() {
    assert_eq!(KEMCorrectnessTest::run(mechanism, &mut random(0)), Ok(()));
}

#[test]
fn encapsulationAndDecapsulationAgreeOnTheSharedSecret() {
    let description = mechanism.description();
    for seed in 0..4 {
        let mut random = random(seed);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        assert_eq!(keyPair.publicKey.len(), description.publicKeyLength);
        assert_eq!(keyPair.secretKey.bytes().len(), description.secretKeyLength);
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        assert_eq!(encapsulation.ciphertext.len(), description.ciphertextLength);
        assert_eq!(encapsulation.sharedSecret.bytes().len(), 32);
        assert_eq!(
            decapsulated(&encapsulation.ciphertext, keyPair.secretKey.bytes()),
            encapsulation.sharedSecret.bytes(),
            "seed {seed}"
        );
    }
}

#[test]
fn eachOperationDrawsTheRequestsOfTheCCode() {
    // `KeyGen` draws 761 words for g and 761 words for f, each in one request of 3044 bytes,
    // and `crypto_kem_sntrup761_keypair` then draws the 191 bytes of rho. The candidate g of
    // these seeds has an inverse, so there is no second candidate.
    for seed in 1..4 {
        let mut keyRandom = RecordingRandom::new(seed);
        let keyPair = mechanism.generateKeyPair(&mut keyRandom).expect("key pair");
        assert_eq!(
            keyRandom.requestLengths(),
            vec![3044, 3044, 191],
            "seed {seed}"
        );
        let secretKey = keyPair.secretKey.bytes();
        assert_eq!(
            &secretKey[2 * smallLength + publicKeyLength..][..smallLength],
            keyRandom.requests[2].as_slice(),
            "seed {seed}"
        );
        // `crypto_kem_sntrup761_enc` draws the 761 words of r in one request.
        let mut encapsulationRandom = RecordingRandom::new(seed + 10);
        mechanism
            .encapsulate(&keyPair.publicKey, &mut encapsulationRandom)
            .expect("encapsulation");
        assert_eq!(encapsulationRandom.requestLengths(), vec![3044]);
    }
    // A public key of a wrong length draws no random bytes.
    let mut unused = RecordingRandom::new(20);
    assert!(
        mechanism
            .encapsulate(&[0u8; publicKeyLength - 1], &mut unused)
            .is_err()
    );
    assert!(unused.requests.is_empty());
}

#[test]
fn theSecretKeyHoldsThePublicKeyRhoAndTheHashOfThePublicKey() {
    let exchange = exchange(5);
    let secretKey = &exchange.secretKey;
    let start = 2 * smallLength;
    assert_eq!(
        &secretKey[start..start + publicKeyLength],
        exchange.publicKey.as_slice()
    );
    assert_eq!(
        &secretKey[secretKey.len() - 32..],
        prefixedHash(4, &[&exchange.publicKey]).as_slice()
    );
    // f is short: each byte of its packing holds four values from 0 to 2, so no pair of bits
    // is 3, and 286 values are not 1.
    let packedF = &secretKey[..smallLength];
    let values: Vec<u8> = (0..761)
        .map(|index| (packedF[index / 4] >> (2 * (index % 4))) & 3)
        .collect();
    assert!(values.iter().all(|value| *value <= 2));
    assert_eq!(values.iter().filter(|value| **value != 1).count(), 286);
}

#[test]
fn theCiphertextConfirmsRAndTheSharedSecretIsTheSessionKeyOfR() {
    for seed in 6..9 {
        let exchange = exchange(seed);
        let encoded = encodedShort(&exchange.request);
        let inputHash = prefixedHash(3, &[&encoded]);
        let publicKeyHash = prefixedHash(4, &[&exchange.publicKey]);
        assert_eq!(
            &exchange.ciphertext[roundedLength..],
            prefixedHash(2, &[&inputHash, &publicKeyHash]).as_slice(),
            "seed {seed}"
        );
        assert_eq!(
            exchange.sharedSecret,
            prefixedHash(1, &[&inputHash, &exchange.ciphertext]),
            "seed {seed}"
        );
    }
}

#[test]
fn aChangedCiphertextGivesTheRejectionSecret() {
    let exchange = exchange(9);
    // The first and a middle byte of the rounded part, and the first and the last byte of the
    // confirmation.
    for (position, bit) in [
        (0, 0),
        (roundedLength / 2, 5),
        (roundedLength, 0),
        (roundedLength + 31, 7),
    ] {
        let mut changed = exchange.ciphertext.clone();
        changed[position] ^= 1 << bit;
        let secret = decapsulated(&changed, &exchange.secretKey);
        assert_eq!(
            secret,
            rejectionSecret(&exchange.secretKey, &changed),
            "byte {position}, bit {bit}"
        );
        assert_ne!(secret, exchange.sharedSecret, "byte {position}");
    }
    // The unchanged ciphertext gives the shared secret, not the rejection secret.
    let secret = decapsulated(&exchange.ciphertext, &exchange.secretKey);
    assert_eq!(secret, exchange.sharedSecret);
    assert_ne!(
        secret,
        rejectionSecret(&exchange.secretKey, &exchange.ciphertext)
    );
}

#[test]
fn aCiphertextWithTheSameBitChangedInTwoBytesIsRejected() {
    // The decryption of these ciphertexts gives the r of the original: the confirmation is not
    // decrypted, and the low bit of byte 0 changes a coefficient of c by 3, which 3 f c does
    // not see modulo 3. So the encryption again differs from each ciphertext in exactly the two
    // bytes, whose differences cancel in an exclusive or, and the comparison must gather them
    // with an or.
    let exchange = exchange(10);
    for (first, second) in [(roundedLength, roundedLength + 1), (0, roundedLength + 8)] {
        let mut changed = exchange.ciphertext.clone();
        changed[first] ^= 0x01;
        changed[second] ^= 0x01;
        assert_eq!(
            decapsulated(&changed, &exchange.secretKey),
            rejectionSecret(&exchange.secretKey, &changed),
            "bytes {first} and {second}"
        );
    }
}

#[test]
fn eachPartOfTheSecretKeyHasItsRoleInDecapsulation() {
    let exchange = exchange(11);
    let changedAt = |position: usize| {
        let mut secretKey = exchange.secretKey.clone();
        secretKey[position] ^= 0x01;
        secretKey
    };
    // rho changes only the rejection secret.
    let rhoPosition = 2 * smallLength + publicKeyLength;
    let otherRho = changedAt(rhoPosition);
    assert_eq!(
        decapsulated(&exchange.ciphertext, &otherRho),
        exchange.sharedSecret
    );
    let mut changed = exchange.ciphertext.clone();
    changed[3] ^= 0x10;
    let rejected = decapsulated(&changed, &otherRho);
    assert_eq!(rejected, rejectionSecret(&otherRho, &changed));
    assert_ne!(rejected, rejectionSecret(&exchange.secretKey, &changed));
    // f, 1 / g, the public key and its hash give another encryption, so a rejection.
    for position in [
        0,
        smallLength + 1,
        2 * smallLength + 5,
        exchange.secretKey.len() - 1,
    ] {
        let secretKey = changedAt(position);
        assert_eq!(
            decapsulated(&exchange.ciphertext, &secretKey),
            rejectionSecret(&secretKey, &exchange.ciphertext),
            "byte {position}"
        );
    }
}

#[test]
fn anyKeyOfTheRightLengthGivesAResultAsTheCCodeGivesIt() {
    let description = mechanism.description();
    // The zero secret key gives an encryption whose confirmation is not the zero bytes of the
    // zero ciphertext, so the result is the rejection secret of rho = 0.
    let secretKey = vec![0u8; description.secretKeyLength];
    let ciphertext = vec![0u8; description.ciphertextLength];
    assert_eq!(
        decapsulated(&ciphertext, &secretKey),
        prefixedHash(0, &[&prefixedHash(3, &[&[0u8; smallLength]]), &ciphertext])
    );
    let encapsulation = mechanism
        .encapsulate(&vec![0xFFu8; description.publicKeyLength], &mut random(12))
        .expect("no key check");
    assert_eq!(encapsulation.ciphertext.len(), description.ciphertextLength);
}

#[test]
fn eachInputOfAWrongLengthIsALengthError() {
    let description = mechanism.description();
    let lengthError =
        |expected: usize, actual: usize| Err(OQSError::invalidLength { expected, actual });
    let publicKeyBytes = description.publicKeyLength;
    let ciphertextBytes = description.ciphertextLength;
    let secretKeyBytes = description.secretKeyLength;
    for actual in [publicKeyBytes - 1, publicKeyBytes + 1, 0] {
        assert_eq!(
            mechanism
                .encapsulate(&vec![0u8; actual], &mut random(13))
                .map(|_| ()),
            lengthError(publicKeyBytes, actual)
        );
    }
    let secretKey = vec![0u8; secretKeyBytes];
    for actual in [ciphertextBytes - 1, ciphertextBytes + 1, 0] {
        assert_eq!(
            mechanism
                .decapsulate(&vec![0u8; actual], &secretKey)
                .map(|_| ()),
            lengthError(ciphertextBytes, actual)
        );
    }
    let ciphertext = vec![0u8; ciphertextBytes];
    for actual in [secretKeyBytes - 2, secretKeyBytes + 1] {
        assert_eq!(
            mechanism
                .decapsulate(&ciphertext, &vec![0u8; actual])
                .map(|_| ()),
            lengthError(secretKeyBytes, actual)
        );
    }
    // The ciphertext is checked first.
    assert_eq!(
        mechanism
            .decapsulate(&ciphertext[1..], &secretKey[1..])
            .map(|_| ()),
        lengthError(ciphertextBytes, ciphertextBytes - 1)
    );
}

#[test]
fn theSeededFormsAreNotSupportedAsInLiboqs() {
    let description = mechanism.description();
    assert_eq!(
        (
            description.keyPairSeedLength,
            description.encapsulationSeedLength
        ),
        (0, 0)
    );
    assert_eq!(
        mechanism.generateKeyPairFromSeed(&[0u8; 64]).map(|_| ()),
        Err(OQSError::seedNotSupported)
    );
    assert_eq!(
        mechanism
            .encapsulateWithSeed(&vec![0u8; description.publicKeyLength], &[0u8; 32])
            .map(|_| ()),
        Err(OQSError::seedNotSupported)
    );
}

#[test]
fn theSetHasTheFactsOfItsCFile() {
    // `kem_ntruprime_sntrup761.c`.
    let description = mechanism.description();
    assert_eq!(description.name, "sntrup761");
    assert_eq!(
        description.algorithmVersion,
        "v1.9.2026.01.20 via https://github.com/openssh/openssh-portable/blob/master/sntrup761.c"
    );
    assert_eq!(description.claimedNISTLevel, 2);
    assert!(description.isINDCCASecure);
    assert_eq!(description.sharedSecretLength, 32);
}
