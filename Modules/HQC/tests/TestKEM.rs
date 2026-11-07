//! The correctness test of liboqs `tests/test_kem.c` for each parameter set, and the rejection
//! paths of HQC: the rejection secret `J` of a changed ciphertext or of a changed secret key, the
//! random requests of the C code, and the length errors.

use OQSNativeAlgorithmTests::KEMCorrectnessTest;
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{KEMDescription, OQSError};
use OQSNativeHQC::HQC;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSHA3::{SHA3256, SHA3512, SHAKE256};

const parameterSets: [&HQC; 3] = [&HQC::hqc1, &HQC::hqc3, &HQC::hqc5];

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

/// A random source that records the length of each request.
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

/// The length `k` of a message, the security level in bytes.
fn messageLength(description: &KEMDescription) -> usize {
    description.secretKeyLength - description.publicKeyLength - 64
}

/// `H`: SHA3-256 of the public key and the domain byte 1.
fn publicKeyHash(publicKey: &[u8]) -> [u8; 32] {
    let mut hash = SHA3256::new();
    hash.absorb(publicKey);
    hash.absorb(&[1]);
    hash.finalize()
}

/// `J`: SHA3-256 of `H` of the public key part of the secret key, `sigma`, the ciphertext and
/// the domain byte 3. The secret key is the public key, the 32-byte decryption key, `sigma` and
/// the 32-byte seed.
fn rejectionSecret(description: &KEMDescription, secretKey: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let publicKey = &secretKey[..description.publicKeyLength];
    let sigma = &secretKey[description.publicKeyLength + 32..secretKey.len() - 32];
    let mut hash = SHA3256::new();
    hash.absorb(&publicKeyHash(publicKey));
    hash.absorb(sigma);
    hash.absorb(ciphertext);
    hash.absorb(&[3]);
    hash.finalize()
}

/// The length in bytes of the vector `u` at the start of a ciphertext.
fn vectorByteCount(description: &KEMDescription) -> usize {
    description.publicKeyLength - 32
}

#[test]
fn testKEMPassesForEveryParameterSet() {
    for (index, mechanism) in parameterSets.into_iter().enumerate() {
        assert_eq!(
            KEMCorrectnessTest::run(mechanism, &mut random(index as u8)),
            Ok(()),
            "seed {index}"
        );
    }
}

#[test]
fn encapsulationAndDecapsulationAgreeOnTheSharedSecret() {
    for mechanism in parameterSets {
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
            let recovered = mechanism
                .decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())
                .expect("decapsulation");
            assert_eq!(
                recovered.bytes(),
                encapsulation.sharedSecret.bytes(),
                "{}, seed {seed}",
                description.name
            );
        }
    }
}

#[test]
fn aKeyPairDrawsOneRequestAndAnEncapsulationTwoAsTheCCode() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let label = format!("{}, seeds 1, 2 and 3", description.name);
        let mut keyRandom = RecordingRandom::new(1);
        let keyPair = mechanism.generateKeyPair(&mut keyRandom).expect("key pair");
        assert_eq!(keyRandom.requestLengths(), vec![32], "{label}");
        let mut encapsulationRandom = RecordingRandom::new(2);
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut encapsulationRandom)
            .expect("encapsulation");
        // The message of `k` bytes and then the salt of 16 bytes.
        assert_eq!(
            encapsulationRandom.requestLengths(),
            vec![messageLength(description), 16],
            "{label}"
        );
        // The salt ends the ciphertext, and the shared secret is the first half of `G`.
        let (message, salt) = (
            &encapsulationRandom.requests[0],
            &encapsulationRandom.requests[1],
        );
        assert_eq!(
            &encapsulation.ciphertext[description.ciphertextLength - 16..],
            salt.as_slice(),
            "{label}"
        );
        let mut hash = SHA3512::new();
        hash.absorb(&publicKeyHash(&keyPair.publicKey));
        hash.absorb(message);
        hash.absorb(salt);
        hash.absorb(&[0]);
        assert_eq!(
            encapsulation.sharedSecret.bytes(),
            &hash.finalize()[..32],
            "{label}"
        );
        // A public key of a wrong length draws no random bytes.
        let mut unused = RecordingRandom::new(3);
        assert!(
            mechanism
                .encapsulate(&keyPair.publicKey[1..], &mut unused)
                .is_err(),
            "{label}"
        );
        assert!(unused.requests.is_empty(), "{label}");
    }
}

#[test]
fn theSecretKeyHoldsThePublicKeyTheDecryptionSeedSigmaAndTheKeySeed() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let label = format!("{}, seed 4", description.name);
        let mut recording = RecordingRandom::new(4);
        let keyPair = mechanism.generateKeyPair(&mut recording).expect("key pair");
        let seed = &recording.requests[0];
        let secretKey = keyPair.secretKey.bytes();
        let publicKeyLength = description.publicKeyLength;
        assert_eq!(
            &secretKey[..publicKeyLength],
            keyPair.publicKey.as_slice(),
            "{label}"
        );
        assert_eq!(
            &secretKey[secretKey.len() - 32..],
            seed.as_slice(),
            "{label}"
        );
        // The expander of the seed gives the PKE seed and then `sigma`, and `I` of the PKE seed
        // gives the decryption seed and the seed of `h`, which starts the public key.
        let mut expanded = vec![0u8; 32 + messageLength(description)];
        SHAKE256::hash(&[seed.as_slice(), &[1]].concat(), &mut expanded);
        assert_eq!(
            &secretKey[publicKeyLength + 32..secretKey.len() - 32],
            &expanded[32..],
            "{label}"
        );
        let seeds = SHA3512::hash(&[&expanded[..32], &[2]].concat());
        assert_eq!(
            &secretKey[publicKeyLength..publicKeyLength + 32],
            &seeds[..32],
            "{label}"
        );
        assert_eq!(&keyPair.publicKey[..32], &seeds[32..], "{label}");
    }
}

#[test]
fn aChangedCiphertextGivesTheRejectionSecretOfJ() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let label = format!("{}, seed 9", description.name);
        let mut random = random(9);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let secretKey = keyPair.secretKey.bytes();
        let vectorBytes = vectorByteCount(description);
        let length = encapsulation.ciphertext.len();
        // The first byte of `u`, the last byte of `u`, a bit of `u` above `n` in its last byte,
        // the first and the last byte of `v`, and the first and the last byte of the salt.
        for (position, bit) in [
            (0, 0x01),
            (vectorBytes - 1, 0x01),
            (vectorBytes - 1, 0x80),
            (vectorBytes, 0x01),
            (length - 17, 0x40),
            (length - 16, 0x01),
            (length - 1, 0x80),
        ] {
            let mut changed = encapsulation.ciphertext.clone();
            changed[position] ^= bit;
            let rejected = mechanism
                .decapsulate(&changed, secretKey)
                .expect("no error");
            assert_eq!(
                rejected.bytes(),
                rejectionSecret(description, secretKey, &changed),
                "{label}, byte {position}, bit {bit:#x}"
            );
            assert_ne!(
                rejected.bytes(),
                encapsulation.sharedSecret.bytes(),
                "{label}, byte {position}, bit {bit:#x}"
            );
        }
    }
}

#[test]
fn aCiphertextWithTheSameBitChangedInTwoBytesIsRejected() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let label = format!("{}, seed 14", description.name);
        let mut random = random(14);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let secretKey = keyPair.secretKey.bytes();
        let vectorBytes = vectorByteCount(description);
        // A small change of `u` or `v` leaves the message, so the re-encryption differs from
        // the ciphertext in exactly these two bytes. Their differences cancel in an exclusive
        // or, so the comparison must gather them with an or: two bytes of `u`, two bytes of `v`,
        // and one byte of each.
        for (first, second) in [
            (0, 1),
            (vectorBytes + 3, vectorBytes + 4),
            (5, vectorBytes + 7),
        ] {
            let mut changed = encapsulation.ciphertext.clone();
            changed[first] ^= 0x10;
            changed[second] ^= 0x10;
            let rejected = mechanism
                .decapsulate(&changed, secretKey)
                .expect("no error");
            assert_eq!(
                rejected.bytes(),
                rejectionSecret(description, secretKey, &changed),
                "{label}, bytes {first} and {second}"
            );
        }
    }
}

#[test]
fn eachPartOfTheSecretKeyHasItsRoleInDecapsulation() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let label = format!("{}, seed 21", description.name);
        let mut random = random(21);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let ciphertext = &encapsulation.ciphertext;
        let sharedSecret = encapsulation.sharedSecret.bytes();
        let publicKeyLength = description.publicKeyLength;
        let decapsulated = |secretKey: &[u8]| {
            mechanism
                .decapsulate(ciphertext, secretKey)
                .expect("no error")
                .bytes()
                .to_vec()
        };
        let changedAt = |position: usize| {
            let mut secretKey = keyPair.secretKey.bytes().to_vec();
            secretKey[position] ^= 0x01;
            secretKey
        };
        // The seed at the end is not used: the secret stays.
        let lastByte = description.secretKeyLength - 1;
        assert_eq!(
            decapsulated(&changedAt(lastByte)),
            sharedSecret,
            "{label}, the key seed"
        );
        // `sigma` is used only for a rejection: the secret stays.
        let sigmaKey = changedAt(publicKeyLength + 32);
        assert_eq!(decapsulated(&sigmaKey), sharedSecret, "{label}, sigma");
        // A changed decryption seed gives another `y`, the message is lost, and the rejection
        // secret has the `sigma` of the key.
        let decryptionKey = changedAt(publicKeyLength);
        assert_eq!(
            decapsulated(&decryptionKey),
            rejectionSecret(description, &decryptionKey, ciphertext),
            "{label}, the decryption seed"
        );
        // A changed public key part changes `H` and the re-encryption, which then differs.
        for position in [0, 32, publicKeyLength - 1] {
            let publicKeyPart = changedAt(position);
            assert_eq!(
                decapsulated(&publicKeyPart),
                rejectionSecret(description, &publicKeyPart, ciphertext),
                "{label}, byte {position}"
            );
        }
        // A changed `sigma` changes the rejection secret of a changed ciphertext.
        let mut changed = ciphertext.clone();
        changed[0] ^= 1;
        let original = mechanism
            .decapsulate(&changed, keyPair.secretKey.bytes())
            .expect("no error");
        let withOtherSigma = mechanism
            .decapsulate(&changed, &sigmaKey)
            .expect("no error");
        assert_ne!(original.bytes(), withOtherSigma.bytes(), "{label}");
        assert_eq!(
            withOtherSigma.bytes(),
            rejectionSecret(description, &sigmaKey, &changed),
            "{label}"
        );
    }
}

#[test]
fn hqcHasNoSeededForms() {
    for mechanism in parameterSets {
        let label = format!("{}, seed 12", mechanism.description().name);
        let keyPair = mechanism
            .generateKeyPair(&mut random(12))
            .expect("key pair");
        assert_eq!(
            mechanism.generateKeyPairFromSeed(&[0u8; 32]).map(|_| ()),
            Err(OQSError::seedNotSupported),
            "{label}"
        );
        assert_eq!(
            mechanism
                .encapsulateWithSeed(&keyPair.publicKey, &[0u8; 32])
                .map(|_| ()),
            Err(OQSError::seedNotSupported),
            "{label}"
        );
    }
}

#[test]
fn eachInputOfAWrongLengthIsALengthError() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let label = format!("{}, seeds 1 and 2", description.name);
        let keyPair = mechanism.generateKeyPair(&mut random(1)).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random(2))
            .expect("encapsulation");
        let lengthError =
            |expected: usize, actual: usize| Err(OQSError::invalidLength { expected, actual });
        assert_eq!(
            mechanism
                .encapsulate(&keyPair.publicKey[1..], &mut random(2))
                .map(|_| ()),
            lengthError(description.publicKeyLength, description.publicKeyLength - 1),
            "{label}"
        );
        let mut longKey = keyPair.publicKey.clone();
        longKey.push(0);
        assert_eq!(
            mechanism.encapsulate(&longKey, &mut random(2)).map(|_| ()),
            lengthError(description.publicKeyLength, description.publicKeyLength + 1),
            "{label}"
        );
        let mut longCiphertext = encapsulation.ciphertext.clone();
        longCiphertext.push(0);
        assert_eq!(
            mechanism
                .decapsulate(&longCiphertext, keyPair.secretKey.bytes())
                .map(|_| ()),
            lengthError(
                description.ciphertextLength,
                description.ciphertextLength + 1
            ),
            "{label}"
        );
        assert_eq!(
            mechanism
                .decapsulate(
                    &encapsulation.ciphertext[..description.ciphertextLength - 1],
                    keyPair.secretKey.bytes()
                )
                .map(|_| ()),
            lengthError(
                description.ciphertextLength,
                description.ciphertextLength - 1
            ),
            "{label}"
        );
        assert_eq!(
            mechanism
                .decapsulate(&encapsulation.ciphertext, &keyPair.secretKey.bytes()[2..])
                .map(|_| ()),
            lengthError(description.secretKeyLength, description.secretKeyLength - 2),
            "{label}"
        );
        // The ciphertext is checked before the secret key.
        assert_eq!(
            mechanism.decapsulate(&[], &[]).map(|_| ()),
            lengthError(description.ciphertextLength, 0),
            "{label}"
        );
    }
}
