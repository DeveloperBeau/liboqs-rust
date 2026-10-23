//! The correctness test of liboqs `tests/test_kem.c`, with its rejection cases of ML-KEM, and
//! the rejection paths of FIPS 203 and of Kyber, for each parameter set.

use OQSNativeAlgorithmTests::KEMCorrectnessTest;
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeMLKEM::{Kyber, MLKEM};
use OQSNativeSHA3::{SHA3256, SHAKE256};

const parameterSets: [&MLKEM; 3] = [&MLKEM::mlkem512, &MLKEM::mlkem768, &MLKEM::mlkem1024];

const kyberSets: [&Kyber; 3] = [&Kyber::kyber512, &Kyber::kyber768, &Kyber::kyber1024];

/// `SHAKE256(z || input)`, 32 bytes: the rejection secret of ML-KEM over a ciphertext, and of
/// Kyber over the hash of a ciphertext.
fn rejectionSecret(secretKey: &[u8], input: &[u8]) -> [u8; 32] {
    let mut secret = [0u8; 32];
    let mut sponge = SHAKE256::new();
    sponge.absorb(&secretKey[secretKey.len() - 32..]);
    sponge.absorb(input);
    sponge.finalize().squeeze(&mut secret);
    secret
}

#[test]
fn testKEMPassesForEveryParameterSet() {
    let mechanisms: [&dyn KeyEncapsulating; 6] = [
        &MLKEM::mlkem512,
        &MLKEM::mlkem768,
        &MLKEM::mlkem1024,
        &Kyber::kyber512,
        &Kyber::kyber768,
        &Kyber::kyber1024,
    ];
    for (index, mechanism) in mechanisms.into_iter().enumerate() {
        assert_eq!(
            KEMCorrectnessTest::run(mechanism, &mut random(index as u8)),
            Ok(())
        );
    }
}

#[test]
fn mlkemRejectionCasesOfTestKEMGiveTheSHAKEOfZAndTheCiphertext() {
    for mechanism in parameterSets {
        let mut random = random(10);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        // Scenario 1 of `mlkem_rej_testcase`: a changed first byte of the secret key.
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        secretKey[0] = secretKey[0].wrapping_add(1);
        let secret = mechanism
            .decapsulate(&encapsulation.ciphertext, &secretKey)
            .expect("decapsulation");
        assert_eq!(
            secret.bytes(),
            rejectionSecret(&secretKey, &encapsulation.ciphertext)
        );
        // Scenario 2: a changed first byte of the ciphertext.
        let mut ciphertext = encapsulation.ciphertext.clone();
        ciphertext[0] = ciphertext[0].wrapping_add(1);
        let secret = mechanism
            .decapsulate(&ciphertext, keyPair.secretKey.bytes())
            .expect("decapsulation");
        assert_eq!(
            secret.bytes(),
            rejectionSecret(keyPair.secretKey.bytes(), &ciphertext)
        );
    }
}

#[test]
fn kyberRejectsWithTheSHAKEOfZAndTheCiphertextHash() {
    for mechanism in kyberSets {
        let mut random = random(11);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let mut ciphertext = encapsulation.ciphertext.clone();
        ciphertext[3] ^= 0x40;
        let secret = mechanism
            .decapsulate(&ciphertext, keyPair.secretKey.bytes())
            .expect("decapsulation");
        assert_eq!(
            secret.bytes(),
            rejectionSecret(keyPair.secretKey.bytes(), &SHA3256::hash(&ciphertext))
        );
        // Kyber does not check the public key hash of the secret key. A wrong hash changes the
        // derived key, so the re-encryption differs and the decapsulation rejects.
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        let hashPosition = secretKey.len() - 64;
        secretKey[hashPosition] ^= 1;
        let secret = mechanism
            .decapsulate(&encapsulation.ciphertext, &secretKey)
            .expect("Kyber has no hash check");
        assert_eq!(
            secret.bytes(),
            rejectionSecret(&secretKey, &SHA3256::hash(&encapsulation.ciphertext))
        );
    }
}

#[test]
fn kyberHasNoSeededFormsAndChecksNoKey() {
    for mechanism in kyberSets {
        assert_eq!(
            mechanism.generateKeyPairFromSeed(&[0u8; 64]).map(|_| ()),
            Err(OQSError::seedNotSupported)
        );
        let keyPair = mechanism
            .generateKeyPair(&mut random(12))
            .expect("key pair");
        assert_eq!(
            mechanism
                .encapsulateWithSeed(&keyPair.publicKey, &[0u8; 32])
                .map(|_| ()),
            Err(OQSError::seedNotSupported)
        );
        // A coefficient above the modulus is not refused.
        let mut publicKey = keyPair.publicKey.clone();
        publicKey[0] = 0xFF;
        publicKey[1] |= 0x0F;
        assert!(mechanism.encapsulate(&publicKey, &mut random(13)).is_ok());
        assert_eq!(
            mechanism
                .encapsulate(&publicKey[1..], &mut random(13))
                .map(|_| ()),
            Err(OQSError::invalidLength {
                expected: publicKey.len(),
                actual: publicKey.len() - 1
            })
        );
    }
}

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

#[test]
fn encapsulationAndDecapsulationAgreeOnTheSharedSecret() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        for seed in 0..5 {
            let mut random = random(seed);
            let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
            assert_eq!(keyPair.publicKey.len(), description.publicKeyLength);
            assert_eq!(keyPair.secretKey.bytes().len(), description.secretKeyLength);
            let encapsulation = mechanism
                .encapsulate(&keyPair.publicKey, &mut random)
                .expect("encapsulation");
            assert_eq!(encapsulation.ciphertext.len(), description.ciphertextLength);
            let recovered = mechanism
                .decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())
                .expect("decapsulation");
            assert_eq!(
                recovered.bytes(),
                encapsulation.sharedSecret.bytes(),
                "{}",
                description.name
            );
        }
    }
}

#[test]
fn aChangedCiphertextGivesTheImplicitRejectionSecret() {
    for mechanism in parameterSets {
        let mut random = random(9);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let secretKey = keyPair.secretKey.bytes();
        for position in [
            0,
            encapsulation.ciphertext.len() / 2,
            encapsulation.ciphertext.len() - 1,
        ] {
            let mut changed = encapsulation.ciphertext.clone();
            changed[position] ^= 0x01;
            let rejected = mechanism
                .decapsulate(&changed, secretKey)
                .expect("no error");
            assert_ne!(rejected.bytes(), encapsulation.sharedSecret.bytes());
            // FIPS 203, Algorithm 18: the rejection secret is J(z || c), with z the last 32
            // bytes of the secret key.
            let mut expected = [0u8; 32];
            let mut sponge = SHAKE256::new();
            sponge.absorb(&secretKey[secretKey.len() - 32..]);
            sponge.absorb(&changed);
            sponge.finalize().squeeze(&mut expected);
            assert_eq!(rejected.bytes(), expected);
        }
    }
}

#[test]
fn theSecretKeyHoldsThePublicKeyItsHashAndTheRejectionSeed() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let mut seed = [0u8; 64];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let keyPair = mechanism.generateKeyPairFromSeed(&seed).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        let pkeLength = secretKey.len() - description.publicKeyLength - 64;
        assert_eq!(
            &secretKey[pkeLength..pkeLength + description.publicKeyLength],
            keyPair.publicKey.as_slice()
        );
        assert_eq!(
            &secretKey[secretKey.len() - 64..secretKey.len() - 32],
            SHA3256::hash(&keyPair.publicKey).as_slice()
        );
        assert_eq!(&secretKey[secretKey.len() - 32..], &seed[32..]);
    }
}

#[test]
fn seededFormsAreTheRandomFormsWithTheSameBytes() {
    for mechanism in parameterSets {
        let mut random = random(3);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let mut seedRandom = self::random(3);
        let mut seed = [0u8; 64];
        seedRandom.fillRandomBytes(&mut seed);
        let seeded = mechanism
            .generateKeyPairFromSeed(&seed)
            .expect("seeded key pair");
        assert_eq!(seeded.publicKey, keyPair.publicKey);
        assert_eq!(seeded.secretKey.bytes(), keyPair.secretKey.bytes());
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let mut message = [0u8; 32];
        seedRandom.fillRandomBytes(&mut message);
        let seededEncapsulation = mechanism
            .encapsulateWithSeed(&keyPair.publicKey, &message)
            .expect("seeded encapsulation");
        assert_eq!(seededEncapsulation.ciphertext, encapsulation.ciphertext);
        assert_eq!(
            seededEncapsulation.sharedSecret.bytes(),
            encapsulation.sharedSecret.bytes()
        );
        let otherSeed = mechanism
            .generateKeyPairFromSeed(&[1u8; 64])
            .expect("key pair");
        assert_ne!(otherSeed.publicKey, keyPair.publicKey);
    }
}

#[test]
fn eachInputOfAWrongLengthIsALengthError() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let keyPair = mechanism.generateKeyPair(&mut random(1)).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random(2))
            .expect("encapsulation");
        let lengthError =
            |expected: usize, actual: usize| Err(OQSError::invalidLength { expected, actual });
        let shortKey = &keyPair.publicKey[1..];
        assert_eq!(
            mechanism.encapsulate(shortKey, &mut random(2)).map(|_| ()),
            lengthError(description.publicKeyLength, description.publicKeyLength - 1)
        );
        assert_eq!(
            mechanism
                .encapsulateWithSeed(shortKey, &[0u8; 32])
                .map(|_| ()),
            lengthError(description.publicKeyLength, description.publicKeyLength - 1)
        );
        assert_eq!(
            mechanism
                .encapsulateWithSeed(&keyPair.publicKey, &[0u8; 31])
                .map(|_| ()),
            lengthError(32, 31)
        );
        assert_eq!(
            mechanism.generateKeyPairFromSeed(&[0u8; 65]).map(|_| ()),
            lengthError(64, 65)
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
            )
        );
        assert_eq!(
            mechanism
                .decapsulate(&encapsulation.ciphertext, &keyPair.secretKey.bytes()[2..])
                .map(|_| ()),
            lengthError(description.secretKeyLength, description.secretKeyLength - 2)
        );
    }
}

#[test]
fn aPublicKeyWithACoefficientAboveTheModulusIsRejected() {
    for mechanism in parameterSets {
        let keyPair = mechanism.generateKeyPair(&mut random(4)).expect("key pair");
        let mut publicKey = keyPair.publicKey.clone();
        // The first coefficient becomes 4095.
        publicKey[0] = 0xFF;
        publicKey[1] |= 0x0F;
        assert_eq!(
            mechanism
                .encapsulate(&publicKey, &mut random(5))
                .map(|_| ()),
            Err(OQSError::operationFailed)
        );
        // The last coefficient of the encoded vector becomes 3329, the first value too large.
        let mut publicKey = keyPair.publicKey.clone();
        let end = publicKey.len() - 32;
        publicKey[end - 2] = (publicKey[end - 2] & 0x0F) | 0x10;
        publicKey[end - 1] = 0xD0;
        assert_eq!(
            mechanism
                .encapsulateWithSeed(&publicKey, &[0u8; 32])
                .map(|_| ()),
            Err(OQSError::operationFailed)
        );
        // A change in the seed part is not checked.
        let mut publicKey = keyPair.publicKey.clone();
        let last = publicKey.len() - 1;
        publicKey[last] ^= 1;
        assert!(mechanism.encapsulate(&publicKey, &mut random(5)).is_ok());
    }
}

#[test]
fn aSecretKeyWithAWrongPublicKeyHashIsRejected() {
    for mechanism in parameterSets {
        let keyPair = mechanism.generateKeyPair(&mut random(6)).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random(7))
            .expect("encapsulation");
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        let hashPosition = secretKey.len() - 64;
        secretKey[hashPosition] ^= 1;
        assert_eq!(
            mechanism
                .decapsulate(&encapsulation.ciphertext, &secretKey)
                .map(|_| ()),
            Err(OQSError::operationFailed)
        );
        let mut secretKey = keyPair.secretKey.bytes().to_vec();
        let publicPartPosition = secretKey.len() - 64 - 32 - 1;
        secretKey[publicPartPosition] ^= 1;
        assert_eq!(
            mechanism
                .decapsulate(&encapsulation.ciphertext, &secretKey)
                .map(|_| ()),
            Err(OQSError::operationFailed)
        );
    }
}

#[test]
fn aCiphertextWithTheSameBitChangedInTwoBytesIsRejected() {
    let mechanisms: [(&dyn KeyEncapsulating, bool); 6] = [
        (&MLKEM::mlkem512, false),
        (&MLKEM::mlkem768, false),
        (&MLKEM::mlkem1024, false),
        (&Kyber::kyber512, true),
        (&Kyber::kyber768, true),
        (&Kyber::kyber1024, true),
    ];
    for (mechanism, isKyber) in mechanisms {
        let mut random = random(14);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        // Bytes 0 and 55 start a compressed coefficient for 10 and 11 bits alike, so the
        // change is small, the decryption gives the same message, and the re-encryption
        // differs from the ciphertext in exactly these two bytes. Their differences cancel in
        // an exclusive or, so the comparison must gather them with an or.
        let mut changed = encapsulation.ciphertext.clone();
        changed[0] ^= 0x01;
        changed[55] ^= 0x01;
        let secretKey = keyPair.secretKey.bytes();
        let rejected = mechanism
            .decapsulate(&changed, secretKey)
            .expect("no error");
        let expected = if isKyber {
            rejectionSecret(secretKey, &SHA3256::hash(&changed))
        } else {
            rejectionSecret(secretKey, &changed)
        };
        assert_eq!(
            rejected.bytes(),
            expected,
            "{}",
            mechanism.description().name
        );
    }
}
