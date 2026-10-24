//! Tests of the replicated KEM programs: a small correct mechanism
//! passes each of them, and each kind of defect fails with its message.

use OQSNativeAlgorithmTests::{FuzzRandom, KEMCorrectnessTest, KEMFuzzTest, KEMMemoryTest};
use OQSNativeDomain::{InputLength, KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};

/// How a small mechanism goes wrong.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    none,
    wrongSecret,
    acceptsEveryCiphertext,
    acceptsWrongLengths,
    reportsAnotherLength,
    failsAfterTheFirstKeyPair,
    acceptsASeedItDoesNotHave,
    refusesItsSeed,
}

const seededDescription: KEMDescription = KEMDescription {
    name: "Seeded-Echo",
    algorithmVersion: "test",
    claimedNISTLevel: 1,
    isINDCCASecure: false,
    publicKeyLength: 16,
    secretKeyLength: 16,
    ciphertextLength: 16,
    sharedSecretLength: 16,
    keyPairSeedLength: 16,
    encapsulationSeedLength: 16,
};

const unseededDescription: KEMDescription = KEMDescription {
    name: "Unseeded-Echo",
    keyPairSeedLength: 0,
    encapsulationSeedLength: 0,
    ..seededDescription
};

/// A mechanism whose key is 16 random bytes and whose ciphertext is the secret XOR the key,
/// with checked input lengths.
struct EchoMechanism {
    description: &'static KEMDescription,
    fault: Fault,
    keyPairCount: std::sync::atomic::AtomicUsize,
}

impl EchoMechanism {
    fn new(description: &'static KEMDescription, fault: Fault) -> Self {
        EchoMechanism {
            description,
            fault,
            keyPairCount: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn keyPairFrom(key: [u8; 16]) -> KeyPair {
        KeyPair {
            publicKey: key.to_vec(),
            secretKey: SecretBytes::new(key.to_vec()),
        }
    }

    fn encapsulationOf(publicKey: &[u8], secret: [u8; 16]) -> Encapsulation {
        Encapsulation {
            ciphertext: secret
                .iter()
                .zip(publicKey)
                .map(|(left, right)| left ^ right)
                .collect(),
            sharedSecret: SecretBytes::new(secret.to_vec()),
        }
    }

    fn checked<'input>(
        &self,
        input: &'input [u8],
        expected: usize,
    ) -> Result<&'input [u8], OQSError> {
        match self.fault {
            Fault::acceptsWrongLengths => Ok(input),
            Fault::reportsAnotherLength if input.len() != expected => {
                Err(OQSError::invalidLength {
                    expected: expected - 1,
                    actual: input.len(),
                })
            }
            _ => InputLength::checked(input, expected),
        }
    }
}

impl KeyEncapsulating for EchoMechanism {
    fn description(&self) -> &'static KEMDescription {
        self.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let count = self
            .keyPairCount
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fault == Fault::failsAfterTheFirstKeyPair && count > 0 {
            return Err(OQSError::operationFailed);
        }
        let mut key = [0u8; 16];
        random.fillRandomBytes(&mut key);
        Ok(Self::keyPairFrom(key))
    }

    fn generateKeyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, OQSError> {
        match (self.description.keyPairSeedLength, self.fault) {
            (0, Fault::acceptsASeedItDoesNotHave) => Ok(Self::keyPairFrom([0; 16])),
            (0, _) | (_, Fault::refusesItsSeed) => Err(OQSError::seedNotSupported),
            (length, _) => Ok(Self::keyPairFrom(
                InputLength::checked(seed, length)?
                    .try_into()
                    .expect("16 bytes"),
            )),
        }
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        let publicKey = self.checked(publicKey, 16)?;
        let mut secret = [0u8; 16];
        random.fillRandomBytes(&mut secret);
        Ok(Self::encapsulationOf(publicKey, secret))
    }

    fn encapsulateWithSeed(
        &self,
        publicKey: &[u8],
        seed: &[u8],
    ) -> Result<Encapsulation, OQSError> {
        if self.description.encapsulationSeedLength == 0 {
            return Err(OQSError::seedNotSupported);
        }
        let publicKey = InputLength::checked(publicKey, 16)?;
        let seed = InputLength::checked(seed, 16)?;
        Ok(Self::encapsulationOf(
            publicKey,
            seed.try_into().expect("16 bytes"),
        ))
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let ciphertext = self.checked(ciphertext, 16)?;
        let secretKey = self.checked(secretKey, 16)?;
        if self.fault == Fault::acceptsEveryCiphertext {
            return Ok(SecretBytes::new(secretKey.to_vec()));
        }
        let mut secret: Vec<u8> = ciphertext
            .iter()
            .zip(secretKey)
            .map(|(left, right)| left ^ right)
            .collect();
        if self.fault == Fault::wrongSecret && !secret.is_empty() {
            secret[0] ^= 1;
        }
        Ok(SecretBytes::new(secret))
    }
}

#[test]
fn correctnessTestPassesACorrectMechanismWithAndWithoutSeeds() {
    for description in [&seededDescription, &unseededDescription] {
        let mechanism = EchoMechanism::new(description, Fault::none);
        assert_eq!(
            KEMCorrectnessTest::run(&mechanism, &mut FuzzRandom::seeded(1)),
            Ok(()),
            "{}",
            description.name
        );
    }
}

#[test]
fn correctnessTestReportsEachDefect() {
    let run = |description: &'static KEMDescription, fault: Fault| {
        KEMCorrectnessTest::run(
            &EchoMechanism::new(description, fault),
            &mut FuzzRandom::seeded(2),
        )
    };
    assert_eq!(
        run(&seededDescription, Fault::wrongSecret),
        Err("Seeded-Echo: the shared secrets are not equal".to_string())
    );
    assert_eq!(
        run(&unseededDescription, Fault::acceptsASeedItDoesNotHave),
        Err("Unseeded-Echo: the seeded key pair must fail without a seed length".to_string())
    );
    assert_eq!(
        run(&seededDescription, Fault::refusesItsSeed),
        Err(
            "Seeded-Echo: the seeded key pair failed: the algorithm has no form of the operation that takes a seed"
                .to_string()
        )
    );
    assert_eq!(
        run(&seededDescription, Fault::failsAfterTheFirstKeyPair),
        Ok(()),
        "the seeded pass makes no random key pair"
    );
    // With an all-zero source the key, the secret and the ciphertext are zero, so the fault
    // gives the true secret, the key, for the honest ciphertext and for the random one too.
    let accepting = EchoMechanism::new(&seededDescription, Fault::acceptsEveryCiphertext);
    assert_eq!(
        KEMCorrectnessTest::runPass(&accepting, &mut FuzzRandom::fixed(0), false),
        Err("Seeded-Echo: decapsulation succeeded on wrong input".to_string())
    );
}

#[test]
fn fuzzTestPassesACorrectMechanism() {
    let mechanism = EchoMechanism::new(&seededDescription, Fault::none);
    assert_eq!(KEMFuzzTest::run(&mechanism, 0x5EED, 40), Ok(()));
}

#[test]
fn fuzzTestReportsAWrongSecretAndAWrongLengthCheck() {
    let wrongSecret = EchoMechanism::new(&seededDescription, Fault::wrongSecret);
    assert_eq!(
        KEMFuzzTest::run(&wrongSecret, 0x5EED, 40),
        Err(
            "Seeded-Echo, fuzz case 0 of seed 0x5eed: the shared secrets are not equal".to_string()
        )
    );
    let unchecked = EchoMechanism::new(&seededDescription, Fault::acceptsWrongLengths);
    let message = KEMFuzzTest::run(&unchecked, 0x5EED, 40).expect_err("the fault is found");
    assert!(
        message.starts_with(
            "Seeded-Echo, fuzz case 0 of seed 0x5eed: a ciphertext of a wrong length gives Ok(())"
        ),
        "{message}"
    );
    let reporting = EchoMechanism::new(&seededDescription, Fault::reportsAnotherLength);
    assert_eq!(
        KEMFuzzTest::run(&reporting, 0x5EED, 3),
        Err("Seeded-Echo, fuzz case 0 of seed 0x5eed: a ciphertext of a wrong length gives Err(invalidLength { expected: 15, actual: 17 }), not the length error".to_string())
    );
    let failing = EchoMechanism::new(&seededDescription, Fault::failsAfterTheFirstKeyPair);
    assert_eq!(
        KEMFuzzTest::run(&failing, 1, 3),
        Err(
            "Seeded-Echo, fuzz case 1 of seed 0x1: the key pair failed: the operation failed"
                .to_string()
        )
    );
}

#[test]
fn memoryTestRoundTripsTheValuesThroughFilesAndRemovesThem() {
    let folder = std::env::temp_dir().join(format!("oqs-native-kem-memory-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let mechanism = EchoMechanism::new(&seededDescription, Fault::none);
    assert_eq!(
        KEMMemoryTest::run(&mechanism, &mut FuzzRandom::seeded(4), &folder),
        Ok(())
    );
    assert_eq!(std::fs::read_dir(&folder).expect("the folder").count(), 0);
    let wrongSecret = EchoMechanism::new(&seededDescription, Fault::wrongSecret);
    assert_eq!(
        KEMMemoryTest::run(&wrongSecret, &mut FuzzRandom::seeded(4), &folder),
        Err("Seeded-Echo: the shared secrets are not equal".to_string())
    );
    let missingFolder = folder.join("missing");
    let message = KEMMemoryTest::run(&mechanism, &mut FuzzRandom::seeded(4), &missingFolder)
        .expect_err("a missing folder fails");
    assert!(message.starts_with("Seeded-Echo: write pk: "), "{message}");
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
