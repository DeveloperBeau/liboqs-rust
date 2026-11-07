//! Tests of the replicated known-answer programs on small mechanisms and schemes whose output
//! the test can follow by hand. The parity tests run the same programs on the C algorithms and
//! compare the digests with the digests of liboqs.

use OQSNativeAlgorithmTests::{KEMKnownAnswerTest, SignatureKnownAnswerTest};
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating, Signing};
use OQSNativeEntities::{
    Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes, SignatureDescription,
};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSHA2::SHA256;

const countZeroSeed: &str = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";

fn upperHex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digits"))
        .collect()
}

/// How a small mechanism goes wrong, so that each failure path of the program runs.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    none,
    keyPairFails,
    wrongSecret,
}

const echoDescription: KEMDescription = KEMDescription {
    name: "ML-KEM-512",
    algorithmVersion: "test",
    claimedNISTLevel: 1,
    isINDCCASecure: false,
    publicKeyLength: 2,
    secretKeyLength: 2,
    ciphertextLength: 2,
    sharedSecretLength: 2,
    keyPairSeedLength: 0,
    encapsulationSeedLength: 0,
};

/// A mechanism whose key is two random bytes and whose ciphertext is the secret XOR the key.
struct EchoMechanism {
    fault: Fault,
}

impl KeyEncapsulating for EchoMechanism {
    fn description(&self) -> &'static KEMDescription {
        &echoDescription
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        if self.fault == Fault::keyPairFails {
            return Err(OQSError::operationFailed);
        }
        let mut key = [0u8; 2];
        random.fillRandomBytes(&mut key);
        Ok(KeyPair {
            publicKey: key.to_vec(),
            secretKey: SecretBytes::new(key.to_vec()),
        })
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        let mut secret = [0u8; 2];
        random.fillRandomBytes(&mut secret);
        Ok(Encapsulation {
            ciphertext: vec![secret[0] ^ publicKey[0], secret[1] ^ publicKey[1]],
            sharedSecret: SecretBytes::new(secret.to_vec()),
        })
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let flip = u8::from(self.fault == Fault::wrongSecret);
        Ok(SecretBytes::new(vec![
            ciphertext[0] ^ secretKey[0] ^ flip,
            ciphertext[1] ^ secretKey[1],
        ]))
    }
}

/// The text of count 0 of the echo mechanism, followed by hand from the NIST generator.
fn expectedEchoCountZero() -> String {
    let seed: [u8; 48] = hex(countZeroSeed).try_into().expect("48 bytes");
    let mut inner = NISTKATRandom::new(&seed, None);
    let mut key = [0u8; 2];
    inner.fillRandomBytes(&mut key);
    let mut secret = [0u8; 2];
    inner.fillRandomBytes(&mut secret);
    let ciphertext = [secret[0] ^ key[0], secret[1] ^ key[1]];
    format!(
        "count = 0\nseed = {countZeroSeed}\npk = {}\nsk = {}\nct = {}\nss = {}\n",
        upperHex(&key),
        upperHex(&key),
        upperHex(&ciphertext),
        upperHex(&secret)
    )
}

#[test]
fn kemSingleRunPrintsCountZeroInTheLayoutOfTheKEMProgram() {
    let text = KEMKnownAnswerTest::text(&EchoMechanism { fault: Fault::none }, false)
        .expect("a correct mechanism passes");
    assert_eq!(text, expectedEchoCountZero());
}

#[test]
fn kemAllRunPrintsEveryCountWithABlankLineBetweenCounts() {
    let text = KEMKnownAnswerTest::text(&EchoMechanism { fault: Fault::none }, true)
        .expect("a correct mechanism passes");
    assert!(text.starts_with(&expectedEchoCountZero()));
    assert_eq!(text.matches("count = ").count(), 100);
    assert_eq!(text.matches("\n\n").count(), 99);
    assert!(text.contains("\n\ncount = 99\n"));
    assert!(!text.ends_with("\n\n"));
}

#[test]
fn kemDigestIsTheSHA256OfTheText() {
    let mechanism = EchoMechanism { fault: Fault::none };
    let text = KEMKnownAnswerTest::text(&mechanism, false).expect("text");
    let expected: String = SHA256::hash(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(KEMKnownAnswerTest::digest(&mechanism, false), Ok(expected));
}

#[test]
fn kemRunFailsWhenDecapsulationDoesNotRecoverTheSecret() {
    let result = KEMKnownAnswerTest::text(
        &EchoMechanism {
            fault: Fault::wrongSecret,
        },
        false,
    );
    assert_eq!(
        result,
        Err("ML-KEM-512, count 0: the shared secrets are not equal".to_string())
    );
}

#[test]
fn kemRunStopsAtAFailedOperation() {
    let result = KEMKnownAnswerTest::digest(
        &EchoMechanism {
            fault: Fault::keyPairFails,
        },
        true,
    );
    assert_eq!(
        result,
        Err("ML-KEM-512, count 0: key pair: the operation failed".to_string())
    );
}

const tagDescription: SignatureDescription = SignatureDescription {
    name: "MAYO-1",
    algorithmVersion: "test",
    claimedNISTLevel: 1,
    isEUFCMASecure: false,
    isSUFCMASecure: false,
    supportsContext: false,
    publicKeyLength: 1,
    secretKeyLength: 1,
    signatureLength: 2,
};

const unknownFormDescription: SignatureDescription = SignatureDescription {
    name: "SLH_DSA_PURE_SHA2_128S",
    ..tagDescription
};

/// A scheme whose signature is a random byte and the key byte XOR the message length.
struct TagScheme {
    description: &'static SignatureDescription,
    isAccepting: bool,
}

impl Signing for TagScheme {
    fn description(&self) -> &'static SignatureDescription {
        self.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let mut key = [0u8; 1];
        random.fillRandomBytes(&mut key);
        Ok(KeyPair {
            publicKey: key.to_vec(),
            secretKey: SecretBytes::new(key.to_vec()),
        })
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        let mut salt = [0u8; 1];
        random.fillRandomBytes(&mut salt);
        Ok(vec![salt[0], secretKey[0] ^ message.len() as u8])
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        self.isAccepting && signature[1] == publicKey[0] ^ message.len() as u8
    }
}

#[test]
fn signatureSingleRunPrintsCountZeroInTheLayoutOfTheSignatureProgram() {
    let scheme = TagScheme {
        description: &tagDescription,
        isAccepting: true,
    };
    let text = SignatureKnownAnswerTest::text(&scheme, false).expect("a correct scheme passes");
    // The outer generator gives the seed and then the 33-byte message. The inner generator,
    // seeded with the seed, gives the key byte and then the salt byte.
    let mut outer = NISTKATRandom::new(&std::array::from_fn(|index| index as u8), None);
    let mut seed = [0u8; 48];
    outer.fillRandomBytes(&mut seed);
    let mut message = [0u8; 33];
    outer.fillRandomBytes(&mut message);
    let mut inner = NISTKATRandom::new(&seed, None);
    let mut key = [0u8; 1];
    inner.fillRandomBytes(&mut key);
    let mut salt = [0u8; 1];
    inner.fillRandomBytes(&mut salt);
    let signature = [salt[0], key[0] ^ 33];
    let mut signed = signature.to_vec();
    signed.extend_from_slice(&message);
    assert_eq!(
        text,
        format!(
            "count = 0\nseed = {countZeroSeed}\nmlen = 33\nmsg = {}\npk = {}\nsk = {}\nsmlen = 35\nsm = {}\n",
            upperHex(&message),
            upperHex(&key),
            upperHex(&key),
            upperHex(&signed)
        )
    );
}

#[test]
fn signatureAllRunGrowsTheMessageBy33BytesEachCount() {
    let scheme = TagScheme {
        description: &tagDescription,
        isAccepting: true,
    };
    let text = SignatureKnownAnswerTest::text(&scheme, true).expect("a correct scheme passes");
    assert_eq!(text.matches("count = ").count(), 100);
    assert!(text.contains("\nmlen = 3300\n"));
    assert!(text.contains("\nsmlen = 3302\n"));
    assert_eq!(text.matches("\n\n").count(), 99);
}

#[test]
fn signatureRunFailsWhenTheSignatureDoesNotVerify() {
    let scheme = TagScheme {
        description: &tagDescription,
        isAccepting: false,
    };
    assert_eq!(
        SignatureKnownAnswerTest::digest(&scheme, false),
        Err("MAYO-1, count 0: the signature does not verify".to_string())
    );
}

#[test]
fn signatureRunNeedsTheFormOfTheCProgram() {
    let scheme = TagScheme {
        description: &unknownFormDescription,
        isAccepting: true,
    };
    assert_eq!(
        SignatureKnownAnswerTest::text(&scheme, false),
        Err("SLH_DSA_PURE_SHA2_128S has no known-answer run in kat_sig".to_string())
    );
}
