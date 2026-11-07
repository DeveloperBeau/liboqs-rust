//! Tests of the replicated signature programs: a small correct scheme passes each of them, and
//! each kind of defect fails with its message.

use OQSNativeAlgorithmTests::{
    FuzzRandom, SignatureCorrectnessTest, SignatureFuzzTest, SignatureMemoryTest,
};
use OQSNativeDomain::{InputLength, RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, SignatureDescription};
use OQSNativeSHA2::SHA256;
use std::sync::atomic::{AtomicUsize, Ordering};

/// How a small scheme goes wrong.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    none,
    failsEveryKeyPair,
    failsAfterTheFirstKeyPair,
    failsEverySignature,
    rejectsEverySignature,
    acceptsEverySignature,
    checksHalfTheSignature,
    rejectsEveryContextSignature,
    acceptsEveryContextSignature,
    refusesTheEmptyContext,
    acceptsALongContext,
    acceptsAContextWithoutSupport,
    acceptsWrongLengths,
    reportsAnotherLength,
}

const strongDescription: SignatureDescription = SignatureDescription {
    name: "Tag-Strong",
    algorithmVersion: "test",
    claimedNISTLevel: 1,
    isEUFCMASecure: true,
    isSUFCMASecure: true,
    supportsContext: true,
    publicKeyLength: 16,
    secretKeyLength: 16,
    signatureLength: 32,
};

const weakDescription: SignatureDescription = SignatureDescription {
    name: "Tag-Weak",
    isSUFCMASecure: false,
    supportsContext: false,
    ..strongDescription
};

const slowDescription: SignatureDescription = SignatureDescription {
    name: "SLH_DSA-Tag",
    ..strongDescription
};

/// A scheme whose key is 16 random bytes and whose signature is the SHA-256 of the key, the
/// context and the message, with checked input lengths.
struct TagScheme {
    description: &'static SignatureDescription,
    fault: Fault,
    keyPairCount: AtomicUsize,
    contextSignatureCount: AtomicUsize,
}

impl TagScheme {
    fn new(description: &'static SignatureDescription, fault: Fault) -> Self {
        TagScheme {
            description,
            fault,
            keyPairCount: AtomicUsize::new(0),
            contextSignatureCount: AtomicUsize::new(0),
        }
    }

    fn tag(key: &[u8], context: &[u8], message: &[u8]) -> Vec<u8> {
        let mut hash = SHA256::new();
        hash.absorb(key);
        hash.absorb(&(context.len() as u64).to_le_bytes());
        hash.absorb(context);
        hash.absorb(message);
        hash.finalize().to_vec()
    }

    fn signed(
        &self,
        message: &[u8],
        context: &[u8],
        secretKey: &[u8],
    ) -> Result<Vec<u8>, OQSError> {
        let secretKey = match self.fault {
            Fault::acceptsWrongLengths => secretKey,
            Fault::reportsAnotherLength if secretKey.len() != 16 => {
                return Err(OQSError::invalidLength {
                    expected: 15,
                    actual: secretKey.len(),
                });
            }
            _ => InputLength::checked(secretKey, 16)?,
        };
        if self.fault == Fault::failsEverySignature {
            return Err(OQSError::operationFailed);
        }
        Ok(Self::tag(secretKey, context, message))
    }

    fn isValid(&self, signature: &[u8], message: &[u8], context: &[u8], publicKey: &[u8]) -> bool {
        let checkedLength = match self.fault {
            Fault::acceptsEverySignature => return true,
            Fault::rejectsEverySignature => return false,
            Fault::checksHalfTheSignature => 16,
            _ => 32,
        };
        publicKey.len() == 16
            && signature.len() == 32
            && Self::tag(publicKey, context, message)[..checkedLength] == signature[..checkedLength]
    }
}

impl Signing for TagScheme {
    fn description(&self) -> &'static SignatureDescription {
        self.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let count = self.keyPairCount.fetch_add(1, Ordering::SeqCst);
        match self.fault {
            Fault::failsEveryKeyPair => return Err(OQSError::operationFailed),
            Fault::failsAfterTheFirstKeyPair if count > 0 => return Err(OQSError::operationFailed),
            _ => {}
        }
        let mut key = [0u8; 16];
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
        _: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        self.signed(message, &[], secretKey)
    }

    fn signWithContext(
        &self,
        message: &[u8],
        context: &[u8],
        secretKey: &[u8],
        _: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        self.contextSignatureCount.fetch_add(1, Ordering::SeqCst);
        let refusal = match self.fault {
            Fault::refusesTheEmptyContext if context.is_empty() => Some(OQSError::operationFailed),
            Fault::acceptsALongContext | Fault::acceptsAContextWithoutSupport => None,
            _ if !self.description.supportsContext && !context.is_empty() => {
                Some(OQSError::contextNotSupported)
            }
            _ if context.len() > 255 => Some(OQSError::contextTooLong),
            _ => None,
        };
        match refusal {
            Some(error) => Err(error),
            None => self.signed(message, context, secretKey),
        }
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        self.isValid(signature, message, &[], publicKey)
    }

    fn isValidSignatureWithContext(
        &self,
        signature: &[u8],
        message: &[u8],
        context: &[u8],
        publicKey: &[u8],
    ) -> bool {
        match self.fault {
            Fault::rejectsEveryContextSignature => false,
            Fault::acceptsEveryContextSignature => true,
            _ => {
                (self.description.supportsContext || context.is_empty())
                    && self.isValid(signature, message, context, publicKey)
            }
        }
    }
}

fn correctness(description: &'static SignatureDescription, fault: Fault) -> Result<(), String> {
    SignatureCorrectnessTest::run(
        &TagScheme::new(description, fault),
        &mut FuzzRandom::seeded(7),
    )
}

#[test]
fn correctnessTestPassesACorrectSchemeWithAndWithoutContextSupport() {
    for description in [&strongDescription, &weakDescription, &slowDescription] {
        assert_eq!(
            correctness(description, Fault::none),
            Ok(()),
            "{}",
            description.name
        );
    }
}

#[test]
fn correctnessTestSignsUnderEachContextLengthAndStepsThroughThemByAPrimeForSLHDSA() {
    let contextSignatureCount = |description: &'static SignatureDescription| {
        let scheme = TagScheme::new(description, Fault::none);
        assert_eq!(
            SignatureCorrectnessTest::run(&scheme, &mut FuzzRandom::seeded(8)),
            Ok(())
        );
        scheme.contextSignatureCount.load(Ordering::SeqCst)
    };
    // The lengths 0 to 255, the refused 256 bytes and the empty context.
    assert_eq!(contextSignatureCount(&strongDescription), 258);
    // The lengths 0, 61, 122, 183, 244 and 255, the refused 256 bytes and the empty context.
    assert_eq!(contextSignatureCount(&slowDescription), 8);
    // The refused byte and the empty context.
    assert_eq!(contextSignatureCount(&weakDescription), 2);
}

#[test]
fn correctnessTestReportsEachFailingStep() {
    assert_eq!(
        correctness(&strongDescription, Fault::failsEveryKeyPair),
        Err("Tag-Strong: the key pair failed: the operation failed".to_string())
    );
    assert_eq!(
        correctness(&strongDescription, Fault::failsEverySignature),
        Err("Tag-Strong: the signature failed: the operation failed".to_string())
    );
    assert_eq!(
        correctness(&strongDescription, Fault::rejectsEverySignature),
        Err("Tag-Strong: the signature does not verify".to_string())
    );
    assert_eq!(
        correctness(&strongDescription, Fault::refusesTheEmptyContext),
        Err(
            "Tag-Strong: the signature with a 0-byte context failed: the operation failed"
                .to_string()
        )
    );
    assert_eq!(
        correctness(&weakDescription, Fault::refusesTheEmptyContext),
        Err(
            "Tag-Weak: the signature with the empty context failed: the operation failed"
                .to_string()
        )
    );
    assert_eq!(
        correctness(&strongDescription, Fault::rejectsEveryContextSignature),
        Err("Tag-Strong: the signature with a 0-byte context does not verify".to_string())
    );
    assert_eq!(
        correctness(&weakDescription, Fault::rejectsEveryContextSignature),
        Err("Tag-Weak: the signature with the empty context does not verify".to_string())
    );
    assert_eq!(
        correctness(&strongDescription, Fault::acceptsALongContext),
        Err("Tag-Strong: a 256-byte context must be refused".to_string())
    );
    assert_eq!(
        correctness(&weakDescription, Fault::acceptsAContextWithoutSupport),
        Err("Tag-Weak: a context must be refused without context support".to_string())
    );
}

// The bit indices are those of a separate model of the random bytes that the test draws:
// SplitMix64 from seed 7, 8 bytes for each flip, read as a little-endian `u64`.
#[test]
fn correctnessTestReportsTheFirstAcceptedBitFlip() {
    assert_eq!(
        correctness(&strongDescription, Fault::acceptsEverySignature),
        Err("Tag-Strong: the verification accepts the message with bit 280 flipped".to_string())
    );
    assert_eq!(
        correctness(&strongDescription, Fault::acceptsEveryContextSignature),
        Err("Tag-Strong: the verification accepts the message with bit 246 flipped".to_string())
    );
    assert_eq!(
        correctness(&weakDescription, Fault::acceptsEveryContextSignature),
        Err("Tag-Weak: the verification accepts the message with bit 688 flipped".to_string())
    );
}

// The fault checks the first 16 bytes only, so the first flip in bits 128 to 255 is accepted.
#[test]
fn correctnessTestFlipsTheSignatureOnlyForAnSUFCMAScheme() {
    assert_eq!(
        correctness(&strongDescription, Fault::checksHalfTheSignature),
        Err("Tag-Strong: the verification accepts the signature with bit 191 flipped".to_string())
    );
    assert_eq!(
        correctness(&weakDescription, Fault::checksHalfTheSignature),
        Ok(())
    );
}

fn fuzz(fault: Fault, caseCount: u64) -> Result<(), String> {
    SignatureFuzzTest::run(
        &TagScheme::new(&strongDescription, fault),
        0x5EED,
        caseCount,
    )
}

#[test]
fn fuzzTestPassesACorrectScheme() {
    assert_eq!(fuzz(Fault::none, 40), Ok(()));
    assert_eq!(
        SignatureFuzzTest::run(&TagScheme::new(&weakDescription, Fault::none), 3, 40),
        Ok(())
    );
}

#[test]
fn fuzzTestReportsEachFailingStepWithTheCaseAndTheSeed() {
    assert_eq!(
        fuzz(Fault::failsAfterTheFirstKeyPair, 3),
        Err(
            "Tag-Strong, fuzz case 1 of seed 0x5eed: the key pair failed: the operation failed"
                .to_string()
        )
    );
    assert_eq!(
        fuzz(Fault::failsEverySignature, 3),
        Err(
            "Tag-Strong, fuzz case 0 of seed 0x5eed: the signature failed: the operation failed"
                .to_string()
        )
    );
    assert_eq!(
        fuzz(Fault::rejectsEverySignature, 3),
        Err("Tag-Strong, fuzz case 0 of seed 0x5eed: the signature does not verify".to_string())
    );
    assert_eq!(
        fuzz(Fault::acceptsEverySignature, 3),
        Err("Tag-Strong, fuzz case 0 of seed 0x5eed: the verification accepts a hostile signature of 32 bytes".to_string())
    );
    assert_eq!(
        fuzz(Fault::acceptsWrongLengths, 3),
        Err("Tag-Strong, fuzz case 0 of seed 0x5eed: a secret key of a wrong length gives Ok(()), not the length error".to_string())
    );
    assert_eq!(
        fuzz(Fault::reportsAnotherLength, 3),
        Err("Tag-Strong, fuzz case 0 of seed 0x5eed: a secret key of a wrong length gives Err(invalidLength { expected: 15, actual: 17 }), not the length error".to_string())
    );
}

#[test]
fn memoryTestRoundTripsTheValuesThroughFilesAndRemovesThem() {
    let folder = std::env::temp_dir().join(format!(
        "oqs-native-signature-memory-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let run = |fault: Fault, folder: &std::path::Path| {
        SignatureMemoryTest::run(
            &TagScheme::new(&strongDescription, fault),
            &mut FuzzRandom::seeded(4),
            folder,
        )
    };
    assert_eq!(run(Fault::none, &folder), Ok(()));
    assert_eq!(std::fs::read_dir(&folder).expect("the folder").count(), 0);
    assert_eq!(
        run(Fault::failsEveryKeyPair, &folder),
        Err("Tag-Strong: the key pair failed: the operation failed".to_string())
    );
    assert_eq!(
        run(Fault::failsEverySignature, &folder),
        Err("Tag-Strong: the signature failed: the operation failed".to_string())
    );
    assert_eq!(
        run(Fault::rejectsEverySignature, &folder),
        Err("Tag-Strong: the signature does not verify".to_string())
    );
    let message = run(Fault::none, &folder.join("missing")).expect_err("a missing folder fails");
    assert!(message.starts_with("Tag-Strong: write pk: "), "{message}");
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
