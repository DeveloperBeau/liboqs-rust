use crate::{ResponseFile, SignatureCorrectnessTest};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// The correctness program of liboqs for stateful signature schemes, `tests/test_sig_stfl.c`, on
/// a Rust scheme.
///
/// The C program runs its parts in this order, and so does the test:
///
/// 1. `sig_stfl_test_correctness`: a key pair, the signature of a random message of 100 bytes,
///    its verification with the public key and with the stored copy of the public key, and the
///    bit flips of `test_sig_stfl_bitflip`.
/// 2. `test_invalid_sig`, for a scheme whose name holds `XMSS`: two signatures that the
///    verification must refuse.
/// 3. `sig_stfl_test_secret_key`: a key pair, its counts, and the saved secret key. The C program
///    saves the serialized key in a file, reads it back and restores a key from it. The test
///    saves keys through a `KeyStatePersisting` store. A signature comes back with exactly one
///    saved key, the key in memory. A key reloaded from the saved bytes signs on, and a refused
///    save releases no signature.
/// 4. `sig_stfl_test_sig_gen` and `sig_stfl_test_query_key`: two signatures of a key pair, with
///    the counts before and after each signature, and the verification of both.
///
/// `sig_stfl_KATs_keygen` takes the key pair of each set of `responseFileKeyPairSchemes` from
/// the response file, because its key generation takes minutes or hours, and generates every
/// other key pair. The C program needs a response file for every XMSS and XMSS^MT scheme, and
/// liboqs runs it without one for LMS.
///
/// The guard bytes of the C program around each buffer have no Rust counterpart. The C program
/// also tests the lock callbacks of its secret key object and signs from several threads, in
/// `sig_stfl_test_secret_key_lock` and the threads of `main`. Those tests concern the C key
/// object, which the Rust API has no form of: the Rust secret key is a value, and `&mut` gives
/// one signer at a time. The test has no replacement for them.
pub struct StatefulSignatureCorrectnessTest;

impl StatefulSignatureCorrectnessTest {
    /// The random bit flips of the message and of the signature, as `test_sig_stfl` runs them.
    pub const bitFlipCount: usize = SignatureCorrectnessTest::bitFlipCount;

    /// The schemes whose key pair `sig_stfl_KATs_keygen` reads from the response file.
    pub const responseFileKeyPairSchemes: [&'static str; 18] = [
        "XMSS-SHA2_16_256",
        "XMSS-SHA2_20_256",
        "XMSS-SHAKE_16_256",
        "XMSS-SHAKE_20_256",
        "XMSS-SHA2_16_512",
        "XMSS-SHA2_20_512",
        "XMSS-SHAKE_16_512",
        "XMSS-SHAKE_20_512",
        "XMSS-SHA2_16_192",
        "XMSS-SHA2_20_192",
        "XMSS-SHAKE256_16_192",
        "XMSS-SHAKE256_20_192",
        "XMSS-SHAKE256_16_256",
        "XMSS-SHAKE256_20_256",
        "XMSSMT-SHA2_40/2_256",
        "XMSSMT-SHA2_60/3_256",
        "XMSSMT-SHAKE_40/2_256",
        "XMSSMT-SHAKE_60/3_256",
    ];

    /// The first message of `sig_stfl_test_sig_gen`, with the zero byte that ends the C string.
    const firstMessage: &'static [u8] = b"The quick brown fox ...\0";

    /// The second message of `sig_stfl_test_sig_gen`, with the zero byte that ends the C string.
    const secondMessage: &'static [u8] = b"The quick brown fox jumped from the tree.\0";

    /// Runs the parts of the program with random bytes from a source and the text of the
    /// response file of the scheme. Returns the first failure.
    pub fn run(
        scheme: &dyn StatefulSigning,
        random: &mut dyn RandomGenerating,
        responseFile: Option<&str>,
    ) -> Result<(), String> {
        let name = scheme.description().name;
        if name.contains("XMSS") && responseFile.is_none() {
            return Err(format!("{name}: a response file must be provided for XMSS"));
        }
        Self::checkCorrectness(scheme, random, responseFile)?;
        if name.contains("XMSS") {
            Self::checkInvalidSignatures(scheme)?;
        }
        Self::checkSecretKey(scheme, random, responseFile)?;
        Self::checkSignatureGeneration(scheme, random, responseFile)
    }

    /// `sig_stfl_KATs_keygen`: the key pair of the response file for a scheme of
    /// `responseFileKeyPairSchemes`, read as `sig_stfl_keypair_from_KATs` reads it, and a new key
    /// pair for every other scheme.
    fn keyPair(
        scheme: &dyn StatefulSigning,
        random: &mut dyn RandomGenerating,
        responseFile: Option<&str>,
    ) -> Result<KeyPair, String> {
        let description = scheme.description();
        let name = description.name;
        let fileText = match responseFile {
            Some(text) if Self::responseFileKeyPairSchemes.contains(&name) => text,
            _ => {
                return scheme
                    .generateKeyPair(random)
                    .map_err(|error| format!("{name}: the key pair failed: {error}"));
            }
        };
        let file = ResponseFile::new(fileText);
        let missing =
            |what: &str| format!("{name}: unable to read '{what}' from the response file");
        let (publicKey, position) = file
            .value("pk = ", 0, description.publicKeyLength)
            .ok_or_else(|| missing("pk"))?;
        let (secretKey, _) = file
            .value("sk = ", position, description.secretKeyLength)
            .ok_or_else(|| missing("sk"))?;
        Ok(KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        })
    }

    /// `sig_stfl_test_correctness`: the signature of a random message, its verification with the
    /// public key and again with the stored copy, and the bit flips. The C program only prints a
    /// failure of the second verification. The test fails on it.
    fn checkCorrectness(
        scheme: &dyn StatefulSigning,
        random: &mut dyn RandomGenerating,
        responseFile: Option<&str>,
    ) -> Result<(), String> {
        let description = scheme.description();
        let name = description.name;
        let mut message = vec![0u8; 100];
        random.fillRandomBytes(&mut message);
        let keyPair = Self::keyPair(scheme, random, responseFile)?;
        // The C program stores the public key, and reads it back for the second verification.
        let storedPublicKey = keyPair.publicKey.clone();
        let mut secretKey = keyPair.secretKey;
        let signature = scheme
            .sign(&message, &mut secretKey, &mut SavedKeys::accepting())
            .map_err(|error| format!("{name}: the signature failed: {error}"))?;
        if !scheme.isValidSignature(&signature, &message, &keyPair.publicKey) {
            return Err(format!("{name}: the signature does not verify"));
        }
        if !scheme.isValidSignature(&signature, &message, &storedPublicKey) {
            return Err(format!(
                "{name}: the signature does not verify with the stored public key"
            ));
        }
        let isValid = |message: &[u8], signature: &[u8]| {
            scheme.isValidSignature(signature, message, &keyPair.publicKey)
        };
        SignatureCorrectnessTest::checkBitFlips(
            name,
            description.isSUFCMASecure,
            random,
            &message,
            &signature,
            &isValid,
        )
    }

    /// `test_invalid_sig`: a signature of 10 zero bytes, which is shorter than the signature of
    /// any scheme, and a zero signature of the scheme length for a public key whose object
    /// identifier names another parameter set. The public key is the 68-byte key of the C
    /// program, zeros with the identifier in its fourth byte: `0x01` and then `0x02`.
    fn checkInvalidSignatures(scheme: &dyn StatefulSigning) -> Result<(), String> {
        let description = scheme.description();
        let name = description.name;
        let message = b"test";
        let mut publicKey = [0u8; 68];
        publicKey[3] = 0x01;
        if scheme.isValidSignature(&[0u8; 10], message, &publicKey) {
            return Err(format!(
                "{name}: the verification accepts a signature of 10 bytes"
            ));
        }
        publicKey[3] = 0x02;
        if scheme.isValidSignature(&vec![0u8; description.signatureLength], message, &publicKey) {
            return Err(format!(
                "{name}: the verification accepts a zero signature for a zero public key with the object identifier 2"
            ));
        }
        Ok(())
    }

    /// `sig_stfl_test_secret_key`: the counts of a key pair and the saved secret key.
    ///
    /// The C program checks only that each count succeeds, and that it can restore a key from
    /// the saved bytes. The Rust store is the store callback of the C key, which receives the
    /// advanced key before the C library releases a signature. So each signature comes back with
    /// one saved key, equal to the advanced key in memory, a key reloaded from the saved bytes
    /// signs on, and a refused save gives `OQSError::persistenceFailed` and no signature. The C
    /// library advances the key in memory before it calls the store, so the key in memory has
    /// changed after a refused save too.
    fn checkSecretKey(
        scheme: &dyn StatefulSigning,
        random: &mut dyn RandomGenerating,
        responseFile: Option<&str>,
    ) -> Result<(), String> {
        let name = scheme.description().name;
        let keyPair = Self::keyPair(scheme, random, responseFile)?;
        scheme
            .totalSignatureCount(keyPair.secretKey.bytes())
            .map_err(|error| format!("{name}: the total count failed: {error}"))?;
        scheme
            .remainingSignatureCount(keyPair.secretKey.bytes())
            .map_err(|error| format!("{name}: the remaining count failed: {error}"))?;
        let mut message = vec![0u8; 100];
        random.fillRandomBytes(&mut message);
        let mut secretKey = keyPair.secretKey.clone();
        let mut saved = SavedKeys::accepting();
        scheme
            .sign(&message, &mut secretKey, &mut saved)
            .map_err(|error| format!("{name}: the signature failed: {error}"))?;
        Self::checkSavedKey(name, &saved, &secretKey)?;
        if secretKey.bytes() == keyPair.secretKey.bytes() {
            return Err(format!(
                "{name}: the key in memory does not change with a signature"
            ));
        }
        let mut reloadedKey = SecretBytes::new(saved.keys[0].clone());
        let mut savedAgain = SavedKeys::accepting();
        let signature = scheme
            .sign(&message, &mut reloadedKey, &mut savedAgain)
            .map_err(|error| format!("{name}: the reloaded key fails to sign: {error}"))?;
        if !scheme.isValidSignature(&signature, &message, &keyPair.publicKey) {
            return Err(format!(
                "{name}: the signature of the reloaded key does not verify"
            ));
        }
        Self::checkSavedKey(name, &savedAgain, &reloadedKey)?;
        let beforeRefusal = reloadedKey.bytes().to_vec();
        match scheme.sign(&message, &mut reloadedKey, &mut SavedKeys::refusing()) {
            Err(OQSError::persistenceFailed) => {}
            Ok(_) => return Err(format!("{name}: a refused save releases a signature")),
            Err(error) => {
                return Err(format!(
                    "{name}: a refused save gives the error \"{error}\", not the persistence error"
                ));
            }
        }
        if reloadedKey.bytes() == beforeRefusal {
            return Err(format!(
                "{name}: the key in memory does not change after a refused save"
            ));
        }
        Ok(())
    }

    /// A signature comes back with exactly one saved key, and the saved key is the key in memory.
    fn checkSavedKey(name: &str, saved: &SavedKeys, secretKey: &SecretBytes) -> Result<(), String> {
        if saved.keys.len() != 1 {
            return Err(format!(
                "{name}: the signature comes back with {} saved keys, not one",
                saved.keys.len()
            ));
        }
        if saved.keys[0] != secretKey.bytes() {
            return Err(format!(
                "{name}: the saved key differs from the key in memory"
            ));
        }
        Ok(())
    }

    /// `sig_stfl_test_sig_gen` and `sig_stfl_test_query_key`, without the lock callbacks: the
    /// counts of a key pair, the signatures of the two messages of the C program with the counts
    /// after each, and the verification of both signatures.
    ///
    /// The C program checks only that each count succeeds. The test also checks the values: a
    /// new key has its whole total left, the total stays the same, and each signature uses one.
    fn checkSignatureGeneration(
        scheme: &dyn StatefulSigning,
        random: &mut dyn RandomGenerating,
        responseFile: Option<&str>,
    ) -> Result<(), String> {
        let name = scheme.description().name;
        let keyPair = Self::keyPair(scheme, random, responseFile)?;
        let mut secretKey = keyPair.secretKey;
        let counts = |secretKey: &SecretBytes| -> Result<(u64, u64), String> {
            let total = scheme
                .totalSignatureCount(secretKey.bytes())
                .map_err(|error| format!("{name}: the total count failed: {error}"))?;
            let remaining = scheme
                .remainingSignatureCount(secretKey.bytes())
                .map_err(|error| format!("{name}: the remaining count failed: {error}"))?;
            Ok((total, remaining))
        };
        let (total, mut remaining) = counts(&secretKey)?;
        if remaining != total {
            return Err(format!(
                "{name}: a new key has {remaining} signatures left of {total}"
            ));
        }
        let mut signatures = Vec::new();
        for (number, message) in [(1, Self::firstMessage), (2, Self::secondMessage)] {
            let signature = scheme
                .sign(message, &mut secretKey, &mut SavedKeys::accepting())
                .map_err(|error| {
                    format!("{name}: the signature of message {number} failed: {error}")
                })?;
            let (totalAfter, remainingAfter) = counts(&secretKey)?;
            if totalAfter != total {
                return Err(format!(
                    "{name}: the total count changes from {total} to {totalAfter} with a signature"
                ));
            }
            if remainingAfter.checked_add(1) != Some(remaining) {
                return Err(format!(
                    "{name}: the remaining count goes from {remaining} to {remainingAfter} with a signature"
                ));
            }
            remaining = remainingAfter;
            signatures.push((number, message, signature));
        }
        for (number, message, signature) in signatures {
            if !scheme.isValidSignature(&signature, message, &keyPair.publicKey) {
                return Err(format!(
                    "{name}: the signature of message {number} does not verify"
                ));
            }
        }
        Ok(())
    }
}

/// The store of `save_secret_key` of the C program: it keeps each saved key, or refuses every
/// save as a full disk would.
pub(crate) struct SavedKeys {
    /// The saved keys, in the order of the saves.
    pub(crate) keys: Vec<Vec<u8>>,
    isRefusing: bool,
}

impl SavedKeys {
    /// A store that keeps each saved key.
    pub(crate) fn accepting() -> Self {
        SavedKeys {
            keys: Vec::new(),
            isRefusing: false,
        }
    }

    /// A store that refuses every save.
    pub(crate) fn refusing() -> Self {
        SavedKeys {
            keys: Vec::new(),
            isRefusing: true,
        }
    }
}

impl KeyStatePersisting for SavedKeys {
    fn persist(&mut self, secretKey: &[u8]) -> Result<(), OQSError> {
        if self.isRefusing {
            return Err(OQSError::operationFailed);
        }
        self.keys.push(secretKey.to_vec());
        Ok(())
    }
}
