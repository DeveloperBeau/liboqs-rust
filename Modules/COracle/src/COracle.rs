// Every function of this file calls the C library through its foreign function interface. The
// unsafe code register lists the file with that reason.
#![allow(unsafe_code)]

use crate::OracleRandomness;
use OQSNativeDomain::RandomGenerating;
use OQSNativeEntities::{
    Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes, SignatureDescription,
    StatefulSignatureDescription,
};
use core::ffi::{CStr, c_char, c_int, c_void};
use std::cell::Cell;
use std::ffi::CString;
use std::ptr::{null, null_mut};
use std::sync::{Mutex, MutexGuard, Once, PoisonError};

/// The lock of the C library. The C library has one global random source, so only one
/// `COracle` may exist at a time. This is the one global state of the crate, and it mirrors the
/// global state of the C library.
static oracleLock: Mutex<()> = Mutex::new(());

/// The one call of `OQS_init` in the process.
static initialization: Once = Once::new();

thread_local! {
    /// True while the thread holds a `COracle`. A second oracle on the same thread would wait
    /// for itself forever, so `COracle::new` stops the test at once with the reason.
    static isHoldingOracle: Cell<bool> = const { Cell::new(false) };
}

/// The liboqs C library, locked for one user, with a chosen random source.
///
/// Each operation takes the liboqs name of an algorithm, such as `ML-KEM-768`. An operation on
/// a name that the C library does not know returns `OQSError::operationFailed`. Each input whose
/// length the C code takes from the algorithm is checked first, so a wrong length is an error
/// and never a read outside the input.
pub struct COracle<'random> {
    lock: MutexGuard<'static, ()>,
    // The C callback holds the address of the reference to the source. The box keeps that
    // address fixed while the oracle value moves, so the allocation is not redundant.
    #[allow(clippy::redundant_allocation)]
    source: Option<Box<&'random mut dyn RandomGenerating>>,
}

#[repr(C)]
struct OracleKEMFacts {
    name: *const c_char,
    algorithmVersion: *const c_char,
    claimedNISTLevel: u8,
    isINDCCASecure: u8,
    publicKeyLength: usize,
    secretKeyLength: usize,
    ciphertextLength: usize,
    sharedSecretLength: usize,
    keyPairSeedLength: usize,
    encapsulationSeedLength: usize,
}

#[repr(C)]
struct OracleSignatureFacts {
    name: *const c_char,
    algorithmVersion: *const c_char,
    claimedNISTLevel: u8,
    isEUFCMASecure: u8,
    isSUFCMASecure: u8,
    supportsContext: u8,
    publicKeyLength: usize,
    secretKeyLength: usize,
    signatureLength: usize,
}

#[repr(C)]
struct OracleStatefulFacts {
    objectIdentifier: u32,
    name: *const c_char,
    algorithmVersion: *const c_char,
    isEUFCMASecure: u8,
    isSUFCMASecure: u8,
    publicKeyLength: usize,
    secretKeyLength: usize,
    signatureLength: usize,
}

unsafe extern "C" {
    fn oracleInitialize();
    fn oracleUseNISTRandom(entropy: *const u8, personalization: *const u8);
    fn oracleUseKATRandom(
        methodName: *const c_char,
        entropy: *const u8,
        personalization: *const u8,
    ) -> c_int;
    fn oracleUseCallbackRandom(
        fill: extern "C" fn(*mut c_void, *mut u8, usize),
        context: *mut c_void,
    );
    fn oracleRandomBytes(bytes: *mut u8, length: usize);
    fn oracleFree(pointer: *mut c_void);

    fn oracleKEMCount() -> usize;
    fn oracleKEMIdentifier(index: usize) -> *const c_char;
    fn oracleKEMIsEnabled(name: *const c_char) -> c_int;
    fn oracleKEMFacts(name: *const c_char, facts: *mut OracleKEMFacts) -> c_int;
    fn oracleKEMKeyPair(name: *const c_char, publicKey: *mut u8, secretKey: *mut u8) -> c_int;
    fn oracleKEMKeyPairFromSeed(
        name: *const c_char,
        publicKey: *mut u8,
        secretKey: *mut u8,
        seed: *const u8,
    ) -> c_int;
    fn oracleKEMEncapsulate(
        name: *const c_char,
        ciphertext: *mut u8,
        sharedSecret: *mut u8,
        publicKey: *const u8,
    ) -> c_int;
    fn oracleKEMEncapsulateWithSeed(
        name: *const c_char,
        ciphertext: *mut u8,
        sharedSecret: *mut u8,
        publicKey: *const u8,
        seed: *const u8,
    ) -> c_int;
    fn oracleKEMDecapsulate(
        name: *const c_char,
        sharedSecret: *mut u8,
        ciphertext: *const u8,
        secretKey: *const u8,
    ) -> c_int;

    fn oracleSignatureCount() -> usize;
    fn oracleSignatureIdentifier(index: usize) -> *const c_char;
    fn oracleSignatureIsEnabled(name: *const c_char) -> c_int;
    fn oracleSignatureFacts(name: *const c_char, facts: *mut OracleSignatureFacts) -> c_int;
    fn oracleSignatureKeyPair(name: *const c_char, publicKey: *mut u8, secretKey: *mut u8)
    -> c_int;
    fn oracleSign(
        name: *const c_char,
        signature: *mut u8,
        signatureLength: *mut usize,
        message: *const u8,
        messageLength: usize,
        secretKey: *const u8,
    ) -> c_int;
    fn oracleSignWithContext(
        name: *const c_char,
        signature: *mut u8,
        signatureLength: *mut usize,
        message: *const u8,
        messageLength: usize,
        context: *const u8,
        contextLength: usize,
        secretKey: *const u8,
    ) -> c_int;
    fn oracleVerify(
        name: *const c_char,
        message: *const u8,
        messageLength: usize,
        signature: *const u8,
        signatureLength: usize,
        publicKey: *const u8,
    ) -> c_int;
    fn oracleVerifyWithContext(
        name: *const c_char,
        message: *const u8,
        messageLength: usize,
        signature: *const u8,
        signatureLength: usize,
        context: *const u8,
        contextLength: usize,
        publicKey: *const u8,
    ) -> c_int;

    fn oracleStatefulCount() -> usize;
    fn oracleStatefulIdentifier(index: usize) -> *const c_char;
    fn oracleStatefulIsEnabled(name: *const c_char) -> c_int;
    fn oracleStatefulFacts(name: *const c_char, facts: *mut OracleStatefulFacts) -> c_int;
    fn oracleStatefulKeyPair(
        name: *const c_char,
        publicKey: *mut u8,
        secretKey: *mut *mut u8,
        secretKeyLength: *mut usize,
    ) -> c_int;
    fn oracleStatefulSign(
        name: *const c_char,
        signature: *mut u8,
        signatureLength: *mut usize,
        message: *const u8,
        messageLength: usize,
        secretKey: *const u8,
        secretKeyLength: usize,
        advancedSecretKey: *mut *mut u8,
        advancedSecretKeyLength: *mut usize,
    ) -> c_int;
    fn oracleStatefulVerify(
        name: *const c_char,
        message: *const u8,
        messageLength: usize,
        signature: *const u8,
        signatureLength: usize,
        publicKey: *const u8,
    ) -> c_int;
    fn oracleStatefulSignatureCount(
        name: *const c_char,
        secretKey: *const u8,
        secretKeyLength: usize,
        isTotal: c_int,
        count: *mut u64,
    ) -> c_int;

    fn oracleSHA3256(output: *mut u8, input: *const u8, inputLength: usize);
    fn oracleSHA3384(output: *mut u8, input: *const u8, inputLength: usize);
    fn oracleSHA3512(output: *mut u8, input: *const u8, inputLength: usize);
    fn oracleSHAKE128(output: *mut u8, outputLength: usize, input: *const u8, inputLength: usize);
    fn oracleSHAKE256(output: *mut u8, outputLength: usize, input: *const u8, inputLength: usize);
    fn oracleSHAKE128InPieces(
        output: *mut u8,
        outputLength: usize,
        squeezeStep: usize,
        input: *const u8,
        inputLength: usize,
        absorbStep: usize,
    );
    fn oracleSHAKE256InPieces(
        output: *mut u8,
        outputLength: usize,
        squeezeStep: usize,
        input: *const u8,
        inputLength: usize,
        absorbStep: usize,
    );
    fn oracleSHA256(output: *mut u8, input: *const u8, inputLength: usize);
    fn oracleSHA384(output: *mut u8, input: *const u8, inputLength: usize);
    fn oracleSHA512(output: *mut u8, input: *const u8, inputLength: usize);
    fn oracleAES128ECB(ciphertext: *mut u8, plaintext: *const u8, length: usize, key: *const u8);
    fn oracleAES256ECB(ciphertext: *mut u8, plaintext: *const u8, length: usize, key: *const u8);
    fn oracleAES128CounterStream(
        output: *mut u8,
        outputLength: usize,
        iv: *const u8,
        ivLength: usize,
        key: *const u8,
    );
    fn oracleAES256CounterStream(
        output: *mut u8,
        outputLength: usize,
        iv: *const u8,
        ivLength: usize,
        key: *const u8,
    );
    fn oracleAES256CounterBlocksTwice(
        output: *mut u8,
        firstBlocks: usize,
        secondBlocks: usize,
        iv: *const u8,
        ivLength: usize,
        key: *const u8,
    );
}

/// The callback through which the C code reads random bytes from a Rust source.
extern "C" fn fillFromSource(context: *mut c_void, bytes: *mut u8, length: usize) {
    if length == 0 {
        return;
    }
    // The context is the address of the boxed source of the live `COracle` that installed the
    // callback, and the C code asks for `length` bytes at `bytes`.
    let source = unsafe { &mut *(context as *mut &mut dyn RandomGenerating) };
    let buffer = unsafe { std::slice::from_raw_parts_mut(bytes, length) };
    source.fillRandomBytes(buffer);
}

/// The text of a static C string of the C library, such as an algorithm name.
fn staticText(pointer: *const c_char) -> &'static str {
    // The C library returns names and versions as string literals, which live for the whole
    // process.
    let text = unsafe { CStr::from_ptr(pointer) };
    text.to_str().expect("the C library returns UTF-8 names")
}

/// Turns a liboqs status into a result.
fn checked(status: c_int) -> Result<(), OQSError> {
    if status == 0 {
        Ok(())
    } else {
        Err(OQSError::operationFailed)
    }
}

/// Checks that an input has the length that the C code reads.
fn checkedLength(input: &[u8], expected: usize) -> Result<(), OQSError> {
    if input.len() == expected {
        Ok(())
    } else {
        Err(OQSError::invalidLength {
            expected,
            actual: input.len(),
        })
    }
}

/// The names of the enabled algorithms of one kind, in liboqs order.
fn enabledNames(
    count: unsafe extern "C" fn() -> usize,
    identifier: unsafe extern "C" fn(usize) -> *const c_char,
    isEnabled: unsafe extern "C" fn(*const c_char) -> c_int,
) -> Vec<&'static str> {
    // liboqs gives a name for every index below the count.
    let total = unsafe { count() };
    (0..total)
        .map(|index| unsafe { identifier(index) })
        .filter(|name| unsafe { isEnabled(*name) } == 1)
        .map(staticText)
        .collect()
}

/// Copies a buffer that the C library allocated and releases it.
fn takenBytes(pointer: *mut u8, length: usize) -> Vec<u8> {
    if pointer.is_null() {
        return Vec::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec();
    unsafe { oracleFree(pointer.cast()) };
    bytes
}

impl<'random> COracle<'random> {
    /// Waits for the lock of the C library and makes a randomness its random source until the
    /// oracle is dropped.
    ///
    /// A thread holds one oracle at a time. A second `new` on a thread that holds an oracle
    /// panics, because it would wait for itself forever.
    pub fn new(randomness: OracleRandomness<'random>) -> Self {
        assert!(
            !isHoldingOracle.get(),
            "this thread already holds a COracle: drop it before it makes another"
        );
        // A test that failed while it held the lock leaves nothing to repair: each oracle sets
        // the random source again.
        let lock = oracleLock.lock().unwrap_or_else(PoisonError::into_inner);
        isHoldingOracle.set(true);
        initialization.call_once(|| unsafe { oracleInitialize() });
        let mut source = None;
        match randomness {
            OracleRandomness::nist(entropy) => unsafe {
                oracleUseNISTRandom(entropy.as_ptr(), null());
            },
            OracleRandomness::knownAnswer { algorithm, entropy } => {
                let name = CString::new(algorithm).expect("an algorithm name has no zero byte");
                let status = unsafe { oracleUseKATRandom(name.as_ptr(), entropy.as_ptr(), null()) };
                assert_eq!(
                    status, 0,
                    "the KAT generator of {algorithm} could not start"
                );
            }
            OracleRandomness::source(random) => {
                let mut boxed = Box::new(random);
                let context =
                    (&mut *boxed) as *mut &'random mut dyn RandomGenerating as *mut c_void;
                unsafe { oracleUseCallbackRandom(fillFromSource, context) };
                source = Some(boxed);
            }
        }
        COracle { lock, source }
    }

    /// Fills a buffer from the current random source of the C library, as `OQS_randombytes`
    /// does.
    pub fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        unsafe { oracleRandomBytes(bytes.as_mut_ptr(), bytes.len()) };
    }

    /// The names of the enabled KEMs, in liboqs order.
    pub fn kemNames(&self) -> Vec<&'static str> {
        enabledNames(oracleKEMCount, oracleKEMIdentifier, oracleKEMIsEnabled)
    }

    /// The facts of a KEM, or `None` when the C library does not know the name.
    pub fn kemDescription(&self, name: &str) -> Option<KEMDescription> {
        let name = CString::new(name).ok()?;
        let mut facts = OracleKEMFacts {
            name: null(),
            algorithmVersion: null(),
            claimedNISTLevel: 0,
            isINDCCASecure: 0,
            publicKeyLength: 0,
            secretKeyLength: 0,
            ciphertextLength: 0,
            sharedSecretLength: 0,
            keyPairSeedLength: 0,
            encapsulationSeedLength: 0,
        };
        checked(unsafe { oracleKEMFacts(name.as_ptr(), &mut facts) }).ok()?;
        Some(KEMDescription {
            name: staticText(facts.name),
            algorithmVersion: staticText(facts.algorithmVersion),
            claimedNISTLevel: facts.claimedNISTLevel,
            isINDCCASecure: facts.isINDCCASecure == 1,
            publicKeyLength: facts.publicKeyLength,
            secretKeyLength: facts.secretKeyLength,
            ciphertextLength: facts.ciphertextLength,
            sharedSecretLength: facts.sharedSecretLength,
            keyPairSeedLength: facts.keyPairSeedLength,
            encapsulationSeedLength: facts.encapsulationSeedLength,
        })
    }

    fn kem(&self, name: &str) -> Result<(CString, KEMDescription), OQSError> {
        let description = self.kemDescription(name).ok_or(OQSError::operationFailed)?;
        let name = CString::new(name).map_err(|_| OQSError::operationFailed)?;
        Ok((name, description))
    }

    /// Generates a KEM key pair with `OQS_KEM_keypair`.
    pub fn generateKEMKeyPair(&mut self, name: &str) -> Result<KeyPair, OQSError> {
        let (name, description) = self.kem(name)?;
        let mut publicKey = vec![0u8; description.publicKeyLength];
        let mut secretKey = SecretBytes::zeroed(description.secretKeyLength);
        checked(unsafe {
            oracleKEMKeyPair(
                name.as_ptr(),
                publicKey.as_mut_ptr(),
                secretKey.mutableBytes().as_mut_ptr(),
            )
        })?;
        Ok(KeyPair {
            publicKey,
            secretKey,
        })
    }

    /// Generates a KEM key pair from a seed with `OQS_KEM_keypair_derand`.
    pub fn generateKEMKeyPairFromSeed(
        &mut self,
        name: &str,
        seed: &[u8],
    ) -> Result<KeyPair, OQSError> {
        let (name, description) = self.kem(name)?;
        if description.keyPairSeedLength == 0 {
            return Err(OQSError::seedNotSupported);
        }
        checkedLength(seed, description.keyPairSeedLength)?;
        let mut publicKey = vec![0u8; description.publicKeyLength];
        let mut secretKey = SecretBytes::zeroed(description.secretKeyLength);
        checked(unsafe {
            oracleKEMKeyPairFromSeed(
                name.as_ptr(),
                publicKey.as_mut_ptr(),
                secretKey.mutableBytes().as_mut_ptr(),
                seed.as_ptr(),
            )
        })?;
        Ok(KeyPair {
            publicKey,
            secretKey,
        })
    }

    /// Encapsulates with `OQS_KEM_encaps`.
    pub fn encapsulate(&mut self, name: &str, publicKey: &[u8]) -> Result<Encapsulation, OQSError> {
        let (name, description) = self.kem(name)?;
        checkedLength(publicKey, description.publicKeyLength)?;
        let mut ciphertext = vec![0u8; description.ciphertextLength];
        let mut sharedSecret = SecretBytes::zeroed(description.sharedSecretLength);
        checked(unsafe {
            oracleKEMEncapsulate(
                name.as_ptr(),
                ciphertext.as_mut_ptr(),
                sharedSecret.mutableBytes().as_mut_ptr(),
                publicKey.as_ptr(),
            )
        })?;
        Ok(Encapsulation {
            ciphertext,
            sharedSecret,
        })
    }

    /// Encapsulates with a seed with `OQS_KEM_encaps_derand`.
    pub fn encapsulateWithSeed(
        &mut self,
        name: &str,
        publicKey: &[u8],
        seed: &[u8],
    ) -> Result<Encapsulation, OQSError> {
        let (name, description) = self.kem(name)?;
        if description.encapsulationSeedLength == 0 {
            return Err(OQSError::seedNotSupported);
        }
        checkedLength(publicKey, description.publicKeyLength)?;
        checkedLength(seed, description.encapsulationSeedLength)?;
        let mut ciphertext = vec![0u8; description.ciphertextLength];
        let mut sharedSecret = SecretBytes::zeroed(description.sharedSecretLength);
        checked(unsafe {
            oracleKEMEncapsulateWithSeed(
                name.as_ptr(),
                ciphertext.as_mut_ptr(),
                sharedSecret.mutableBytes().as_mut_ptr(),
                publicKey.as_ptr(),
                seed.as_ptr(),
            )
        })?;
        Ok(Encapsulation {
            ciphertext,
            sharedSecret,
        })
    }

    /// Decapsulates with `OQS_KEM_decaps`.
    pub fn decapsulate(
        &mut self,
        name: &str,
        ciphertext: &[u8],
        secretKey: &[u8],
    ) -> Result<SecretBytes, OQSError> {
        let (name, description) = self.kem(name)?;
        checkedLength(ciphertext, description.ciphertextLength)?;
        checkedLength(secretKey, description.secretKeyLength)?;
        let mut sharedSecret = SecretBytes::zeroed(description.sharedSecretLength);
        checked(unsafe {
            oracleKEMDecapsulate(
                name.as_ptr(),
                sharedSecret.mutableBytes().as_mut_ptr(),
                ciphertext.as_ptr(),
                secretKey.as_ptr(),
            )
        })?;
        Ok(sharedSecret)
    }

    /// The names of the enabled signature schemes, in liboqs order.
    pub fn signatureNames(&self) -> Vec<&'static str> {
        enabledNames(
            oracleSignatureCount,
            oracleSignatureIdentifier,
            oracleSignatureIsEnabled,
        )
    }

    /// The facts of a signature scheme, or `None` when the C library does not know the name.
    pub fn signatureDescription(&self, name: &str) -> Option<SignatureDescription> {
        let name = CString::new(name).ok()?;
        let mut facts = OracleSignatureFacts {
            name: null(),
            algorithmVersion: null(),
            claimedNISTLevel: 0,
            isEUFCMASecure: 0,
            isSUFCMASecure: 0,
            supportsContext: 0,
            publicKeyLength: 0,
            secretKeyLength: 0,
            signatureLength: 0,
        };
        checked(unsafe { oracleSignatureFacts(name.as_ptr(), &mut facts) }).ok()?;
        Some(SignatureDescription {
            name: staticText(facts.name),
            algorithmVersion: staticText(facts.algorithmVersion),
            claimedNISTLevel: facts.claimedNISTLevel,
            isEUFCMASecure: facts.isEUFCMASecure == 1,
            isSUFCMASecure: facts.isSUFCMASecure == 1,
            supportsContext: facts.supportsContext == 1,
            publicKeyLength: facts.publicKeyLength,
            secretKeyLength: facts.secretKeyLength,
            signatureLength: facts.signatureLength,
        })
    }

    fn signatureScheme(&self, name: &str) -> Result<(CString, SignatureDescription), OQSError> {
        let description = self
            .signatureDescription(name)
            .ok_or(OQSError::operationFailed)?;
        let name = CString::new(name).map_err(|_| OQSError::operationFailed)?;
        Ok((name, description))
    }

    /// Generates a signature key pair with `OQS_SIG_keypair`.
    pub fn generateSignatureKeyPair(&mut self, name: &str) -> Result<KeyPair, OQSError> {
        let (name, description) = self.signatureScheme(name)?;
        let mut publicKey = vec![0u8; description.publicKeyLength];
        let mut secretKey = SecretBytes::zeroed(description.secretKeyLength);
        checked(unsafe {
            oracleSignatureKeyPair(
                name.as_ptr(),
                publicKey.as_mut_ptr(),
                secretKey.mutableBytes().as_mut_ptr(),
            )
        })?;
        Ok(KeyPair {
            publicKey,
            secretKey,
        })
    }

    /// Signs with `OQS_SIG_sign`.
    pub fn sign(
        &mut self,
        name: &str,
        message: &[u8],
        secretKey: &[u8],
    ) -> Result<Vec<u8>, OQSError> {
        let (name, description) = self.signatureScheme(name)?;
        checkedLength(secretKey, description.secretKeyLength)?;
        let mut signature = vec![0u8; description.signatureLength];
        let mut signatureLength = 0usize;
        checked(unsafe {
            oracleSign(
                name.as_ptr(),
                signature.as_mut_ptr(),
                &mut signatureLength,
                message.as_ptr(),
                message.len(),
                secretKey.as_ptr(),
            )
        })?;
        signature.truncate(signatureLength);
        Ok(signature)
    }

    /// Signs under a context string with `OQS_SIG_sign_with_ctx_str`.
    pub fn signWithContext(
        &mut self,
        name: &str,
        message: &[u8],
        context: &[u8],
        secretKey: &[u8],
    ) -> Result<Vec<u8>, OQSError> {
        let (name, description) = self.signatureScheme(name)?;
        checkedLength(secretKey, description.secretKeyLength)?;
        let mut signature = vec![0u8; description.signatureLength];
        let mut signatureLength = 0usize;
        checked(unsafe {
            oracleSignWithContext(
                name.as_ptr(),
                signature.as_mut_ptr(),
                &mut signatureLength,
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len(),
                secretKey.as_ptr(),
            )
        })?;
        signature.truncate(signatureLength);
        Ok(signature)
    }

    /// True when `OQS_SIG_verify` accepts a signature.
    pub fn isValidSignature(
        &mut self,
        name: &str,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> bool {
        let Ok((name, description)) = self.signatureScheme(name) else {
            return false;
        };
        checkedLength(publicKey, description.publicKeyLength).is_ok()
            && unsafe {
                oracleVerify(
                    name.as_ptr(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                    publicKey.as_ptr(),
                )
            } == 0
    }

    /// True when `OQS_SIG_verify_with_ctx_str` accepts a signature under a context string.
    pub fn isValidSignatureWithContext(
        &mut self,
        name: &str,
        signature: &[u8],
        message: &[u8],
        context: &[u8],
        publicKey: &[u8],
    ) -> bool {
        let Ok((name, description)) = self.signatureScheme(name) else {
            return false;
        };
        checkedLength(publicKey, description.publicKeyLength).is_ok()
            && unsafe {
                oracleVerifyWithContext(
                    name.as_ptr(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                    context.as_ptr(),
                    context.len(),
                    publicKey.as_ptr(),
                )
            } == 0
    }

    /// The names of the enabled stateful signature schemes, in liboqs order.
    pub fn statefulSignatureNames(&self) -> Vec<&'static str> {
        enabledNames(
            oracleStatefulCount,
            oracleStatefulIdentifier,
            oracleStatefulIsEnabled,
        )
    }

    /// The facts of a stateful signature scheme, or `None` when the C library does not know
    /// the name.
    pub fn statefulSignatureDescription(&self, name: &str) -> Option<StatefulSignatureDescription> {
        let name = CString::new(name).ok()?;
        let mut facts = OracleStatefulFacts {
            objectIdentifier: 0,
            name: null(),
            algorithmVersion: null(),
            isEUFCMASecure: 0,
            isSUFCMASecure: 0,
            publicKeyLength: 0,
            secretKeyLength: 0,
            signatureLength: 0,
        };
        checked(unsafe { oracleStatefulFacts(name.as_ptr(), &mut facts) }).ok()?;
        Some(StatefulSignatureDescription {
            objectIdentifier: facts.objectIdentifier,
            name: staticText(facts.name),
            algorithmVersion: staticText(facts.algorithmVersion),
            isEUFCMASecure: facts.isEUFCMASecure == 1,
            isSUFCMASecure: facts.isSUFCMASecure == 1,
            publicKeyLength: facts.publicKeyLength,
            secretKeyLength: facts.secretKeyLength,
            signatureLength: facts.signatureLength,
        })
    }

    fn statefulScheme(
        &self,
        name: &str,
    ) -> Result<(CString, StatefulSignatureDescription), OQSError> {
        let description = self
            .statefulSignatureDescription(name)
            .ok_or(OQSError::operationFailed)?;
        let name = CString::new(name).map_err(|_| OQSError::operationFailed)?;
        Ok((name, description))
    }

    /// Generates a stateful key pair with `OQS_SIG_STFL_keypair`. The secret key is in its
    /// serialized form.
    pub fn generateStatefulKeyPair(&mut self, name: &str) -> Result<KeyPair, OQSError> {
        let (name, description) = self.statefulScheme(name)?;
        let mut publicKey = vec![0u8; description.publicKeyLength];
        let mut secretKeyPointer = null_mut();
        let mut secretKeyLength = 0usize;
        let status = unsafe {
            oracleStatefulKeyPair(
                name.as_ptr(),
                publicKey.as_mut_ptr(),
                &mut secretKeyPointer,
                &mut secretKeyLength,
            )
        };
        let secretKey = SecretBytes::new(takenBytes(secretKeyPointer, secretKeyLength));
        checked(status)?;
        Ok(KeyPair {
            publicKey,
            secretKey,
        })
    }

    /// Signs with `OQS_SIG_STFL_sign` and returns the signature with the advanced secret key
    /// that the C library persisted through its store callback.
    pub fn signStateful(
        &mut self,
        name: &str,
        message: &[u8],
        secretKey: &[u8],
    ) -> Result<(Vec<u8>, SecretBytes), OQSError> {
        let (name, description) = self.statefulScheme(name)?;
        let mut signature = vec![0u8; description.signatureLength];
        let mut signatureLength = 0usize;
        let mut advancedPointer = null_mut();
        let mut advancedLength = 0usize;
        let status = unsafe {
            oracleStatefulSign(
                name.as_ptr(),
                signature.as_mut_ptr(),
                &mut signatureLength,
                message.as_ptr(),
                message.len(),
                secretKey.as_ptr(),
                secretKey.len(),
                &mut advancedPointer,
                &mut advancedLength,
            )
        };
        let advanced = SecretBytes::new(takenBytes(advancedPointer, advancedLength));
        checked(status)?;
        signature.truncate(signatureLength);
        Ok((signature, advanced))
    }

    /// True when `OQS_SIG_STFL_verify` accepts a signature.
    ///
    /// The C function reads the public key from a buffer of the length of the scheme. A shorter
    /// key goes to the C code with zeros after it, because liboqs also accepts a raw LMS public
    /// key, four bytes shorter than the HSS key, and reads only its bytes. A longer key is
    /// refused.
    pub fn isValidStatefulSignature(
        &mut self,
        name: &str,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> bool {
        let Ok((name, description)) = self.statefulScheme(name) else {
            return false;
        };
        if publicKey.len() > description.publicKeyLength {
            return false;
        }
        let mut paddedKey = vec![0u8; description.publicKeyLength];
        paddedKey[..publicKey.len()].copy_from_slice(publicKey);
        let status = unsafe {
            oracleStatefulVerify(
                name.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
                paddedKey.as_ptr(),
            )
        };
        status == 0
    }

    fn statefulSignatureCount(
        &mut self,
        name: &str,
        secretKey: &[u8],
        isTotal: bool,
    ) -> Result<u64, OQSError> {
        let (name, _) = self.statefulScheme(name)?;
        let mut count = 0u64;
        checked(unsafe {
            oracleStatefulSignatureCount(
                name.as_ptr(),
                secretKey.as_ptr(),
                secretKey.len(),
                c_int::from(isTotal),
                &mut count,
            )
        })?;
        Ok(count)
    }

    /// The number of signatures that a serialized secret key can still make.
    pub fn remainingSignatureCount(
        &mut self,
        name: &str,
        secretKey: &[u8],
    ) -> Result<u64, OQSError> {
        self.statefulSignatureCount(name, secretKey, false)
    }

    /// The number of signatures that a serialized secret key can make over its whole life.
    pub fn totalSignatureCount(&mut self, name: &str, secretKey: &[u8]) -> Result<u64, OQSError> {
        self.statefulSignatureCount(name, secretKey, true)
    }

    /// The SHA3-256 digest of an input, from `OQS_SHA3_sha3_256`.
    pub fn sha3256(&self, input: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        unsafe { oracleSHA3256(output.as_mut_ptr(), input.as_ptr(), input.len()) };
        output
    }

    /// The SHA3-384 digest of an input, from `OQS_SHA3_sha3_384`.
    pub fn sha3384(&self, input: &[u8]) -> [u8; 48] {
        let mut output = [0u8; 48];
        unsafe { oracleSHA3384(output.as_mut_ptr(), input.as_ptr(), input.len()) };
        output
    }

    /// The SHA3-512 digest of an input, from `OQS_SHA3_sha3_512`.
    pub fn sha3512(&self, input: &[u8]) -> [u8; 64] {
        let mut output = [0u8; 64];
        unsafe { oracleSHA3512(output.as_mut_ptr(), input.as_ptr(), input.len()) };
        output
    }

    /// SHAKE128 output of a length, from `OQS_SHA3_shake128`.
    pub fn shake128(&self, input: &[u8], outputLength: usize) -> Vec<u8> {
        let mut output = vec![0u8; outputLength];
        unsafe {
            oracleSHAKE128(
                output.as_mut_ptr(),
                outputLength,
                input.as_ptr(),
                input.len(),
            )
        };
        output
    }

    /// SHAKE256 output of a length, from `OQS_SHA3_shake256`.
    pub fn shake256(&self, input: &[u8], outputLength: usize) -> Vec<u8> {
        let mut output = vec![0u8; outputLength];
        unsafe {
            oracleSHAKE256(
                output.as_mut_ptr(),
                outputLength,
                input.as_ptr(),
                input.len(),
            )
        };
        output
    }

    /// SHAKE128 output from the incremental API, which absorbs pieces of `absorbStep` bytes and
    /// squeezes pieces of `squeezeStep` bytes. A step of 0 is one piece.
    pub fn shake128InPieces(
        &self,
        input: &[u8],
        absorbStep: usize,
        outputLength: usize,
        squeezeStep: usize,
    ) -> Vec<u8> {
        let mut output = vec![0u8; outputLength];
        unsafe {
            oracleSHAKE128InPieces(
                output.as_mut_ptr(),
                outputLength,
                squeezeStep,
                input.as_ptr(),
                input.len(),
                absorbStep,
            )
        };
        output
    }

    /// SHAKE256 output from the incremental API, as `shake128InPieces` gives for SHAKE128.
    pub fn shake256InPieces(
        &self,
        input: &[u8],
        absorbStep: usize,
        outputLength: usize,
        squeezeStep: usize,
    ) -> Vec<u8> {
        let mut output = vec![0u8; outputLength];
        unsafe {
            oracleSHAKE256InPieces(
                output.as_mut_ptr(),
                outputLength,
                squeezeStep,
                input.as_ptr(),
                input.len(),
                absorbStep,
            )
        };
        output
    }

    /// The SHA-256 digest of an input, from `OQS_SHA2_sha256`.
    pub fn sha256(&self, input: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        unsafe { oracleSHA256(output.as_mut_ptr(), input.as_ptr(), input.len()) };
        output
    }

    /// The SHA-384 digest of an input, from `OQS_SHA2_sha384`.
    pub fn sha384(&self, input: &[u8]) -> [u8; 48] {
        let mut output = [0u8; 48];
        unsafe { oracleSHA384(output.as_mut_ptr(), input.as_ptr(), input.len()) };
        output
    }

    /// The SHA-512 digest of an input, from `OQS_SHA2_sha512`.
    pub fn sha512(&self, input: &[u8]) -> [u8; 64] {
        let mut output = [0u8; 64];
        unsafe { oracleSHA512(output.as_mut_ptr(), input.as_ptr(), input.len()) };
        output
    }

    /// AES-128 encryption of whole blocks, from `OQS_AES128_ECB_enc`.
    pub fn aes128ECB(&self, key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(plaintext.len() % 16, 0, "ECB takes whole blocks");
        let mut ciphertext = vec![0u8; plaintext.len()];
        unsafe {
            oracleAES128ECB(
                ciphertext.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext.len(),
                key.as_ptr(),
            )
        };
        ciphertext
    }

    /// AES-256 encryption of whole blocks, from `OQS_AES256_ECB_enc`.
    pub fn aes256ECB(&self, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(plaintext.len() % 16, 0, "ECB takes whole blocks");
        let mut ciphertext = vec![0u8; plaintext.len()];
        unsafe {
            oracleAES256ECB(
                ciphertext.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext.len(),
                key.as_ptr(),
            )
        };
        ciphertext
    }

    /// An AES-128 counter-mode keystream from an initialization vector, from
    /// `OQS_AES128_CTR_inc_stream_iv`.
    pub fn aes128CounterStream(&self, key: &[u8; 16], iv: &[u8], length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        unsafe {
            oracleAES128CounterStream(
                output.as_mut_ptr(),
                length,
                iv.as_ptr(),
                iv.len(),
                key.as_ptr(),
            )
        };
        output
    }

    /// An AES-256 counter-mode keystream from an initialization vector, from
    /// `OQS_AES256_CTR_inc_stream_iv`.
    pub fn aes256CounterStream(&self, key: &[u8; 32], iv: &[u8], length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        unsafe {
            oracleAES256CounterStream(
                output.as_mut_ptr(),
                length,
                iv.as_ptr(),
                iv.len(),
                key.as_ptr(),
            )
        };
        output
    }

    /// Two runs of whole AES-256 counter blocks from one counter, from `OQS_AES256_CTR_inc_iv`
    /// and two calls of `OQS_AES256_CTR_inc_stream_blks`.
    pub fn aes256CounterBlocksTwice(
        &self,
        key: &[u8; 32],
        iv: &[u8],
        firstBlocks: usize,
        secondBlocks: usize,
    ) -> Vec<u8> {
        let mut output = vec![0u8; 16 * (firstBlocks + secondBlocks)];
        unsafe {
            oracleAES256CounterBlocksTwice(
                output.as_mut_ptr(),
                firstBlocks,
                secondBlocks,
                iv.as_ptr(),
                iv.len(),
                key.as_ptr(),
            )
        };
        output
    }
}

impl Drop for COracle<'_> {
    fn drop(&mut self) {
        // The C library must not keep the address of a source that ends with this oracle, so
        // the random source goes back to a fixed generator while the lock is still held.
        unsafe { oracleUseNISTRandom([0u8; 48].as_ptr(), null()) };
        isHoldingOracle.set(false);
        let _ = (&self.lock, &self.source);
    }
}
