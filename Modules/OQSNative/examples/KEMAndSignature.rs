//! A key encapsulation and a signature through the registry, with the random source of the
//! operating system. The README shows this program.

use OQSNative::{OQSError, Registry, SystemRandom};

fn main() -> Result<(), OQSError> {
    let mut random = SystemRandom::new().map_err(|_| OQSError::operationFailed)?;

    let mechanism = Registry::mechanism("ML-KEM-768").ok_or(OQSError::operationFailed)?;
    let keyPair = mechanism.generateKeyPair(&mut random)?;
    let encapsulation = mechanism.encapsulate(&keyPair.publicKey, &mut random)?;
    let sharedSecret =
        mechanism.decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())?;
    assert_eq!(sharedSecret.bytes(), encapsulation.sharedSecret.bytes());

    let scheme = Registry::signatureScheme("ML-DSA-65").ok_or(OQSError::operationFailed)?;
    let keyPair = scheme.generateKeyPair(&mut random)?;
    let message = b"a message";
    let signature = scheme.sign(message, keyPair.secretKey.bytes(), &mut random)?;
    assert!(scheme.isValidSignature(&signature, message, &keyPair.publicKey));
    Ok(())
}
