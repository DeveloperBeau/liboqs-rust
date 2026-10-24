//! Parity of hostile public keys and signatures with the C library: for every registered
//! signature scheme, a public key or a signature of the right length with any bytes gets the
//! verdict of the C library. The checks of `SignatureParity` change one bit of a valid
//! signature or message, and these cases add public keys that no key generation gives, and the
//! high bit of the last byte, which is a padding bit of every CROSS key.

use OQSNative::{Registry, Signing};
use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeParity::{LargeStack, ParitySettings, VariationGenerator};

const message: &[u8] = b"the quick brown fox";

/// The NIST DRBG of the entropy input whose first four bytes are a number, little-endian, and
/// whose other bytes are zero.
fn numberedRandom(number: u32) -> NISTKATRandom {
    let mut entropy = [0u8; 48];
    entropy[..4].copy_from_slice(&number.to_le_bytes());
    NISTKATRandom::new(&entropy, None)
}

/// A copy of some bytes with the high bit of the last byte set.
fn withHighLastBit(bytes: &[u8]) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    let last = changed.len() - 1;
    changed[last] |= 0x80;
    changed
}

/// Checks that both sides give the same verdict on a signature under a public key.
fn checkVerdict(scheme: &dyn Signing, signature: &[u8], publicKey: &[u8], label: &str) {
    let name = scheme.description().name;
    let cVerdict = COracle::new(OracleRandomness::nist([0; 48]))
        .isValidSignature(name, signature, message, publicKey);
    let rustVerdict = scheme.isValidSignature(signature, message, publicKey);
    assert_eq!(
        cVerdict, rustVerdict,
        "{name}, {label}: C says {cVerdict} and Rust says {rustVerdict}"
    );
}

#[test]
fn hostileKeysAndSignaturesGetTheVerdictOfTheCLibraryForEveryScheme() {
    let seed = ParitySettings::defaultSeed;
    LargeStack::run(|| {
        for scheme in Registry::signatureSchemes() {
            let description = scheme.description();
            let mut generator = VariationGenerator::forCase(seed, description.name, 0);
            let keyPair = scheme
                .generateKeyPair(&mut numberedRandom(1))
                .expect("a key pair");
            let signature = scheme
                .sign(message, keyPair.secretKey.bytes(), &mut numberedRandom(2))
                .expect("a signature");
            checkVerdict(*scheme, &signature, &keyPair.publicKey, "the valid key");
            let publicKeyLength = description.publicKeyLength;
            let publicKeys = [
                vec![0xFF; publicKeyLength],
                vec![0x00; publicKeyLength],
                generator.bytes(publicKeyLength),
                withHighLastBit(&keyPair.publicKey),
            ];
            for (index, publicKey) in publicKeys.iter().enumerate() {
                let label = format!("public key {index} of seed {seed:#x}");
                checkVerdict(*scheme, &signature, publicKey, &label);
            }
            let signatureLength = signature.len();
            let signatures = [
                vec![0xFF; signatureLength],
                vec![0x00; signatureLength],
                generator.bytes(signatureLength),
                withHighLastBit(&signature),
            ];
            for (index, hostile) in signatures.iter().enumerate() {
                let label = format!("signature {index} of seed {seed:#x}");
                checkVerdict(*scheme, hostile, &keyPair.publicKey, &label);
            }
        }
    });
}
