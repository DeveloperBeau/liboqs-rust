//! Parity of hostile keys and ciphertexts with the C library: a key or a ciphertext of the right
//! length with any bytes gives the result of the C library, the same bytes or a failure on both
//! sides, for every registered KEM. The checks of `KEMParity` change one bit of a valid
//! ciphertext, and these cases add keys that no key generation gives.

use OQSNative::{Encapsulation, HQC, KeyEncapsulating, OQSError, Registry, SecretBytes};
use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeParity::{LargeStack, ParitySettings, VariationGenerator};

/// The NIST DRBG of the entropy input whose first four bytes are a number, little-endian, and
/// whose other bytes are zero.
fn numberedRandom(number: u32) -> NISTKATRandom {
    let mut entropy = [0u8; 48];
    entropy[..4].copy_from_slice(&number.to_le_bytes());
    NISTKATRandom::new(&entropy, None)
}

/// The encapsulation of the C library with the random bytes of a numbered generator.
fn cEncapsulation(name: &str, publicKey: &[u8], number: u32) -> Result<Encapsulation, OQSError> {
    let mut random = numberedRandom(number);
    COracle::new(OracleRandomness::source(&mut random)).encapsulate(name, publicKey)
}

/// True for the same ciphertext and shared secret, or for a failure on both sides.
fn isAgreeing(
    cResult: &Result<Encapsulation, OQSError>,
    rustResult: &Result<Encapsulation, OQSError>,
) -> bool {
    match (cResult, rustResult) {
        (Ok(cValue), Ok(rustValue)) => {
            cValue.ciphertext == rustValue.ciphertext
                && cValue.sharedSecret.bytes() == rustValue.sharedSecret.bytes()
        }
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

/// True for the same secret, or for a failure on both sides.
fn isAgreeingSecret(
    cResult: &Result<SecretBytes, OQSError>,
    rustResult: &Result<SecretBytes, OQSError>,
) -> bool {
    match (cResult, rustResult) {
        (Ok(cSecret), Ok(rustSecret)) => cSecret.bytes() == rustSecret.bytes(),
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

#[test]
fn hostileKeysAndCiphertextsGiveTheResultOfTheCLibraryForEveryMechanism() {
    let seed = ParitySettings::defaultSeed;
    LargeStack::run(|| {
        for mechanism in Registry::mechanisms() {
            let description = mechanism.description();
            let name = description.name;
            let mut generator = VariationGenerator::forCase(seed, name, 0);
            let keyPair = mechanism
                .generateKeyPair(&mut numberedRandom(1))
                .expect("a key pair");
            let validCiphertext = mechanism
                .encapsulate(&keyPair.publicKey, &mut numberedRandom(2))
                .expect("an encapsulation")
                .ciphertext;
            let publicKeyLength = description.publicKeyLength;
            let publicKeys = [
                vec![0xFF; publicKeyLength],
                vec![0x00; publicKeyLength],
                generator.bytes(publicKeyLength),
                generator.bytes(publicKeyLength),
            ];
            for (index, publicKey) in publicKeys.iter().enumerate() {
                let number = 3 + index as u32;
                let cResult = cEncapsulation(name, publicKey, number);
                let rustResult = mechanism.encapsulate(publicKey, &mut numberedRandom(number));
                assert!(
                    isAgreeing(&cResult, &rustResult),
                    "{name}, public key {index} of seed {seed:#x}: C {cResult:?}, Rust {rustResult:?}"
                );
            }
            let secretKeys = [
                keyPair.secretKey.bytes().to_vec(),
                vec![0xFF; description.secretKeyLength],
                generator.bytes(description.secretKeyLength),
            ];
            let ciphertexts = [
                validCiphertext,
                vec![0xFF; description.ciphertextLength],
                generator.bytes(description.ciphertextLength),
            ];
            for (keyIndex, secretKey) in secretKeys.iter().enumerate() {
                for (ciphertextIndex, ciphertext) in ciphertexts.iter().enumerate() {
                    let cResult = COracle::new(OracleRandomness::nist([0; 48]))
                        .decapsulate(name, ciphertext, secretKey);
                    let rustResult = mechanism.decapsulate(ciphertext, secretKey);
                    assert!(
                        isAgreeingSecret(&cResult, &rustResult),
                        "{name}, secret key {keyIndex} and ciphertext {ciphertextIndex} of seed {seed:#x}: C {cResult:?}, Rust {rustResult:?}"
                    );
                }
            }
        }
    });
}

#[test]
fn hqcKeysWithTheBitsAboveNGiveTheBytesOfTheReductionOfTheCCode() {
    // A key of only ones sets the bits of `s` above `n` in its last byte. With these numbered
    // generators the vector `r2` has a position near `n`, so the product `s r2` reaches past
    // `2 n`. The reduction of the C code drops those bits, where the ring would fold them a
    // second time, so a product that reduces in the ring gives other bytes for these cases.
    let cases: [(&HQC, [u32; 2]); 3] = [
        (&HQC::hqc1, [89, 260]),
        (&HQC::hqc3, [96, 161]),
        (&HQC::hqc5, [546, 629]),
    ];
    LargeStack::run(|| {
        for (mechanism, numbers) in cases {
            let description = mechanism.description();
            let publicKey = vec![0xFF; description.publicKeyLength];
            for number in numbers {
                let cResult = cEncapsulation(description.name, &publicKey, number);
                let rustResult = mechanism.encapsulate(&publicKey, &mut numberedRandom(number));
                assert!(cResult.is_ok());
                assert!(
                    isAgreeing(&cResult, &rustResult),
                    "{}, generator {number}",
                    description.name
                );
            }
        }
    });
}

/// The field bits `m`, the code length `n` and the error weight `t` of a Classic McEliece set.
fn mcElieceFacts(name: &str) -> (usize, usize, usize) {
    match name["Classic-McEliece-".len()..].trim_end_matches('f') {
        "348864" => (12, 3488, 64),
        "460896" => (13, 4608, 96),
        "6688128" => (13, 6688, 128),
        "6960119" => (13, 6960, 119),
        _ => (13, 8192, 128),
    }
}

#[test]
fn classicMcElieceKeysOfTheIdentityNetworkGiveTheDecisionsOfTheCLibrary() {
    // A secret key with control bits of zero has the support bitrev(i), with the element 0 at
    // place 0, and the Goppa polynomial y^t + 1 sees every place of a ciphertext. The errors at
    // the places 1 to t are accepted. t - 1 errors with place 0 fail the weight check alone,
    // and t - 1 errors without it fail the syndrome check alone, because the decoder adds the
    // root 0. t - 2 errors without place 0 fail both, and for the 6960119 sets the weight
    // difference 118 xor 119 has the bits of the syndrome difference 1, so only an or of the
    // two refuses them.
    LargeStack::run(|| {
        for mechanism in Registry::mechanisms() {
            let description = mechanism.description();
            let name = description.name;
            if !name.starts_with("Classic-McEliece-") || name.ends_with('f') {
                continue;
            }
            let (bits, length, weight) = mcElieceFacts(name);
            let mut secretKey = vec![0u8; 40];
            secretKey.extend(1u16.to_le_bytes());
            secretKey.resize(40 + 2 * weight + ((2 * bits - 1) << (bits - 4)), 0);
            secretKey.extend((0..length / 8).map(|index| (index * 37 + 11) as u8));
            assert_eq!(secretKey.len(), description.secretKeyLength);
            let cases: [Vec<usize>; 4] = [
                (1..=weight).collect(),
                (0..weight - 1).collect(),
                (1..weight).collect(),
                (1..weight - 1).collect(),
            ];
            for (index, positions) in cases.iter().enumerate() {
                let mut ciphertext = vec![0u8; description.ciphertextLength];
                for position in positions {
                    ciphertext[position / 8] |= 1 << (position % 8);
                }
                let cResult = COracle::new(OracleRandomness::nist([0; 48])).decapsulate(
                    name,
                    &ciphertext,
                    &secretKey,
                );
                let rustResult = mechanism.decapsulate(&ciphertext, &secretKey);
                assert!(cResult.is_ok());
                assert!(
                    isAgreeingSecret(&cResult, &rustResult),
                    "{name}, case {index}: C {cResult:?}, Rust {rustResult:?}"
                );
            }
        }
    });
}
