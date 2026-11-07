//! The fuzz test of liboqs `tests/fuzz_test_kem.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error.
//!
//! The C program draws its bytes from `rand()`. The cases 0 and 1 of the Rust program draw
//! only zeros or only ones, and every such byte is 0 modulo 3, so `f = 0`, which has no
//! inverse. The C code checks no key, so these key pairs cannot decapsulate, and
//! `constantRandomBytesGiveTheKeyFZeroAsInTheCCode` states what they give. The fuzz program
//! runs the seeded cases from 2 up.

use OQSNativeAlgorithmTests::{FuzzRandom, KEMFuzzTest};
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeNTRU::NTRU;
use OQSNativeSHA3::SHA3256;
use core::ops::Range;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4E54_5255_4655_5A5A;

/// The seeded cases of each set.
const seededCases: Range<u64> = 2..14;

const everySet: [&NTRU; 6] = [
    &NTRU::ntruHPS2048509,
    &NTRU::ntruHPS2048677,
    &NTRU::ntruHPS4096821,
    &NTRU::ntruHPS40961229,
    &NTRU::ntruHRSS701,
    &NTRU::ntruHRSS1373,
];

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestKEMPassesForNTRUHPS2048509() {
    assert_eq!(
        KEMFuzzTest::runCases(&NTRU::ntruHPS2048509, fuzzSeed, seededCases),
        Ok(())
    );
}

#[test]
fn fuzzTestKEMPassesForNTRUHPS2048677() {
    assert_eq!(
        KEMFuzzTest::runCases(&NTRU::ntruHPS2048677, fuzzSeed, seededCases),
        Ok(())
    );
}

#[test]
fn fuzzTestKEMPassesForNTRUHPS4096821() {
    assert_eq!(
        KEMFuzzTest::runCases(&NTRU::ntruHPS4096821, fuzzSeed, seededCases),
        Ok(())
    );
}

#[test]
fn fuzzTestKEMPassesForNTRUHPS40961229() {
    assert_eq!(
        KEMFuzzTest::runCases(&NTRU::ntruHPS40961229, fuzzSeed, seededCases),
        Ok(())
    );
}

#[test]
fn fuzzTestKEMPassesForNTRUHRSS701() {
    assert_eq!(
        KEMFuzzTest::runCases(&NTRU::ntruHRSS701, fuzzSeed, seededCases),
        Ok(())
    );
}

#[test]
fn fuzzTestKEMPassesForNTRUHRSS1373() {
    assert_eq!(
        KEMFuzzTest::runCases(&NTRU::ntruHRSS1373, fuzzSeed, seededCases),
        Ok(())
    );
}

#[test]
fn constantRandomBytesGiveTheKeyFZeroAsInTheCCode() {
    for mechanism in everySet {
        let description = mechanism.description();
        let name = description.name;
        let isHPS = name.starts_with("NTRU-HPS");
        // The secret key is f, f^-1, h^-1 and the rejection key, so its length gives the
        // length of a packed polynomial modulo 3.
        let ternaryLength = (description.secretKeyLength - description.publicKeyLength - 32) / 2;
        for byte in [0x00, 0xFF] {
            let mut random = FuzzRandom::fixed(byte);
            let keyPair = mechanism
                .generateKeyPair(&mut random)
                .expect("no key check");
            let secretKey = keyPair.secretKey.bytes();
            assert!(
                secretKey[..ternaryLength].iter().all(|digits| *digits == 0),
                "{name}, the byte {byte:#04x}: f is 0"
            );
            let encapsulation = mechanism
                .encapsulate(&keyPair.publicKey, &mut random)
                .expect("no key check");
            let secret = mechanism
                .decapsulate(&encapsulation.ciphertext, secretKey)
                .expect("no error");
            if isHPS {
                // f = 0 decrypts m = 0, whose weight NTRU-HPS refuses.
                let mut hash = SHA3256::new();
                hash.absorb(&secretKey[secretKey.len() - 32..]);
                hash.absorb(&encapsulation.ciphertext);
                assert_eq!(secret.bytes(), hash.finalize(), "{name}, {byte:#04x}");
                assert_ne!(secret.bytes(), encapsulation.sharedSecret.bytes(), "{name}");
            } else {
                // The same bytes give r = 0 and m = 0, which f = 0 decrypts too.
                let zeros = SHA3256::hash(&vec![0u8; 2 * ternaryLength]);
                assert_eq!(secret.bytes(), zeros, "{name}, {byte:#04x}");
                assert_eq!(secret.bytes(), encapsulation.sharedSecret.bytes(), "{name}");
            }
        }
    }
}

#[test]
fn randomKeysAndCiphertextsGiveAResultBecauseNoKeyIsChecked() {
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for mechanism in everySet {
        let description = mechanism.description();
        let name = description.name;
        for case in 0..4 {
            // The C code decapsulates with any secret key and encapsulates to any public key,
            // so each random input of the right length gives a result of the right length.
            let ciphertext = randomBytes(&mut random, description.ciphertextLength);
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let secret = mechanism
                .decapsulate(&ciphertext, &secretKey)
                .unwrap_or_else(|error| {
                    panic!("{name}, case {case} of seed {fuzzSeed:#x}: {error}")
                });
            assert_eq!(secret.bytes().len(), 32);
            let publicKey = randomBytes(&mut random, description.publicKeyLength);
            let encapsulation = mechanism
                .encapsulate(&publicKey, &mut random)
                .unwrap_or_else(|error| {
                    panic!("{name}, case {case} of seed {fuzzSeed:#x}: {error}")
                });
            assert_eq!(
                encapsulation.ciphertext.len(),
                description.ciphertextLength,
                "{name}, case {case} of seed {fuzzSeed:#x}"
            );
        }
    }
}
