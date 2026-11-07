//! The fuzz test of liboqs `tests/fuzz_test_kem.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error.
//!
//! A case runs six operations on matrices of up to 1344 by 1344 values, which take about a
//! second for the largest SHAKE sets in the dev profile. So each set runs the cases 0 to 3: all
//! zeros, all ones and two seeded cases. The parity program runs 1000 seeded variations of each
//! set against the C library.

use OQSNativeAlgorithmTests::{FuzzRandom, KEMFuzzTest};
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeFrodoKEM::FrodoKEM;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4652_4F44_4F4B_454D;

/// The cases of each set.
const caseCount: u64 = 4;

fn checkFuzzCases(mechanism: &dyn KeyEncapsulating) {
    assert_eq!(KEMFuzzTest::run(mechanism, fuzzSeed, caseCount), Ok(()));
}

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestKEMPassesForFrodoKEM640AES() {
    checkFuzzCases(&FrodoKEM::frodoKEM640AES);
}

#[test]
fn fuzzTestKEMPassesForFrodoKEM640SHAKE() {
    checkFuzzCases(&FrodoKEM::frodoKEM640SHAKE);
}

#[test]
fn fuzzTestKEMPassesForFrodoKEM976AES() {
    checkFuzzCases(&FrodoKEM::frodoKEM976AES);
}

#[test]
fn fuzzTestKEMPassesForFrodoKEM976SHAKE() {
    checkFuzzCases(&FrodoKEM::frodoKEM976SHAKE);
}

#[test]
fn fuzzTestKEMPassesForFrodoKEM1344AES() {
    checkFuzzCases(&FrodoKEM::frodoKEM1344AES);
}

#[test]
fn fuzzTestKEMPassesForFrodoKEM1344SHAKE() {
    checkFuzzCases(&FrodoKEM::frodoKEM1344SHAKE);
}

#[test]
fn fuzzTestKEMPassesForEFrodoKEM640AES() {
    checkFuzzCases(&FrodoKEM::eFrodoKEM640AES);
}

#[test]
fn fuzzTestKEMPassesForEFrodoKEM640SHAKE() {
    checkFuzzCases(&FrodoKEM::eFrodoKEM640SHAKE);
}

#[test]
fn fuzzTestKEMPassesForEFrodoKEM976AES() {
    checkFuzzCases(&FrodoKEM::eFrodoKEM976AES);
}

#[test]
fn fuzzTestKEMPassesForEFrodoKEM976SHAKE() {
    checkFuzzCases(&FrodoKEM::eFrodoKEM976SHAKE);
}

#[test]
fn fuzzTestKEMPassesForEFrodoKEM1344AES() {
    checkFuzzCases(&FrodoKEM::eFrodoKEM1344AES);
}

#[test]
fn fuzzTestKEMPassesForEFrodoKEM1344SHAKE() {
    checkFuzzCases(&FrodoKEM::eFrodoKEM1344SHAKE);
}

#[test]
fn randomKeysAndCiphertextsGiveAResultBecauseNoKeyIsChecked() {
    let mechanisms: [&dyn KeyEncapsulating; 12] = [
        &FrodoKEM::frodoKEM640AES,
        &FrodoKEM::frodoKEM640SHAKE,
        &FrodoKEM::frodoKEM976AES,
        &FrodoKEM::frodoKEM976SHAKE,
        &FrodoKEM::frodoKEM1344AES,
        &FrodoKEM::frodoKEM1344SHAKE,
        &FrodoKEM::eFrodoKEM640AES,
        &FrodoKEM::eFrodoKEM640SHAKE,
        &FrodoKEM::eFrodoKEM976AES,
        &FrodoKEM::eFrodoKEM976SHAKE,
        &FrodoKEM::eFrodoKEM1344AES,
        &FrodoKEM::eFrodoKEM1344SHAKE,
    ];
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for mechanism in mechanisms {
        let description = mechanism.description();
        let name = description.name;
        // The C code decapsulates with any secret key and encapsulates to any public key, so
        // each random input of the right length gives a result of the right length.
        let ciphertext = randomBytes(&mut random, description.ciphertextLength);
        let secretKey = randomBytes(&mut random, description.secretKeyLength);
        let secret = mechanism
            .decapsulate(&ciphertext, &secretKey)
            .unwrap_or_else(|error| panic!("{name}, seed {fuzzSeed:#x}: {error}"));
        assert_eq!(secret.bytes().len(), description.sharedSecretLength);
        let publicKey = randomBytes(&mut random, description.publicKeyLength);
        let encapsulation = mechanism
            .encapsulate(&publicKey, &mut random)
            .unwrap_or_else(|error| panic!("{name}, seed {fuzzSeed:#x}: {error}"));
        assert_eq!(
            encapsulation.ciphertext.len(),
            description.ciphertextLength,
            "{name}, seed {fuzzSeed:#x}"
        );
    }
}
