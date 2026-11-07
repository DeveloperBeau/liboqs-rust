//! The fuzz test of liboqs `tests/fuzz_test_kem.c`, with seeded cases, and the hostile inputs
//! of sntrup761: a random input gives a defined result or a defined error.
//!
//! The C program draws its bytes from `rand()`. The cases 0 and 1 of the Rust program draw
//! only zeros or only ones. They give the small `g` of all -1 or all 1, which has an inverse
//! modulo 3, and the short `f` and `r` of 286 equal coefficients, so they make a key pair that
//! decapsulates, as they do in the C code.

use OQSNativeAlgorithmTests::{FuzzRandom, KEMFuzzTest};
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeNTRUPrime::NTRUPrime;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x534E_5452_5550_3736;

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

#[test]
fn fuzzTestKEMPassesForSntrup761() {
    assert_eq!(
        KEMFuzzTest::run(&NTRUPrime::sntrup761, fuzzSeed, 12),
        Ok(())
    );
}

#[test]
fn randomKeysAndCiphertextsGiveAResultBecauseNoKeyIsChecked() {
    let mechanism = &NTRUPrime::sntrup761;
    let description = mechanism.description();
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for case in 0..4 {
        // The C code decapsulates with any secret key and encapsulates to any public key, so
        // each random input of the right length gives a result of the right length.
        let ciphertext = randomBytes(&mut random, description.ciphertextLength);
        let secretKey = randomBytes(&mut random, description.secretKeyLength);
        let secret = mechanism
            .decapsulate(&ciphertext, &secretKey)
            .unwrap_or_else(|error| panic!("case {case} of seed {fuzzSeed:#x}: {error}"));
        assert_eq!(secret.bytes().len(), 32);
        let publicKey = randomBytes(&mut random, description.publicKeyLength);
        let encapsulation = mechanism
            .encapsulate(&publicKey, &mut random)
            .unwrap_or_else(|error| panic!("case {case} of seed {fuzzSeed:#x}: {error}"));
        assert_eq!(
            encapsulation.ciphertext.len(),
            description.ciphertextLength,
            "case {case} of seed {fuzzSeed:#x}"
        );
    }
}
