//! The fuzz test of liboqs `tests/fuzz_test_kem.c`, with seeded cases, and the hostile inputs
//! of each parameter set: a random input gives a defined result or a defined error.

use OQSNativeAlgorithmTests::{FuzzRandom, KEMFuzzTest};
use OQSNativeBIKE::BIKE;
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeSHA3::SHA3384;

/// The seed of every fuzz case. A failure message names it.
const fuzzSeed: u64 = 0x4B45_4D5F_4655_5A5A;

/// The fuzz cases of each parameter set: the zero and the one bytes of cases 0 and 1, and
/// seeded bytes after them. A case of BIKE-L5 takes about a tenth of a second in a test build.
const fuzzCaseCount: u64 = 12;

const parameterSets: [&BIKE; 3] = [&BIKE::bikeL1, &BIKE::bikeL3, &BIKE::bikeL5];

fn randomBytes(random: &mut FuzzRandom, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    random.fillRandomBytes(&mut bytes);
    bytes
}

/// The secret of the rejection seed, the last 32 bytes of a secret key, for a ciphertext.
fn rejectionSecret(secretKey: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut hash = SHA3384::new();
    hash.absorb(&secretKey[secretKey.len() - 32..]);
    hash.absorb(ciphertext);
    hash.finalize()[..32].to_vec()
}

#[test]
fn fuzzTestKEMPassesForEveryParameterSet() {
    for mechanism in parameterSets {
        assert_eq!(KEMFuzzTest::run(mechanism, fuzzSeed, fuzzCaseCount), Ok(()));
    }
}

#[test]
fn randomKeysAndCiphertextsAreDecapsulatedAndRejected() {
    // BIKE checks neither key, as the C code does, so every input of the right length gives a
    // shared secret. A random ciphertext or a random secret key fails the comparison of the
    // decoded error with the error of its message, and gives the secret of sigma.
    let mut random = FuzzRandom::seeded(fuzzSeed);
    for mechanism in parameterSets {
        let description = mechanism.description();
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        for case in 0..4 {
            let label = format!("{}, case {case} of seed {fuzzSeed:#x}", description.name);
            let ciphertext = randomBytes(&mut random, description.ciphertextLength);
            let secret = mechanism
                .decapsulate(&ciphertext, keyPair.secretKey.bytes())
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(
                secret.bytes(),
                rejectionSecret(keyPair.secretKey.bytes(), &ciphertext),
                "{label}"
            );
            let secretKey = randomBytes(&mut random, description.secretKeyLength);
            let encapsulation = mechanism
                .encapsulate(&keyPair.publicKey, &mut random)
                .expect("encapsulation");
            let secret = mechanism
                .decapsulate(&encapsulation.ciphertext, &secretKey)
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(
                secret.bytes(),
                rejectionSecret(&secretKey, &encapsulation.ciphertext),
                "{label}"
            );
            let publicKey = randomBytes(&mut random, description.publicKeyLength);
            let encapsulation = mechanism
                .encapsulate(&publicKey, &mut random)
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(encapsulation.ciphertext.len(), description.ciphertextLength);
        }
    }
}
