//! Parity of the shared primitives with the C primitives of liboqs: 1000 seeded inputs each.

use OQSNativeAES::{AES128, AES256, Rijndael256};
use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeParity::{ParitySettings, VariationGenerator};
use OQSNativeSHA2::{SHA256, SHA384, SHA512};
use OQSNativeSHA3::{SHA3256, SHA3384, SHA3512, SHAKE128, SHAKE256};

const caseCount: u64 = 1000;

fn oracle() -> COracle<'static> {
    COracle::new(OracleRandomness::nist([0; 48]))
}

/// The generator of a test, with the seed in the failure message of each assertion.
fn generator(test: &str) -> (VariationGenerator, String) {
    let seed = ParitySettings::defaultSeed;
    (
        VariationGenerator::forCase(seed, test, 0),
        format!("{test} with seed {seed:#x}"),
    )
}

#[test]
fn sha3DigestsMatchTheCLibrary() {
    let (mut generator, label) = generator("SHA-3");
    for case in 0..caseCount {
        let length = generator.below(1200) as usize;
        let input = generator.bytes(length);
        let oracle = oracle();
        assert_eq!(
            SHA3256::hash(&input),
            oracle.sha3256(&input),
            "{label}, case {case}"
        );
        assert_eq!(
            SHA3384::hash(&input),
            oracle.sha3384(&input),
            "{label}, case {case}"
        );
        assert_eq!(
            SHA3512::hash(&input),
            oracle.sha3512(&input),
            "{label}, case {case}"
        );
    }
}

#[test]
fn shakeOutputMatchesTheCLibraryForAnyLength() {
    let (mut generator, label) = generator("SHAKE");
    for case in 0..caseCount {
        let length = generator.below(1200) as usize;
        let input = generator.bytes(length);
        let outputLength = generator.below(700) as usize;
        let oracle = oracle();
        let mut output128 = vec![0u8; outputLength];
        SHAKE128::hash(&input, &mut output128);
        assert_eq!(
            output128,
            oracle.shake128(&input, outputLength),
            "{label}, case {case}"
        );
        let mut output256 = vec![0u8; outputLength];
        SHAKE256::hash(&input, &mut output256);
        assert_eq!(
            output256,
            oracle.shake256(&input, outputLength),
            "{label}, case {case}"
        );
    }
}

#[test]
fn shakeInPiecesMatchesTheIncrementalCLibrary() {
    let (mut generator, label) = generator("SHAKE in pieces");
    for case in 0..caseCount {
        let length = generator.below(1200) as usize;
        let input = generator.bytes(length);
        let absorbStep = 1 + generator.below(300) as usize;
        let squeezeStep = 1 + generator.below(300) as usize;
        let outputLength = generator.below(900) as usize;
        let mut sponge128 = SHAKE128::new();
        let mut sponge256 = SHAKE256::new();
        for piece in input.chunks(absorbStep) {
            sponge128.absorb(piece);
            sponge256.absorb(piece);
        }
        let mut reader128 = sponge128.finalize();
        let mut reader256 = sponge256.finalize();
        let mut output128 = vec![0u8; outputLength];
        let mut output256 = vec![0u8; outputLength];
        for piece in output128.chunks_mut(squeezeStep) {
            reader128.squeeze(piece);
        }
        for piece in output256.chunks_mut(squeezeStep) {
            reader256.squeeze(piece);
        }
        let oracle = oracle();
        assert_eq!(
            output128,
            oracle.shake128InPieces(&input, absorbStep, outputLength, squeezeStep),
            "{label}, case {case}"
        );
        assert_eq!(
            output256,
            oracle.shake256InPieces(&input, absorbStep, outputLength, squeezeStep),
            "{label}, case {case}"
        );
    }
}

#[test]
fn sha2DigestsMatchTheCLibraryForWholeAndSplitInput() {
    let (mut generator, label) = generator("SHA-2");
    for case in 0..caseCount {
        let length = generator.below(1200) as usize;
        let input = generator.bytes(length);
        let step = 1 + generator.below(200) as usize;
        let mut split256 = SHA256::new();
        let mut split512 = SHA512::new();
        for piece in input.chunks(step) {
            split256.absorb(piece);
            split512.absorb(piece);
        }
        let oracle = oracle();
        assert_eq!(
            SHA256::hash(&input),
            oracle.sha256(&input),
            "{label}, case {case}"
        );
        assert_eq!(
            split256.finalize(),
            oracle.sha256(&input),
            "{label}, case {case}"
        );
        assert_eq!(
            SHA384::hash(&input),
            oracle.sha384(&input),
            "{label}, case {case}"
        );
        assert_eq!(
            SHA512::hash(&input),
            oracle.sha512(&input),
            "{label}, case {case}"
        );
        assert_eq!(
            split512.finalize(),
            oracle.sha512(&input),
            "{label}, case {case}"
        );
    }
}

#[test]
fn aesBlocksMatchTheCLibrary() {
    let (mut generator, label) = generator("AES ECB");
    for case in 0..caseCount {
        let key128: [u8; 16] = generator.bytes(16).try_into().expect("16 bytes");
        let key256: [u8; 32] = generator.bytes(32).try_into().expect("32 bytes");
        let blocks = generator.below(12) as usize;
        let plaintext = generator.bytes(16 * blocks);
        let mut ciphertext128 = vec![0u8; plaintext.len()];
        AES128::new(&key128).encryptBlocks(&plaintext, &mut ciphertext128);
        let mut ciphertext256 = vec![0u8; plaintext.len()];
        AES256::new(&key256).encryptBlocks(&plaintext, &mut ciphertext256);
        let oracle = oracle();
        assert_eq!(
            ciphertext128,
            oracle.aes128ECB(&key128, &plaintext),
            "{label}, case {case}"
        );
        assert_eq!(
            ciphertext256,
            oracle.aes256ECB(&key256, &plaintext),
            "{label}, case {case}"
        );
    }
}

#[test]
fn rijndael256BlocksMatchTheMQOMCodeOfTheCLibrary() {
    let (mut generator, label) = generator("Rijndael-256");
    for case in 0..caseCount {
        let key: [u8; 32] = generator.bytes(32).try_into().expect("32 bytes");
        // An odd count leaves the second block of the last pair of the bitsliced form empty.
        let blocks = generator.below(12) as usize;
        let plaintext = generator.bytes(32 * blocks);
        let mut ciphertext = vec![0u8; plaintext.len()];
        Rijndael256::new(&key).encryptBlocks(&plaintext, &mut ciphertext);
        assert_eq!(
            ciphertext,
            oracle().rijndael256ECB(&key, &plaintext),
            "{label}, case {case}"
        );
    }
}

#[test]
fn aesCounterKeystreamsMatchTheCLibrary() {
    let (mut generator, label) = generator("AES CTR");
    for case in 0..caseCount {
        let key128: [u8; 16] = generator.bytes(16).try_into().expect("16 bytes");
        let key256: [u8; 32] = generator.bytes(32).try_into().expect("32 bytes");
        let ivLength = if generator.below(2) == 0 { 12 } else { 16 };
        let iv = generator.bytes(ivLength);
        let length = generator.below(600) as usize;
        let mut stream128 = vec![0u8; length];
        AES128::new(&key128).fillCounterKeystream(&iv, &mut stream128);
        let mut stream256 = vec![0u8; length];
        AES256::new(&key256).fillCounterKeystream(&iv, &mut stream256);
        let oracle = oracle();
        assert_eq!(
            stream128,
            oracle.aes128CounterStream(&key128, &iv, length),
            "{label}, case {case}"
        );
        assert_eq!(
            stream256,
            oracle.aes256CounterStream(&key256, &iv, length),
            "{label}, case {case}"
        );
    }
}

#[test]
fn aesCounterBlocksContinueTheCounterAsTheCLibraryDoes() {
    let (mut generator, label) = generator("AES CTR blocks");
    for case in 0..caseCount {
        let key: [u8; 32] = generator.bytes(32).try_into().expect("32 bytes");
        let ivLength = if generator.below(2) == 0 { 12 } else { 16 };
        let iv = generator.bytes(ivLength);
        let firstBlocks = generator.below(6) as usize;
        let secondBlocks = generator.below(6) as usize;
        let cipher = AES256::new(&key);
        let mut counterBlock = [0u8; 16];
        counterBlock[..ivLength].copy_from_slice(&iv);
        let mut output = vec![0u8; 16 * (firstBlocks + secondBlocks)];
        let (first, second) = output.split_at_mut(16 * firstBlocks);
        cipher.fillCounterBlocks(&mut counterBlock, first);
        cipher.fillCounterBlocks(&mut counterBlock, second);
        assert_eq!(
            output,
            oracle().aes256CounterBlocksTwice(&key, &iv, firstBlocks, secondBlocks),
            "{label}, case {case}"
        );
    }
}
