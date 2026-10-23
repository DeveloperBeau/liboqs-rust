//! Replicates liboqs `tests/test_aes.c`: the FIPS 197 block vectors for ECB, and the RFC 3686
//! vectors for CTR. Adds the counter rules of the C code and the misuse panics.

use OQSNativeAES::{AES128, AES256};

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
        .collect()
}

fn key<const LENGTH: usize>(hex: &str) -> [u8; LENGTH] {
    bytes(hex).try_into().expect("key length")
}

#[test]
fn aes128EncryptsTheBlockOfFips197() {
    let cipher = AES128::new(&key("000102030405060708090a0b0c0d0e0f"));
    let mut ciphertext = [0u8; 16];
    cipher.encryptBlocks(&bytes("00112233445566778899aabbccddeeff"), &mut ciphertext);
    assert_eq!(
        ciphertext.to_vec(),
        bytes("69c4e0d86a7b0430d8cdb78070b4c55a")
    );
}

#[test]
fn aes256EncryptsTheBlockOfFips197() {
    let cipher = AES256::new(&key(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ));
    let mut ciphertext = [0u8; 16];
    cipher.encryptBlocks(&bytes("00112233445566778899aabbccddeeff"), &mut ciphertext);
    assert_eq!(
        ciphertext.to_vec(),
        bytes("8ea2b7ca516745bfeafc49904b496089")
    );
}

#[test]
fn aes128CounterModeMatchesTheUpstreamAESTest() {
    let cipher = AES128::new(&key("7691be035e5020a8ac6e618529f9a0dc"));
    let mut keystream = [0u8; 36];
    cipher.fillCounterKeystream(&bytes("00e0017b27777f3f4a1786f000000001"), &mut keystream);
    let plaintext =
        bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223");
    let ciphertext: Vec<u8> = keystream
        .iter()
        .zip(&plaintext)
        .map(|(stream, plain)| stream ^ plain)
        .collect();
    assert_eq!(
        ciphertext,
        bytes("c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f")
    );
}

#[test]
fn aes256CounterModeMatchesTheUpstreamAESTest() {
    let cipher = AES256::new(&key(
        "ff7a617ce69148e4f1726e2f43581de2aa62d9f805532edff1eed687fb54153d",
    ));
    let mut keystream = [0u8; 36];
    cipher.fillCounterKeystream(&bytes("001cc5b751a51d70a1c1114800000001"), &mut keystream);
    let plaintext =
        bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223");
    let ciphertext: Vec<u8> = keystream
        .iter()
        .zip(&plaintext)
        .map(|(stream, plain)| stream ^ plain)
        .collect();
    assert_eq!(
        ciphertext,
        bytes("eb6c52821d0bbbf7ce7594462aca4faab407df866569fd07f48cc0b583d6071f1ec0e6b8")
    );
}

/// Counter mode is ECB encryption of the counter blocks, with a 32-bit big-endian counter in
/// the last four bytes. The test builds the counter blocks by hand, so it does not read the
/// expected value from the code under test.
#[test]
fn counterKeystreamIsTheEncryptionOfCounterBlocks() {
    let cipher = AES256::new(&key(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    ));
    let nonce = bytes("f0f1f2f3f4f5f6f7f8f9fafb");
    let mut keystream = vec![0u8; 16 * 9 + 5];
    cipher.fillCounterKeystream(&nonce, &mut keystream);
    for (index, block) in keystream.chunks(16).enumerate() {
        let mut counterBlock = nonce.clone();
        counterBlock.extend_from_slice(&(index as u32).to_be_bytes());
        let mut expected = [0u8; 16];
        cipher.encryptBlocks(&counterBlock, &mut expected);
        assert_eq!(block, &expected[..block.len()], "block {index}");
    }
}

#[test]
fn counterWrapsAtThirtyTwoBitsAndKeepsTheFirstTwelveBytes() {
    let cipher = AES128::new(&key("2b7e151628aed2a6abf7158809cf4f3c"));
    let start = bytes("000102030405060708090a0bfffffffe");
    let mut keystream = [0u8; 64];
    cipher.fillCounterKeystream(&start, &mut keystream);
    for (index, expectedCounter) in ["fffffffe", "ffffffff", "00000000", "00000001"]
        .iter()
        .enumerate()
    {
        let mut counterBlock = bytes("000102030405060708090a0b");
        counterBlock.extend(bytes(expectedCounter));
        let mut expected = [0u8; 16];
        cipher.encryptBlocks(&counterBlock, &mut expected);
        assert_eq!(
            &keystream[index * 16..index * 16 + 16],
            &expected,
            "block {index}"
        );
    }
}

#[test]
fn counterBlocksContinueTheKeystreamAndAdvanceTheCounter() {
    let cipher = AES256::new(&key(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ));
    let start: [u8; 16] = bytes("0f0e0d0c0b0a09080706050400000005")
        .try_into()
        .expect("block");
    let mut whole = vec![0u8; 16 * 11];
    cipher.fillCounterKeystream(&start, &mut whole);
    let mut counterBlock = start;
    let mut pieces = Vec::new();
    for count in [1usize, 4, 2, 0, 3, 1] {
        let mut piece = vec![0u8; 16 * count];
        cipher.fillCounterBlocks(&mut counterBlock, &mut piece);
        pieces.extend(piece);
    }
    assert_eq!(pieces, whole);
    assert_eq!(&counterBlock[..12], &start[..12]);
    assert_eq!(&counterBlock[12..], &16u32.to_be_bytes());
}

#[test]
fn ecbEncryptsEachBlockAloneForEveryCount() {
    let cipher = AES128::new(&key("000102030405060708090a0b0c0d0e0f"));
    let plaintext: Vec<u8> = (0..16 * 9).map(|value| value as u8).collect();
    for blocks in 0..=9 {
        let mut ciphertext = vec![0u8; blocks * 16];
        cipher.encryptBlocks(&plaintext[..blocks * 16], &mut ciphertext);
        for block in 0..blocks {
            let mut single = [0u8; 16];
            cipher.encryptBlocks(&plaintext[block * 16..block * 16 + 16], &mut single);
            assert_eq!(
                &ciphertext[block * 16..block * 16 + 16],
                &single,
                "{blocks} blocks, block {block}"
            );
        }
    }
}

#[test]
#[should_panic(expected = "AES encrypts whole blocks of 16 bytes")]
fn ecbRejectsAPartialBlock() {
    AES128::new(&[0; 16]).encryptBlocks(&[0; 15], &mut [0; 15]);
}

#[test]
#[should_panic(expected = "the ciphertext buffer has the length of the plaintext")]
fn ecbRejectsAnOutputOfAnotherLength() {
    AES256::new(&[0; 32]).encryptBlocks(&[0; 16], &mut [0; 32]);
}

#[test]
#[should_panic(expected = "an AES counter-mode vector has 12 or 16 bytes, not 8")]
fn counterModeRejectsAVectorOfAnotherLength() {
    AES256::new(&[0; 32]).fillCounterKeystream(&[0; 8], &mut [0; 16]);
}

#[test]
#[should_panic(expected = "the output is a whole number of 16-byte blocks")]
fn counterBlocksRejectAPartialBlock() {
    AES128::new(&[0; 16]).fillCounterBlocks(&mut [0; 16], &mut [0; 20]);
}
