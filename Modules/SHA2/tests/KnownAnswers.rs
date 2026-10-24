//! Known answers of FIPS 180-4 for the SHA-2 hash functions, and the consistency of the
//! incremental form with the one-shot form.
//!
//! liboqs `tests/test_hash.py` compares its hashes with Python `hashlib` on random inputs.
//! The port compares SHA-256, SHA-384 and SHA-512 with the C library in the parity tests of the
//! facade crate. The SHA-2 API of liboqs has no SHA-224, SHA-512/224 or SHA-512/256, so their
//! answers here come from Python `hashlib`.

use OQSNativeSHA2::{SHA224, SHA256, SHA384, SHA512, SHA512224, SHA512256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const twoBlockMessage: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

const fourBlockMessage: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

/// The bytes 0, 1, 2 and so on, of a length.
fn countingMessage(length: usize) -> Vec<u8> {
    (0..length).map(|index| index as u8).collect()
}

#[test]
fn sha256MatchesTheExamplesOfFIPS180() {
    assert_eq!(
        hex(&SHA256::hash(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&SHA256::hash(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&SHA256::hash(twoBlockMessage)),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert_eq!(
        hex(&SHA256::hash(&vec![b'a'; 1_000_000])),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn sha384MatchesTheExamplesOfFIPS180() {
    assert_eq!(
        hex(&SHA384::hash(b"")),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );
    assert_eq!(
        hex(&SHA384::hash(b"abc")),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
    assert_eq!(
        hex(&SHA384::hash(&vec![b'a'; 1_000_000])),
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
    );
}

#[test]
fn sha512MatchesTheExamplesOfFIPS180() {
    assert_eq!(
        hex(&SHA512::hash(b"")),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
    assert_eq!(
        hex(&SHA512::hash(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(
        hex(&SHA512::hash(&vec![b'a'; 1_000_000])),
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    );
}

#[test]
fn sha224MatchesTheExamplesOfFIPS180AndHashlib() {
    assert_eq!(
        hex(&SHA224::hash(b"")),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    );
    assert_eq!(
        hex(&SHA224::hash(b"abc")),
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    );
    assert_eq!(
        hex(&SHA224::hash(twoBlockMessage)),
        "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
    );
    assert_eq!(
        hex(&SHA224::hash(&vec![b'a'; 1_000_000])),
        "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
    );
    // The lengths around the padding edges of a 64-byte block.
    for (length, expected) in [
        (
            55,
            "8991dfba74284e04dc7581c7c3e4068ff6cb7a63733361429834bb56",
        ),
        (
            56,
            "2b2cd637c16ad7290bb067ad7d8fd04e204fa43a84366afc7130f4ef",
        ),
        (
            63,
            "049e8dd7eab3378ce9f823bfb569e5b270235d4b7f9623606971998f",
        ),
        (
            64,
            "c37b88a3522dbf7ac30d1c68ea397ac11d4773571aed01ddab73531e",
        ),
        (
            119,
            "762f18c0df65c3d0ea64126c8a6e51db4425e76d4d969ed0f83899be",
        ),
        (
            120,
            "d022deb78772a77e8b91d68f90ca1f636e8fe047ae219434ced18eef",
        ),
    ] {
        assert_eq!(
            hex(&SHA224::hash(&countingMessage(length))),
            expected,
            "{length}"
        );
    }
}

#[test]
fn sha512Truncated224MatchesTheExamplesOfFIPS180AndHashlib() {
    assert_eq!(
        hex(&SHA512224::hash(b"")),
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
    );
    assert_eq!(
        hex(&SHA512224::hash(b"abc")),
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
    );
    assert_eq!(
        hex(&SHA512224::hash(fourBlockMessage)),
        "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9"
    );
    assert_eq!(
        hex(&SHA512224::hash(&vec![b'a'; 1_000_000])),
        "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287"
    );
    for (length, expected) in [
        (
            111,
            "f8810ee322210d0f4cbd7a4e92e7d7e72b63d2777dcb531e13ddd690",
        ),
        (
            112,
            "8099918892ebbd31215c9bb5e4e53c0b52927b000ced0720d2c65a22",
        ),
        (
            127,
            "29d2c4166a36e07b2dcd3a7c988dcb14776dc187040f6a733162efb7",
        ),
        (
            128,
            "49a64b72a88a3c93432b6e4c59a1b4908403f70e46e13bf7494fbe88",
        ),
        (
            239,
            "5f3fd8a5a4ef847d833b2faaa74a30fe51d22c68244298a25302b7ed",
        ),
        (
            240,
            "181dbae9308b111d4ae06a6229d6038c4afffb93a0eafda9cf1e83aa",
        ),
    ] {
        assert_eq!(
            hex(&SHA512224::hash(&countingMessage(length))),
            expected,
            "{length}"
        );
    }
}

#[test]
fn sha512Truncated256MatchesTheExamplesOfFIPS180AndHashlib() {
    assert_eq!(
        hex(&SHA512256::hash(b"")),
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
    );
    assert_eq!(
        hex(&SHA512256::hash(b"abc")),
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    );
    assert_eq!(
        hex(&SHA512256::hash(fourBlockMessage)),
        "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"
    );
    assert_eq!(
        hex(&SHA512256::hash(&vec![b'a'; 1_000_000])),
        "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21"
    );
    for (length, expected) in [
        (
            111,
            "bd209f60b0d04102a09175297fd255367e54b5a5605b928635c606306914363f",
        ),
        (
            112,
            "2cafeb0882cc405167e9a255b8581a66dc683212474902dd453dbca20a94e61a",
        ),
        (
            127,
            "c26bc7e9315e62ab0dc6aeb577724d07c09b0c6fdfc0a9f08d8548047c032248",
        ),
        (
            128,
            "2ff11194b2aec1f943cb5f130ba647c151334068083194d7281a55d607ae255f",
        ),
        (
            239,
            "b81472d255d80182e196481e5866aa207761a152302a0237e242eb88c577a428",
        ),
        (
            240,
            "6ca13c55886b74a5ca2ac9782c4b9a49fe3aeeefdfc0cefc34984872fb4c54fd",
        ),
    ] {
        assert_eq!(
            hex(&SHA512256::hash(&countingMessage(length))),
            expected,
            "{length}"
        );
    }
}

/// Every split of inputs of every length up to three blocks gives the one-shot digest. The
/// lengths cross each padding edge: 55, 56, 63 and 64 bytes for SHA-224 and SHA-256, 111, 112,
/// 127 and 128 bytes for SHA-384, SHA-512, SHA-512/224 and SHA-512/256.
#[test]
fn splitInputGivesTheOneShotDigestAtEveryLength() {
    let input: Vec<u8> = (0..=255u8).cycle().take(384).collect();
    for length in 0..input.len() {
        let message = &input[..length];
        for split in [0, 1, length / 2, length.saturating_sub(1), length] {
            let (first, second) = message.split_at(split.min(length));
            let mut sha256 = SHA256::new();
            sha256.absorb(first);
            sha256.absorb(second);
            assert_eq!(
                sha256.finalize(),
                SHA256::hash(message),
                "SHA-256 length {length} split {split}"
            );
            let mut sha384 = SHA384::default();
            sha384.absorb(first);
            sha384.absorb(second);
            assert_eq!(
                sha384.finalize(),
                SHA384::hash(message),
                "SHA-384 length {length} split {split}"
            );
            let mut sha512 = SHA512::new();
            sha512.absorb(first);
            let snapshot = sha512.clone();
            sha512.absorb(second);
            assert_eq!(
                sha512.finalize(),
                SHA512::hash(message),
                "SHA-512 length {length} split {split}"
            );
            let mut resumed = snapshot;
            resumed.absorb(second);
            assert_eq!(
                resumed.finalize(),
                SHA512::hash(message),
                "SHA-512 clone length {length}"
            );
            let mut sha224 = SHA224::default();
            sha224.absorb(first);
            let sha224Snapshot = sha224.clone();
            sha224.absorb(second);
            assert_eq!(
                sha224.finalize(),
                SHA224::hash(message),
                "SHA-224 length {length} split {split}"
            );
            let mut sha224Resumed = sha224Snapshot;
            sha224Resumed.absorb(second);
            assert_eq!(sha224Resumed.finalize(), SHA224::hash(message));
            let mut sha512224 = SHA512224::default();
            sha512224.absorb(first);
            sha512224.absorb(second);
            assert_eq!(
                sha512224.finalize(),
                SHA512224::hash(message),
                "SHA-512/224 length {length} split {split}"
            );
            let mut sha512256 = SHA512256::default();
            sha512256.absorb(first);
            let sha512256Snapshot = sha512256.clone();
            sha512256.absorb(second);
            assert_eq!(
                sha512256.finalize(),
                SHA512256::hash(message),
                "SHA-512/256 length {length} split {split}"
            );
            let mut sha512256Resumed = sha512256Snapshot;
            sha512256Resumed.absorb(second);
            assert_eq!(sha512256Resumed.finalize(), SHA512256::hash(message));
        }
    }
}

#[test]
fn changingOneByteChangesTheDigest() {
    let message = b"the quick brown fox".to_vec();
    for index in 0..message.len() {
        let mut changed = message.clone();
        changed[index] ^= 1;
        assert_ne!(SHA256::hash(&changed), SHA256::hash(&message));
        assert_ne!(SHA384::hash(&changed), SHA384::hash(&message));
        assert_ne!(SHA512::hash(&changed), SHA512::hash(&message));
        assert_ne!(SHA224::hash(&changed), SHA224::hash(&message));
        assert_ne!(SHA512224::hash(&changed), SHA512224::hash(&message));
        assert_ne!(SHA512256::hash(&changed), SHA512256::hash(&message));
    }
}
