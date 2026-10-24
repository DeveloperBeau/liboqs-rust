//! Known answers of FIPS 180-4 for SHA-256, SHA-384 and SHA-512, and the consistency of the
//! incremental form with the one-shot form.
//!
//! liboqs `tests/test_hash.py` compares its hashes with Python `hashlib` on random inputs.
//! The port compares them with the C library in the parity tests of the facade crate.

use OQSNativeSHA2::{SHA256, SHA384, SHA512};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const twoBlockMessage: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

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

/// Every split of inputs of every length up to three blocks gives the one-shot digest. The
/// lengths cross each padding edge: 55, 56, 63 and 64 bytes for SHA-256, 111, 112, 127 and
/// 128 bytes for SHA-384 and SHA-512.
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
    }
}
