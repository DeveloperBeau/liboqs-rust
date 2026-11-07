//! Known answers of SHA3-224, which the SHA-3 API of liboqs does not have, from Python
//! `hashlib`, as liboqs `tests/test_hash.py` checks its other hashes, and the consistency of the
//! incremental form with the one-shot form.

use OQSNativeSHA3::SHA3224;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The 448-bit message of the SHA-3 examples, as in `tests/test_sha3.c`.
const message448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

#[test]
fn sha3224MatchesTheExamplesOfFIPS202AndHashlib() {
    assert_eq!(
        hex(&SHA3224::hash(b"")),
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    );
    assert_eq!(
        hex(&SHA3224::hash(b"abc")),
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
    );
    assert_eq!(
        hex(&SHA3224::hash(message448)),
        "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"
    );
    assert_eq!(
        hex(&SHA3224::hash(&[0xA3; 200])),
        "9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0"
    );
    assert_eq!(
        hex(&SHA3224::hash(&vec![b'a'; 1_000_000])),
        "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"
    );
}

#[test]
fn sha3224MatchesHashlibAroundTheEdgesOfItsRate() {
    // The rate of SHA3-224 is 144 bytes, so these lengths fill one block, two blocks or one
    // byte less or more.
    let counting: Vec<u8> = (0..300).map(|index| index as u8).collect();
    for (length, expected) in [
        (
            143,
            "64d0e8a1be3cf30ef6727b30a6e428f7f068d44634c943d277ad8e7f",
        ),
        (
            144,
            "5be75e6a08f19913a1d8036c056cc4556b98dc90aeca3f2a0664dedc",
        ),
        (
            145,
            "90b861ac1b1598459ad8337afa9933ce2f1a6f972c57daf8fc2737e4",
        ),
        (
            287,
            "d0a87b49e62bc8d7a2bcc3c8104836c5e712f2a4b5fe52d67a23bab6",
        ),
        (
            288,
            "e0ae33f2dd63c31ef87f219c9b80c897669974b73d8a9fe64500887b",
        ),
    ] {
        assert_eq!(
            hex(&SHA3224::hash(&counting[..length])),
            expected,
            "{length}"
        );
    }
}

#[test]
fn sha3224InPiecesAndFromACloneGivesTheOneShotDigest() {
    let input: Vec<u8> = (0..=255u8).cycle().take(450).collect();
    for length in [0, 1, 143, 144, 145, 300, 450] {
        let message = &input[..length];
        let mut pieces = SHA3224::default();
        for piece in message.chunks(7) {
            pieces.absorb(piece);
        }
        let snapshot = pieces.clone();
        assert_eq!(pieces.finalize(), SHA3224::hash(message), "{length}");
        assert_eq!(snapshot.finalize(), SHA3224::hash(message), "{length}");
        let mut changed = message.to_vec();
        changed.push(0);
        assert_ne!(SHA3224::hash(&changed), SHA3224::hash(message), "{length}");
    }
}
