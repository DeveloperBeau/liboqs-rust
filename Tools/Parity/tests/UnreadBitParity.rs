//! Parity with the C library for the bits that a verification does not read.
//!
//! The SNOVA code reads an odd count of GF(16) elements from the low half of the last byte
//! only. Three sets have an odd count of elements in the variables of a signature, and two in
//! the blocks P22 of a public key, so a signature or a public key with that high half changed
//! still verifies. The variations change random bits, and this test changes exactly those, on
//! both sides.

use OQSNative::{SNOVA, Signing};
use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeParity::LargeStack;

const message: &[u8] = b"the quick brown fox";

#[test]
fn snovaJudgesSignaturesAndKeysWithAChangedHighHalfLikeTheCLibrary() {
    LargeStack::run(|| {
        // SNOVA_24_5_5 has both odd counts, SNOVA_25_8_3 and SNOVA_29_6_5 the odd signature,
        // SNOVA_49_11_3 the odd public key, and SNOVA_24_5_4 neither.
        let expectedAcceptances = [
            (&SNOVA::snova24x5x5, 2),
            (&SNOVA::snova25x8x3, 1),
            (&SNOVA::snova29x6x5, 1),
            (&SNOVA::snova49x11x3, 1),
            (&SNOVA::snova24x5x4, 0),
        ];
        for (scheme, expected) in expectedAcceptances {
            let description = scheme.description();
            let name = description.name;
            let keyPair = scheme
                .generateKeyPair(&mut NISTKATRandom::new(&[7; 48], None))
                .expect("a key pair");
            let signature = scheme
                .sign(
                    message,
                    keyPair.secretKey.bytes(),
                    &mut NISTKATRandom::new(&[8; 48], None),
                )
                .expect("a signature");
            let lastVariableByte = description.signatureLength - 16 - 1;
            let mut changedSignature = signature.clone();
            changedSignature[lastVariableByte] ^= 0xF0;
            let mut changedKey = keyPair.publicKey.clone();
            let lastKeyByte = changedKey.len() - 1;
            changedKey[lastKeyByte] ^= 0xF0;
            let mut changedLowHalf = signature.clone();
            changedLowHalf[lastVariableByte] ^= 0x01;
            let mut acceptanceCount = 0;
            for (label, signature, publicKey) in [
                (
                    "high half of the signature",
                    &changedSignature,
                    &keyPair.publicKey,
                ),
                ("high half of the public key", &signature, &changedKey),
                (
                    "low half of the signature",
                    &changedLowHalf,
                    &keyPair.publicKey,
                ),
            ] {
                let cVerdict = COracle::new(OracleRandomness::nist([0; 48]))
                    .isValidSignature(name, signature, message, publicKey);
                let rustVerdict = scheme.isValidSignature(signature, message, publicKey);
                assert_eq!(rustVerdict, cVerdict, "{name}: {label}");
                acceptanceCount += usize::from(cVerdict);
            }
            assert_eq!(acceptanceCount, expected, "{name}");
        }
    });
}
