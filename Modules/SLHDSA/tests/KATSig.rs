//! The liboqs known-answer test of `tests/kat_sig.c` and `tests/test_kat.py` for each scheme.
//!
//! liboqs has no known answers of `kat_sig` for SLH-DSA. `combine_message_signature` of the C
//! program has no signed-message form for it, so the run fails, `tests/KATs/sig/kats.json`
//! holds no digest for it, and `tests/test_kat.py` and `tests/test_kat_all.py` skip every
//! SLH-DSA scheme, because the ACVP vectors of `VectorsSig.rs` test it instead. The frozen
//! snapshot of `Tools/Parity` holds the C base case of each scheme.

use OQSNativeAlgorithmTests::{KnownAnswerDigests, SignatureKnownAnswerTest, SignedMessageForm};
use OQSNativeSLHDSA::SLHDSA;

#[test]
fn katSigHasNoKnownAnswerRunForAnySLHDSAScheme() {
    assert_eq!(SLHDSA::schemes.len(), 156);
    for scheme in SLHDSA::schemes {
        let name = scheme.description().name;
        let refusal = Err(format!("{name} has no known-answer run in kat_sig"));
        assert_eq!(SignatureKnownAnswerTest::digest(*scheme, false), refusal);
        assert_eq!(SignatureKnownAnswerTest::digest(*scheme, true), refusal);
        assert_eq!(SignedMessageForm::of(name), None);
    }
}

#[test]
fn liboqsDigestFileHasNoSLHDSAEntry() {
    let digests = KnownAnswerDigests::signature();
    for scheme in SLHDSA::schemes {
        let name = scheme.description().name;
        assert_eq!(digests.singleDigest(name), None, "{name}");
        assert_eq!(digests.allDigest(name), None, "{name}");
    }
    assert!(
        digests
            .names()
            .iter()
            .all(|name| !name.starts_with("SLH_DSA"))
    );
}
