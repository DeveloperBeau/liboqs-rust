//! The liboqs known-answer test of `tests/kat_kem.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/kem/kats.json`. HQC draws its known-answer bytes from the SHAKE256 generator of
//! `tests/test_helpers.c`, which `KEMKnownAnswerTest` selects by name.

use OQSNativeAlgorithmTests::{KEMKnownAnswerTest, KnownAnswerDigests};
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeHQC::HQC;

fn checkDigest(mechanism: &dyn KeyEncapsulating, isAll: bool) {
    let name = mechanism.description().name;
    let digests = KnownAnswerDigests::kem();
    let expected = if isAll {
        digests.allDigest(name).expect("an all digest")
    } else {
        digests.singleDigest(name).expect("a single digest")
    };
    assert_eq!(
        KEMKnownAnswerTest::digest(mechanism, isAll).as_deref(),
        Ok(expected),
        "{name}, {}",
        if isAll { "all" } else { "single" }
    );
}

#[test]
fn hqc1GivesTheSingleKnownAnswerOfLiboqs() {
    checkDigest(&HQC::hqc1, false);
}

#[test]
fn hqc3GivesTheSingleKnownAnswerOfLiboqs() {
    checkDigest(&HQC::hqc3, false);
}

#[test]
fn hqc5GivesTheSingleKnownAnswerOfLiboqs() {
    checkDigest(&HQC::hqc5, false);
}

#[test]
fn hqc1GivesTheAllKnownAnswersOfLiboqs() {
    checkDigest(&HQC::hqc1, true);
}

#[test]
fn hqc3GivesTheAllKnownAnswersOfLiboqs() {
    checkDigest(&HQC::hqc3, true);
}

#[test]
fn hqc5GivesTheAllKnownAnswersOfLiboqs() {
    checkDigest(&HQC::hqc5, true);
}
