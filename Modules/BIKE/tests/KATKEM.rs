//! The liboqs known-answer test of `tests/kat_kem.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/kem/kats.json`.

use OQSNativeAlgorithmTests::{KEMKnownAnswerTest, KnownAnswerDigests};
use OQSNativeBIKE::BIKE;
use OQSNativeDomain::KeyEncapsulating;

fn checkSingleDigest(mechanism: &dyn KeyEncapsulating) {
    let name = mechanism.description().name;
    assert_eq!(
        KEMKnownAnswerTest::digest(mechanism, false).as_deref(),
        Ok(KnownAnswerDigests::kem()
            .singleDigest(name)
            .expect("a single digest")),
        "{name}, single"
    );
}

fn checkAllDigest(mechanism: &dyn KeyEncapsulating) {
    let name = mechanism.description().name;
    assert_eq!(
        KEMKnownAnswerTest::digest(mechanism, true).as_deref(),
        Ok(KnownAnswerDigests::kem()
            .allDigest(name)
            .expect("an all digest")),
        "{name}, all"
    );
}

#[test]
fn bikeL1GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&BIKE::bikeL1);
}

#[test]
fn bikeL3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&BIKE::bikeL3);
}

#[test]
fn bikeL5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&BIKE::bikeL5);
}

#[test]
fn bikeL1GivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&BIKE::bikeL1);
}

#[test]
fn bikeL3GivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&BIKE::bikeL3);
}

#[test]
fn bikeL5GivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&BIKE::bikeL5);
}
