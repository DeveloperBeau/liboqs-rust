//! The liboqs known-answer test of `tests/kat_kem.c` and `tests/test_kat.py`: the digest of the
//! `single` run and of the `all` run of sntrup761 must equal the digests in
//! `tests/KATs/kem/kats.json`.
//!
//! The `all` run of 100 counts takes 3 seconds of processor time in the dev profile, so that
//! test is ignored in the default run. A release build and `parity known-answers` run it.

use OQSNativeAlgorithmTests::{KEMKnownAnswerTest, KnownAnswerDigests};
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeNTRUPrime::NTRUPrime;

#[test]
fn sntrup761GivesTheKnownAnswerOfLiboqs() {
    let mechanism = &NTRUPrime::sntrup761;
    let name = mechanism.description().name;
    assert_eq!(
        KEMKnownAnswerTest::digest(mechanism, false).as_deref(),
        Ok(KnownAnswerDigests::kem()
            .singleDigest(name)
            .expect("a single digest")),
        "{name}, single"
    );
}

#[test]
#[ignore = "100 counts take 3 seconds of processor time in the dev profile: run them with `cargo test --release -- --ignored`"]
fn sntrup761GivesEveryKnownAnswerOfLiboqs() {
    let mechanism = &NTRUPrime::sntrup761;
    let name = mechanism.description().name;
    assert_eq!(
        KEMKnownAnswerTest::digest(mechanism, true).as_deref(),
        Ok(KnownAnswerDigests::kem()
            .allDigest(name)
            .expect("an all digest")),
        "{name}, all"
    );
}
