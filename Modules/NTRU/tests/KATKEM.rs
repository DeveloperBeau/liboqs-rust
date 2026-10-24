//! The liboqs known-answer test of `tests/kat_kem.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/kem/kats.json`.
//!
//! The `all` run of 100 counts takes from under a second of processor time for
//! NTRU-HPS-2048-509 to 5 seconds for NTRU-HRSS-1373 in the dev profile, so those tests are
//! ignored in the default run. A release build and `parity known-answers` run them.

use OQSNativeAlgorithmTests::{KEMKnownAnswerTest, KnownAnswerDigests};
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeNTRU::NTRU;

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
fn ntruHPS2048509GivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&NTRU::ntruHPS2048509);
}

#[test]
fn ntruHPS2048677GivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&NTRU::ntruHPS2048677);
}

#[test]
fn ntruHPS4096821GivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&NTRU::ntruHPS4096821);
}

#[test]
fn ntruHPS40961229GivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&NTRU::ntruHPS40961229);
}

#[test]
fn ntruHRSS701GivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&NTRU::ntruHRSS701);
}

#[test]
fn ntruHRSS1373GivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&NTRU::ntruHRSS1373);
}

#[test]
#[ignore = "100 counts take up to 5 seconds of processor time in the dev profile: run them with `cargo test --release -- --ignored`"]
fn ntruHPS2048509GivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&NTRU::ntruHPS2048509);
}

#[test]
#[ignore = "100 counts take up to 5 seconds of processor time in the dev profile: run them with `cargo test --release -- --ignored`"]
fn ntruHPS2048677GivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&NTRU::ntruHPS2048677);
}

#[test]
#[ignore = "100 counts take up to 5 seconds of processor time in the dev profile: run them with `cargo test --release -- --ignored`"]
fn ntruHPS4096821GivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&NTRU::ntruHPS4096821);
}

#[test]
#[ignore = "100 counts take up to 5 seconds of processor time in the dev profile: run them with `cargo test --release -- --ignored`"]
fn ntruHPS40961229GivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&NTRU::ntruHPS40961229);
}

#[test]
#[ignore = "100 counts take up to 5 seconds of processor time in the dev profile: run them with `cargo test --release -- --ignored`"]
fn ntruHRSS701GivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&NTRU::ntruHRSS701);
}

#[test]
#[ignore = "100 counts take up to 5 seconds of processor time in the dev profile: run them with `cargo test --release -- --ignored`"]
fn ntruHRSS1373GivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&NTRU::ntruHRSS1373);
}
