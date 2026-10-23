//! The liboqs known-answer test of `tests/kat_kem.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/kem/kats.json`.
//!
//! The `all` run of Classic McEliece has 10 counts. Each count makes a key pair, which takes up
//! to a few seconds for the large sets in the dev profile, so the `all` tests are ignored in the
//! default run. `parity known-answers --all` runs them in a release build.

use OQSNativeAlgorithmTests::{KEMKnownAnswerTest, KnownAnswerDigests};
use OQSNativeClassicMcEliece::ClassicMcEliece;
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
fn classicMcEliece348864GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece348864);
}

#[test]
fn classicMcEliece348864fGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece348864f);
}

#[test]
fn classicMcEliece460896GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece460896);
}

#[test]
fn classicMcEliece460896fGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece460896f);
}

#[test]
fn classicMcEliece6688128GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece6688128);
}

#[test]
fn classicMcEliece6688128fGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece6688128f);
}

#[test]
fn classicMcEliece6960119GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece6960119);
}

#[test]
fn classicMcEliece6960119fGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece6960119f);
}

#[test]
fn classicMcEliece8192128GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece8192128);
}

#[test]
fn classicMcEliece8192128fGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&ClassicMcEliece::classicMcEliece8192128f);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece348864GivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece348864);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece348864fGivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece348864f);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece460896GivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece460896);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece460896fGivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece460896f);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece6688128GivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece6688128);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece6688128fGivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece6688128f);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece6960119GivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece6960119);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece6960119fGivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece6960119f);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece8192128GivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece8192128);
}

#[test]
#[ignore = "10 key pairs take up to half a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn classicMcEliece8192128fGivesTheAllKnownAnswerOfLiboqs() {
    checkAllDigest(&ClassicMcEliece::classicMcEliece8192128f);
}
