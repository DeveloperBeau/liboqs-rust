//! The liboqs known-answer test of `tests/kat_kem.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/kem/kats.json`.
//!
//! The `all` run of 100 counts takes from 4 seconds for FrodoKEM-640-AES to a minute for
//! FrodoKEM-1344-SHAKE in the dev profile, so those tests are ignored in the default run. A
//! release build runs all twelve in about a minute of processor time.

use OQSNativeAlgorithmTests::{KEMKnownAnswerTest, KnownAnswerDigests};
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeFrodoKEM::FrodoKEM;

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
fn frodoKEM640AESGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::frodoKEM640AES);
}

#[test]
fn frodoKEM640SHAKEGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::frodoKEM640SHAKE);
}

#[test]
fn frodoKEM976AESGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::frodoKEM976AES);
}

#[test]
fn frodoKEM976SHAKEGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::frodoKEM976SHAKE);
}

#[test]
fn frodoKEM1344AESGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::frodoKEM1344AES);
}

#[test]
fn frodoKEM1344SHAKEGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::frodoKEM1344SHAKE);
}

#[test]
fn eFrodoKEM640AESGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::eFrodoKEM640AES);
}

#[test]
fn eFrodoKEM640SHAKEGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::eFrodoKEM640SHAKE);
}

#[test]
fn eFrodoKEM976AESGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::eFrodoKEM976AES);
}

#[test]
fn eFrodoKEM976SHAKEGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::eFrodoKEM976SHAKE);
}

#[test]
fn eFrodoKEM1344AESGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::eFrodoKEM1344AES);
}

#[test]
fn eFrodoKEM1344SHAKEGivesTheKnownAnswerOfLiboqs() {
    checkSingleDigest(&FrodoKEM::eFrodoKEM1344SHAKE);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn frodoKEM640AESGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::frodoKEM640AES);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn frodoKEM640SHAKEGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::frodoKEM640SHAKE);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn frodoKEM976AESGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::frodoKEM976AES);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn frodoKEM976SHAKEGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::frodoKEM976SHAKE);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn frodoKEM1344AESGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::frodoKEM1344AES);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn frodoKEM1344SHAKEGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::frodoKEM1344SHAKE);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn eFrodoKEM640AESGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::eFrodoKEM640AES);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn eFrodoKEM640SHAKEGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::eFrodoKEM640SHAKE);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn eFrodoKEM976AESGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::eFrodoKEM976AES);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn eFrodoKEM976SHAKEGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::eFrodoKEM976SHAKE);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn eFrodoKEM1344AESGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::eFrodoKEM1344AES);
}

#[test]
#[ignore = "100 counts take up to a minute in the dev profile: run them with `cargo test --release -- --ignored`"]
fn eFrodoKEM1344SHAKEGivesEveryKnownAnswerOfLiboqs() {
    checkAllDigest(&FrodoKEM::eFrodoKEM1344SHAKE);
}
