//! The liboqs known-answer test of `tests/kat_sig.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/sig/kats.json`.
//!
//! The `all` runs make 100 key pairs, signatures and verifications for each set, about 70
//! seconds of processor time for the twelve sets in a test build. They are ignored in the fast
//! suite, and `cargo test -p oqs-native-snova --test KATSig -- --ignored` runs them. The parity
//! program runs them in a release build, and compares the port with the C library for 1000
//! variations of each set.

use OQSNativeAlgorithmTests::{KnownAnswerDigests, SignatureKnownAnswerTest};
use OQSNativeDomain::Signing;
use OQSNativeSNOVA::SNOVA;

fn checkSingleDigest(scheme: &dyn Signing) {
    let name = scheme.description().name;
    assert_eq!(
        SignatureKnownAnswerTest::digest(scheme, false).as_deref(),
        Ok(KnownAnswerDigests::signature()
            .singleDigest(name)
            .expect("a single digest")),
        "{name}, single"
    );
}

fn checkAllDigest(scheme: &dyn Signing) {
    let name = scheme.description().name;
    assert_eq!(
        SignatureKnownAnswerTest::digest(scheme, true).as_deref(),
        Ok(KnownAnswerDigests::signature()
            .allDigest(name)
            .expect("an all digest")),
        "{name}, all"
    );
}

#[test]
fn snova24x5x4GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova24x5x4);
}

#[test]
fn snova24x5x4SHAKEGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova24x5x4SHAKE);
}

#[test]
fn snova24x5x4WithExpandedSecretKeyGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova24x5x4WithExpandedSecretKey);
}

#[test]
fn snova24x5x4SHAKEWithExpandedSecretKeyGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova24x5x4SHAKEWithExpandedSecretKey);
}

#[test]
fn snova37x17x2GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova37x17x2);
}

#[test]
fn snova25x8x3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova25x8x3);
}

#[test]
fn snova56x25x2GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova56x25x2);
}

#[test]
fn snova49x11x3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova49x11x3);
}

#[test]
fn snova37x8x4GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova37x8x4);
}

#[test]
fn snova24x5x5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova24x5x5);
}

#[test]
fn snova60x10x4GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova60x10x4);
}

#[test]
fn snova29x6x5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&SNOVA::snova29x6x5);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova24x5x4GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova24x5x4);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova24x5x4SHAKEGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova24x5x4SHAKE);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova24x5x4WithExpandedSecretKeyGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova24x5x4WithExpandedSecretKey);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova24x5x4SHAKEWithExpandedSecretKeyGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova24x5x4SHAKEWithExpandedSecretKey);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova37x17x2GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova37x17x2);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova25x8x3GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova25x8x3);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova56x25x2GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova56x25x2);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova49x11x3GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova49x11x3);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova37x8x4GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova37x8x4);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova24x5x5GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova24x5x5);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova60x10x4GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova60x10x4);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn snova29x6x5GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&SNOVA::snova29x6x5);
}
