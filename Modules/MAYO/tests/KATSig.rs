//! The liboqs known-answer test of `tests/kat_sig.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/sig/kats.json`.

use OQSNativeAlgorithmTests::{KnownAnswerDigests, SignatureKnownAnswerTest};
use OQSNativeDomain::Signing;
use OQSNativeMAYO::MAYO;

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
fn mayo1GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MAYO::mayo1);
}

#[test]
fn mayo2GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MAYO::mayo2);
}

#[test]
fn mayo3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MAYO::mayo3);
}

#[test]
fn mayo5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MAYO::mayo5);
}

#[test]
fn mayo1GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MAYO::mayo1);
}

#[test]
fn mayo2GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MAYO::mayo2);
}

#[test]
fn mayo3GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MAYO::mayo3);
}

#[test]
fn mayo5GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MAYO::mayo5);
}
