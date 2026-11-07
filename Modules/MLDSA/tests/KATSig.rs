//! The liboqs known-answer test of `tests/kat_sig.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/sig/kats.json`.

use OQSNativeAlgorithmTests::{KnownAnswerDigests, SignatureKnownAnswerTest};
use OQSNativeDomain::Signing;
use OQSNativeMLDSA::MLDSA;

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
fn mldsa44GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MLDSA::mldsa44);
}

#[test]
fn mldsa65GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MLDSA::mldsa65);
}

#[test]
fn mldsa87GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MLDSA::mldsa87);
}

#[test]
fn mldsa44GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MLDSA::mldsa44);
}

#[test]
fn mldsa65GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MLDSA::mldsa65);
}

#[test]
fn mldsa87GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MLDSA::mldsa87);
}
