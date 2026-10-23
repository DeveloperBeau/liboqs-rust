//! The liboqs known-answer test of `tests/kat_sig.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/sig/kats.json`.
//!
//! The `all` runs make 100 key pairs and signatures for each set, about 23 seconds of processor
//! time for the four sets in a test build. They are ignored in the fast suite, and
//! `cargo test -p oqs-native-falcon --test KATSig -- --ignored` runs them. The parity program
//! compares the port with the C library for 1000 variations of each set.

use OQSNativeAlgorithmTests::{KnownAnswerDigests, SignatureKnownAnswerTest};
use OQSNativeDomain::Signing;
use OQSNativeFalcon::Falcon;

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
fn falcon512GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&Falcon::falcon512);
}

#[test]
fn falcon1024GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&Falcon::falcon1024);
}

#[test]
fn falconPadded512GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&Falcon::falconPadded512);
}

#[test]
fn falconPadded1024GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&Falcon::falconPadded1024);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn falcon512GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&Falcon::falcon512);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn falcon1024GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&Falcon::falcon1024);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn falconPadded512GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&Falcon::falconPadded512);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn falconPadded1024GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&Falcon::falconPadded1024);
}
