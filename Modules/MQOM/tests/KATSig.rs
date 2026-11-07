//! The liboqs known-answer test of `tests/kat_sig.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/sig/kats.json`.
//!
//! The `all` run makes 100 key pairs and signatures, which take minutes for the twelve sets in a
//! test build. Those tests are ignored in the fast suite, and
//! `cargo test --release -p oqs-native-mqom --test KATSig -- --ignored` runs them. The parity
//! program checks the `all` digest of each set in a release build with `known-answers`.

use OQSNativeAlgorithmTests::{KnownAnswerDigests, SignatureKnownAnswerTest};
use OQSNativeDomain::Signing;
use OQSNativeMQOM::MQOM;

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
fn mqom2Cat1GF16FastR3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat1GF16FastR3);
}

#[test]
fn mqom2Cat1GF16FastR5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat1GF16FastR5);
}

#[test]
fn mqom2Cat1GF16ShortR3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat1GF16ShortR3);
}

#[test]
fn mqom2Cat1GF16ShortR5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat1GF16ShortR5);
}

#[test]
fn mqom2Cat3GF16FastR3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat3GF16FastR3);
}

#[test]
fn mqom2Cat3GF16FastR5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat3GF16FastR5);
}

#[test]
fn mqom2Cat3GF16ShortR3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat3GF16ShortR3);
}

#[test]
fn mqom2Cat3GF16ShortR5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat3GF16ShortR5);
}

#[test]
fn mqom2Cat5GF16FastR3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat5GF16FastR3);
}

#[test]
fn mqom2Cat5GF16FastR5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat5GF16FastR5);
}

#[test]
fn mqom2Cat5GF16ShortR3GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat5GF16ShortR3);
}

#[test]
fn mqom2Cat5GF16ShortR5GivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&MQOM::mqom2Cat5GF16ShortR5);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat1GF16FastR3GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat1GF16FastR3);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat1GF16FastR5GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat1GF16FastR5);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat1GF16ShortR3GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat1GF16ShortR3);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat1GF16ShortR5GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat1GF16ShortR5);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat3GF16FastR3GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat3GF16FastR3);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat3GF16FastR5GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat3GF16FastR5);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat3GF16ShortR3GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat3GF16ShortR3);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat3GF16ShortR5GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat3GF16ShortR5);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat5GF16FastR3GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat5GF16FastR3);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat5GF16FastR5GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat5GF16FastR5);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat5GF16ShortR3GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat5GF16ShortR3);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --release -- --ignored"]
fn mqom2Cat5GF16ShortR5GivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&MQOM::mqom2Cat5GF16ShortR5);
}
