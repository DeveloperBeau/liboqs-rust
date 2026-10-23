//! The liboqs known-answer test of `tests/kat_sig.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/sig/kats.json`.
//!
//! The `all` runs make 100 key pairs and signatures for each set, several minutes of processor
//! time for the eighteen sets in a test build. They are ignored in the fast suite, and
//! `cargo test -p oqs-native-cross --test KATSig -- --ignored` runs them. The parity program
//! runs the `all` digests of each set in a release build.

use OQSNativeAlgorithmTests::{KnownAnswerDigests, SignatureKnownAnswerTest};
use OQSNativeCROSS::CROSS;
use OQSNativeDomain::Signing;

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
fn crossRSDP128BalancedGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDP128Balanced);
}

#[test]
fn crossRSDP128FastGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDP128Fast);
}

#[test]
fn crossRSDP128SmallGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDP128Small);
}

#[test]
fn crossRSDP192BalancedGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDP192Balanced);
}

#[test]
fn crossRSDP192FastGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDP192Fast);
}

#[test]
fn crossRSDP192SmallGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDP192Small);
}

#[test]
fn crossRSDP256BalancedGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDP256Balanced);
}

#[test]
fn crossRSDP256FastGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDP256Fast);
}

#[test]
fn crossRSDP256SmallGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDP256Small);
}

#[test]
fn crossRSDPG128BalancedGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDPG128Balanced);
}

#[test]
fn crossRSDPG128FastGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDPG128Fast);
}

#[test]
fn crossRSDPG128SmallGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDPG128Small);
}

#[test]
fn crossRSDPG192BalancedGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDPG192Balanced);
}

#[test]
fn crossRSDPG192FastGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDPG192Fast);
}

#[test]
fn crossRSDPG192SmallGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDPG192Small);
}

#[test]
fn crossRSDPG256BalancedGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDPG256Balanced);
}

#[test]
fn crossRSDPG256FastGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDPG256Fast);
}

#[test]
fn crossRSDPG256SmallGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&CROSS::crossRSDPG256Small);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDP128BalancedGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDP128Balanced);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDP128FastGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDP128Fast);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDP128SmallGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDP128Small);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDP192BalancedGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDP192Balanced);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDP192FastGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDP192Fast);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDP192SmallGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDP192Small);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDP256BalancedGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDP256Balanced);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDP256FastGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDP256Fast);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDP256SmallGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDP256Small);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDPG128BalancedGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDPG128Balanced);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDPG128FastGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDPG128Fast);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDPG128SmallGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDPG128Small);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDPG192BalancedGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDPG192Balanced);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDPG192FastGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDPG192Fast);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDPG192SmallGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDPG192Small);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDPG256BalancedGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDPG256Balanced);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDPG256FastGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDPG256Fast);
}

#[test]
#[ignore = "slow: 100 key pairs and signatures, run with --ignored"]
fn crossRSDPG256SmallGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&CROSS::crossRSDPG256Small);
}
