//! The liboqs known-answer test of `tests/kat_sig.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/sig/kats.json`.
//!
//! The `all` runs make 100 key pairs and signatures for each set and print every key in
//! hexadecimal, more than 10 MB of text for each count of OV-V. They take about 160 seconds of
//! processor time for the twelve sets in a test build, so the fast suite ignores them, and
//! `cargo test -p oqs-native-uov --test KATSig -- --ignored` runs them. The parity program
//! proves the `all` digests of each set in a release build with `known-answers`.

use OQSNativeAlgorithmTests::{KnownAnswerDigests, SignatureKnownAnswerTest};
use OQSNativeDomain::Signing;
use OQSNativeUOV::UOV;

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
fn ovIsGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovIs);
}

#[test]
fn ovIpGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovIp);
}

#[test]
fn ovIIIGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovIII);
}

#[test]
fn ovVGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovV);
}

#[test]
fn ovIsCompressedPublicKeyGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovIsCompressedPublicKey);
}

#[test]
fn ovIpCompressedPublicKeyGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovIpCompressedPublicKey);
}

#[test]
fn ovIIICompressedPublicKeyGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovIIICompressedPublicKey);
}

#[test]
fn ovVCompressedPublicKeyGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovVCompressedPublicKey);
}

#[test]
fn ovIsCompressedKeysGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovIsCompressedKeys);
}

#[test]
fn ovIpCompressedKeysGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovIpCompressedKeys);
}

#[test]
fn ovIIICompressedKeysGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovIIICompressedKeys);
}

#[test]
fn ovVCompressedKeysGivesTheSingleKnownAnswerOfLiboqs() {
    checkSingleDigest(&UOV::ovVCompressedKeys);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovIsGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovIs);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovIpGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovIp);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovIIIGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovIII);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovVGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovV);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovIsCompressedPublicKeyGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovIsCompressedPublicKey);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovIpCompressedPublicKeyGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovIpCompressedPublicKey);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovIIICompressedPublicKeyGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovIIICompressedPublicKey);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovVCompressedPublicKeyGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovVCompressedPublicKey);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovIsCompressedKeysGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovIsCompressedKeys);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovIpCompressedKeysGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovIpCompressedKeys);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovIIICompressedKeysGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovIIICompressedKeys);
}

#[test]
#[ignore = "slow: 100 key pairs of up to 5.3 MB each and their text, run with --ignored"]
fn ovVCompressedKeysGivesTheKnownAnswersOfEveryCountOfLiboqs() {
    checkAllDigest(&UOV::ovVCompressedKeys);
}
