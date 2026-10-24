//! The liboqs known-answer test of `tests/kat_kem.c` and `tests/test_kat.py` for each
//! parameter set: the digest of the `single` run and of the `all` run must equal the digests in
//! `tests/KATs/kem/kats.json`.

use OQSNativeAlgorithmTests::{KEMKnownAnswerTest, KnownAnswerDigests};
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeMLKEM::{Kyber, MLKEM};

fn checkDigests(mechanism: &dyn KeyEncapsulating) {
    let name = mechanism.description().name;
    let digests = KnownAnswerDigests::kem();
    assert_eq!(
        KEMKnownAnswerTest::digest(mechanism, false).as_deref(),
        Ok(digests.singleDigest(name).expect("a single digest")),
        "{name}, single"
    );
    assert_eq!(
        KEMKnownAnswerTest::digest(mechanism, true).as_deref(),
        Ok(digests.allDigest(name).expect("an all digest")),
        "{name}, all"
    );
}

#[test]
fn mlkem512GivesTheKnownAnswersOfLiboqs() {
    checkDigests(&MLKEM::mlkem512);
}

#[test]
fn mlkem768GivesTheKnownAnswersOfLiboqs() {
    checkDigests(&MLKEM::mlkem768);
}

#[test]
fn mlkem1024GivesTheKnownAnswersOfLiboqs() {
    checkDigests(&MLKEM::mlkem1024);
}

#[test]
fn kyber512GivesTheKnownAnswersOfLiboqs() {
    checkDigests(&Kyber::kyber512);
}

#[test]
fn kyber768GivesTheKnownAnswersOfLiboqs() {
    checkDigests(&Kyber::kyber768);
}

#[test]
fn kyber1024GivesTheKnownAnswersOfLiboqs() {
    checkDigests(&Kyber::kyber1024);
}
