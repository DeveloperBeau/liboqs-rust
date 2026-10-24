//! The liboqs known-answer test of `tests/kat_sig_stfl.c` for each LMS set with a response file:
//! the program verifies the signature of the response file and prints the message, the
//! signature and the public key, and the SHA-256 of what it prints must equal the digest in
//! `tests/KATs/sig_stfl/kats.json`.
//!
//! The response files of `LMS_SHA256_H5_W8_H5_W8` and `LMS_SHA256_H10_W4_H5_W8` are the test
//! cases 1 and 2 of RFC 8554, Appendix F. The files of `LMS_SHA256_H5_W1` and
//! `LMS_SHA256_H10_W1` hold a raw LMS public key and a raw LMS signature.

use OQSNativeAlgorithmTests::{
    StatefulKnownAnswerDigests, StatefulKnownAnswerTest, TestVectorFiles,
};
use OQSNativeDomain::StatefulSigning;
use OQSNativeLMS::LMS;

fn checkDigest(scheme: &LMS) {
    let name = scheme.description().name;
    let responseFile =
        TestVectorFiles::responseFile(name).unwrap_or_else(|message| panic!("{message}"));
    assert_eq!(
        StatefulKnownAnswerTest::digest(scheme, &responseFile).as_deref(),
        Ok(StatefulKnownAnswerDigests::digest(name).expect("a digest of liboqs")),
        "{name}"
    );
}

#[test]
fn lmsSHA256H5W1GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H5W1);
}

#[test]
fn lmsSHA256H5W2GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H5W2);
}

#[test]
fn lmsSHA256H5W4GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H5W4);
}

#[test]
fn lmsSHA256H5W8GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H5W8);
}

#[test]
fn lmsSHA256H10W1GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H10W1);
}

#[test]
fn lmsSHA256H10W2GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H10W2);
}

#[test]
fn lmsSHA256H10W4GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H10W4);
}

#[test]
fn lmsSHA256H10W8GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H10W8);
}

#[test]
fn lmsSHA256H15W1GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H15W1);
}

#[test]
fn lmsSHA256H15W2GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H15W2);
}

#[test]
fn lmsSHA256H15W4GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H15W4);
}

#[test]
fn lmsSHA256H15W8GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H15W8);
}

#[test]
fn lmsSHA256H20W1GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H20W1);
}

#[test]
fn lmsSHA256H20W2GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H20W2);
}

#[test]
fn lmsSHA256H20W4GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H20W4);
}

#[test]
fn lmsSHA256H20W8GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H20W8);
}

#[test]
fn lmsSHA256H5W8H5W8GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H5W8H5W8);
}

#[test]
fn lmsSHA256H10W4H5W8GivesTheKnownAnswerOfLiboqs() {
    checkDigest(&LMS::lmsSHA256H10W4H5W8);
}

#[test]
fn everySetWithADigestOfLiboqsHasItsTestHere() {
    // The digest file has entries for 18 LMS sets. The 4 sets of height 25 and 11 sets of two
    // levels have no response file in liboqs, and so no known answer.
    let names: Vec<&str> = StatefulKnownAnswerDigests::names()
        .into_iter()
        .filter(|name| name.starts_with("LMS"))
        .collect();
    assert_eq!(names.len(), 18);
    assert!(!names.contains(&"LMS_SHA256_H25_W1"));
    assert!(!names.contains(&"LMS_SHA256_H10_W8_H5_W8"));
}
