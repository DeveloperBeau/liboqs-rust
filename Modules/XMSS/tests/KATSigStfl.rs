//! The liboqs known-answer test of `tests/kat_sig_stfl.c` and `tests/test_kat.py` for each
//! parameter set: the program signs the message of the response file with the secret key of the
//! file, and the SHA-256 of what it prints must equal the digest of
//! `tests/KATs/sig_stfl/kats.json`. Each set signs once with a key of the file, so even the sets
//! of height 20 and 60 run in the default suite.

use OQSNativeAlgorithmTests::{
    StatefulKnownAnswerDigests, StatefulKnownAnswerTest, TestVectorFiles,
};
use OQSNativeDomain::StatefulSigning;
use OQSNativeXMSS::{XMSS, XMSSMT};

fn checkDigest(scheme: &dyn StatefulSigning) {
    let name = scheme.description().name;
    let responseFile =
        TestVectorFiles::responseFile(name).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        StatefulKnownAnswerTest::digest(scheme, &responseFile).as_deref(),
        Ok(StatefulKnownAnswerDigests::digest(name).expect("a digest of liboqs")),
        "{name}"
    );
}

/// A test that the known-answer program of a set gives the digest of liboqs.
macro_rules! knownAnswerTest {
    ($test:ident, $scheme:expr) => {
        #[test]
        fn $test() {
            checkDigest(&$scheme);
        }
    };
}

knownAnswerTest!(
    xmssSHA2Height10Bits256GivesTheKnownAnswerOfLiboqs,
    XMSS::sha2Height10Bits256
);
knownAnswerTest!(
    xmssSHA2Height16Bits256GivesTheKnownAnswerOfLiboqs,
    XMSS::sha2Height16Bits256
);
knownAnswerTest!(
    xmssSHA2Height20Bits256GivesTheKnownAnswerOfLiboqs,
    XMSS::sha2Height20Bits256
);
knownAnswerTest!(
    xmssSHAKE128Height10Bits256GivesTheKnownAnswerOfLiboqs,
    XMSS::shake128Height10Bits256
);
knownAnswerTest!(
    xmssSHAKE128Height16Bits256GivesTheKnownAnswerOfLiboqs,
    XMSS::shake128Height16Bits256
);
knownAnswerTest!(
    xmssSHAKE128Height20Bits256GivesTheKnownAnswerOfLiboqs,
    XMSS::shake128Height20Bits256
);
knownAnswerTest!(
    xmssSHA2Height10Bits512GivesTheKnownAnswerOfLiboqs,
    XMSS::sha2Height10Bits512
);
knownAnswerTest!(
    xmssSHA2Height16Bits512GivesTheKnownAnswerOfLiboqs,
    XMSS::sha2Height16Bits512
);
knownAnswerTest!(
    xmssSHA2Height20Bits512GivesTheKnownAnswerOfLiboqs,
    XMSS::sha2Height20Bits512
);
knownAnswerTest!(
    xmssSHAKE256Height10Bits512GivesTheKnownAnswerOfLiboqs,
    XMSS::shake256Height10Bits512
);
knownAnswerTest!(
    xmssSHAKE256Height16Bits512GivesTheKnownAnswerOfLiboqs,
    XMSS::shake256Height16Bits512
);
knownAnswerTest!(
    xmssSHAKE256Height20Bits512GivesTheKnownAnswerOfLiboqs,
    XMSS::shake256Height20Bits512
);
knownAnswerTest!(
    xmssSHA2Height10Bits192GivesTheKnownAnswerOfLiboqs,
    XMSS::sha2Height10Bits192
);
knownAnswerTest!(
    xmssSHA2Height16Bits192GivesTheKnownAnswerOfLiboqs,
    XMSS::sha2Height16Bits192
);
knownAnswerTest!(
    xmssSHA2Height20Bits192GivesTheKnownAnswerOfLiboqs,
    XMSS::sha2Height20Bits192
);
knownAnswerTest!(
    xmssSHAKE256Height10Bits192GivesTheKnownAnswerOfLiboqs,
    XMSS::shake256Height10Bits192
);
knownAnswerTest!(
    xmssSHAKE256Height16Bits192GivesTheKnownAnswerOfLiboqs,
    XMSS::shake256Height16Bits192
);
knownAnswerTest!(
    xmssSHAKE256Height20Bits192GivesTheKnownAnswerOfLiboqs,
    XMSS::shake256Height20Bits192
);
knownAnswerTest!(
    xmssSHAKE256Height10Bits256GivesTheKnownAnswerOfLiboqs,
    XMSS::shake256Height10Bits256
);
knownAnswerTest!(
    xmssSHAKE256Height16Bits256GivesTheKnownAnswerOfLiboqs,
    XMSS::shake256Height16Bits256
);
knownAnswerTest!(
    xmssSHAKE256Height20Bits256GivesTheKnownAnswerOfLiboqs,
    XMSS::shake256Height20Bits256
);
knownAnswerTest!(
    xmssmtSHA2Height20Layers2GivesTheKnownAnswerOfLiboqs,
    XMSSMT::sha2Height20Layers2
);
knownAnswerTest!(
    xmssmtSHA2Height20Layers4GivesTheKnownAnswerOfLiboqs,
    XMSSMT::sha2Height20Layers4
);
knownAnswerTest!(
    xmssmtSHA2Height40Layers2GivesTheKnownAnswerOfLiboqs,
    XMSSMT::sha2Height40Layers2
);
knownAnswerTest!(
    xmssmtSHA2Height40Layers4GivesTheKnownAnswerOfLiboqs,
    XMSSMT::sha2Height40Layers4
);
knownAnswerTest!(
    xmssmtSHA2Height40Layers8GivesTheKnownAnswerOfLiboqs,
    XMSSMT::sha2Height40Layers8
);
knownAnswerTest!(
    xmssmtSHA2Height60Layers3GivesTheKnownAnswerOfLiboqs,
    XMSSMT::sha2Height60Layers3
);
knownAnswerTest!(
    xmssmtSHA2Height60Layers6GivesTheKnownAnswerOfLiboqs,
    XMSSMT::sha2Height60Layers6
);
knownAnswerTest!(
    xmssmtSHA2Height60Layers12GivesTheKnownAnswerOfLiboqs,
    XMSSMT::sha2Height60Layers12
);
knownAnswerTest!(
    xmssmtSHAKE128Height20Layers2GivesTheKnownAnswerOfLiboqs,
    XMSSMT::shake128Height20Layers2
);
knownAnswerTest!(
    xmssmtSHAKE128Height20Layers4GivesTheKnownAnswerOfLiboqs,
    XMSSMT::shake128Height20Layers4
);
knownAnswerTest!(
    xmssmtSHAKE128Height40Layers2GivesTheKnownAnswerOfLiboqs,
    XMSSMT::shake128Height40Layers2
);
knownAnswerTest!(
    xmssmtSHAKE128Height40Layers4GivesTheKnownAnswerOfLiboqs,
    XMSSMT::shake128Height40Layers4
);
knownAnswerTest!(
    xmssmtSHAKE128Height40Layers8GivesTheKnownAnswerOfLiboqs,
    XMSSMT::shake128Height40Layers8
);
knownAnswerTest!(
    xmssmtSHAKE128Height60Layers3GivesTheKnownAnswerOfLiboqs,
    XMSSMT::shake128Height60Layers3
);
knownAnswerTest!(
    xmssmtSHAKE128Height60Layers6GivesTheKnownAnswerOfLiboqs,
    XMSSMT::shake128Height60Layers6
);
knownAnswerTest!(
    xmssmtSHAKE128Height60Layers12GivesTheKnownAnswerOfLiboqs,
    XMSSMT::shake128Height60Layers12
);
