//! The memory test of liboqs `tests/test_sig_mem.c`: the key pair, the signature and the
//! verification of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::SignatureMemoryTest;
use OQSNativeCROSS::CROSS;
use OQSNativeDomain::Signing;
use OQSNativeKATRandom::NISTKATRandom;

#[test]
fn testSigMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-cross-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let schemes: [&dyn Signing; 18] = [
        &CROSS::crossRSDP128Balanced,
        &CROSS::crossRSDP128Fast,
        &CROSS::crossRSDP128Small,
        &CROSS::crossRSDP192Balanced,
        &CROSS::crossRSDP192Fast,
        &CROSS::crossRSDP192Small,
        &CROSS::crossRSDP256Balanced,
        &CROSS::crossRSDP256Fast,
        &CROSS::crossRSDP256Small,
        &CROSS::crossRSDPG128Balanced,
        &CROSS::crossRSDPG128Fast,
        &CROSS::crossRSDPG128Small,
        &CROSS::crossRSDPG192Balanced,
        &CROSS::crossRSDPG192Fast,
        &CROSS::crossRSDPG192Small,
        &CROSS::crossRSDPG256Balanced,
        &CROSS::crossRSDPG256Fast,
        &CROSS::crossRSDPG256Small,
    ];
    for scheme in schemes {
        assert_eq!(
            SignatureMemoryTest::run(scheme, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
