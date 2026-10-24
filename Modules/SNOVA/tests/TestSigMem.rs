//! The memory test of liboqs `tests/test_sig_mem.c`: the key pair, the signature and the
//! verification of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::SignatureMemoryTest;
use OQSNativeDomain::Signing;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSNOVA::SNOVA;

#[test]
fn testSigMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-snova-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let schemes: [&dyn Signing; 12] = [
        &SNOVA::snova24x5x4,
        &SNOVA::snova24x5x4SHAKE,
        &SNOVA::snova24x5x4WithExpandedSecretKey,
        &SNOVA::snova24x5x4SHAKEWithExpandedSecretKey,
        &SNOVA::snova37x17x2,
        &SNOVA::snova25x8x3,
        &SNOVA::snova56x25x2,
        &SNOVA::snova49x11x3,
        &SNOVA::snova37x8x4,
        &SNOVA::snova24x5x5,
        &SNOVA::snova60x10x4,
        &SNOVA::snova29x6x5,
    ];
    for scheme in schemes {
        assert_eq!(
            SignatureMemoryTest::run(scheme, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
