//! The memory test of liboqs `tests/test_sig_mem.c`: the key pair, the signature and the
//! verification of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::SignatureMemoryTest;
use OQSNativeDomain::Signing;
use OQSNativeFalcon::Falcon;
use OQSNativeKATRandom::NISTKATRandom;

#[test]
fn testSigMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-falcon-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let schemes: [&dyn Signing; 4] = [
        &Falcon::falcon512,
        &Falcon::falcon1024,
        &Falcon::falconPadded512,
        &Falcon::falconPadded1024,
    ];
    for scheme in schemes {
        assert_eq!(
            SignatureMemoryTest::run(scheme, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
