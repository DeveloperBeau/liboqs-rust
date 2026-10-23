//! The memory test of liboqs `tests/test_sig_mem.c`: the key pair, the signature and the
//! verification of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::SignatureMemoryTest;
use OQSNativeDomain::Signing;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeMQOM::MQOM;

#[test]
fn testSigMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-mqom-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let schemes: [&dyn Signing; 12] = [
        &MQOM::mqom2Cat1GF16FastR3,
        &MQOM::mqom2Cat1GF16FastR5,
        &MQOM::mqom2Cat1GF16ShortR3,
        &MQOM::mqom2Cat1GF16ShortR5,
        &MQOM::mqom2Cat3GF16FastR3,
        &MQOM::mqom2Cat3GF16FastR5,
        &MQOM::mqom2Cat3GF16ShortR3,
        &MQOM::mqom2Cat3GF16ShortR5,
        &MQOM::mqom2Cat5GF16FastR3,
        &MQOM::mqom2Cat5GF16FastR5,
        &MQOM::mqom2Cat5GF16ShortR3,
        &MQOM::mqom2Cat5GF16ShortR5,
    ];
    for scheme in schemes {
        assert_eq!(
            SignatureMemoryTest::run(scheme, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
