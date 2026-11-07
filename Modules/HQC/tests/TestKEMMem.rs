//! The memory test of liboqs `tests/test_kem_mem.c`: the key pair, the encapsulation and the
//! decapsulation of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::KEMMemoryTest;
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeHQC::HQC;
use OQSNativeKATRandom::NISTKATRandom;

#[test]
fn testKEMMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-hqc-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let mechanisms: [&dyn KeyEncapsulating; 3] = [&HQC::hqc1, &HQC::hqc3, &HQC::hqc5];
    for mechanism in mechanisms {
        assert_eq!(
            KEMMemoryTest::run(mechanism, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(()),
            "seed 5"
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
