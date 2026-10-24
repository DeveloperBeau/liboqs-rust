//! The memory test of liboqs `tests/test_kem_mem.c`: the key pair, the encapsulation and the
//! decapsulation of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::KEMMemoryTest;
use OQSNativeBIKE::BIKE;
use OQSNativeKATRandom::NISTKATRandom;

#[test]
fn testKEMMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-bike-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    for mechanism in [&BIKE::bikeL1, &BIKE::bikeL3, &BIKE::bikeL5] {
        assert_eq!(
            KEMMemoryTest::run(mechanism, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
