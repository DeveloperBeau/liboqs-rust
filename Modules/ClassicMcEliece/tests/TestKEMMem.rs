//! The memory test of liboqs `tests/test_kem_mem.c`: the key pair, the encapsulation and the
//! decapsulation of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::KEMMemoryTest;
use OQSNativeClassicMcEliece::ClassicMcEliece;
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeKATRandom::NISTKATRandom;

#[test]
fn testKEMMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!(
        "oqs-native-classic-mceliece-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let mechanisms: [&dyn KeyEncapsulating; 10] = [
        &ClassicMcEliece::classicMcEliece348864,
        &ClassicMcEliece::classicMcEliece348864f,
        &ClassicMcEliece::classicMcEliece460896,
        &ClassicMcEliece::classicMcEliece460896f,
        &ClassicMcEliece::classicMcEliece6688128,
        &ClassicMcEliece::classicMcEliece6688128f,
        &ClassicMcEliece::classicMcEliece6960119,
        &ClassicMcEliece::classicMcEliece6960119f,
        &ClassicMcEliece::classicMcEliece8192128,
        &ClassicMcEliece::classicMcEliece8192128f,
    ];
    for mechanism in mechanisms {
        assert_eq!(
            KEMMemoryTest::run(mechanism, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
