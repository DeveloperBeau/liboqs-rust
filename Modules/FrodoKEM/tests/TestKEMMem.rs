//! The memory test of liboqs `tests/test_kem_mem.c`: the key pair, the encapsulation and the
//! decapsulation of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::KEMMemoryTest;
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeFrodoKEM::FrodoKEM;
use OQSNativeKATRandom::NISTKATRandom;

#[test]
fn testKEMMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-frodokem-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let mechanisms: [&dyn KeyEncapsulating; 12] = [
        &FrodoKEM::frodoKEM640AES,
        &FrodoKEM::frodoKEM640SHAKE,
        &FrodoKEM::frodoKEM976AES,
        &FrodoKEM::frodoKEM976SHAKE,
        &FrodoKEM::frodoKEM1344AES,
        &FrodoKEM::frodoKEM1344SHAKE,
        &FrodoKEM::eFrodoKEM640AES,
        &FrodoKEM::eFrodoKEM640SHAKE,
        &FrodoKEM::eFrodoKEM976AES,
        &FrodoKEM::eFrodoKEM976SHAKE,
        &FrodoKEM::eFrodoKEM1344AES,
        &FrodoKEM::eFrodoKEM1344SHAKE,
    ];
    for mechanism in mechanisms {
        assert_eq!(
            KEMMemoryTest::run(mechanism, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
