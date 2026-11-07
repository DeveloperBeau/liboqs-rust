//! The memory test of liboqs `tests/test_kem_mem.c`: the key pair, the encapsulation and the
//! decapsulation of sntrup761, with every value in a file between the steps.

use OQSNativeAlgorithmTests::KEMMemoryTest;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeNTRUPrime::NTRUPrime;

#[test]
fn testKEMMemPassesForSntrup761() {
    let folder = std::env::temp_dir().join(format!("oqs-native-ntru-prime-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    assert_eq!(
        KEMMemoryTest::run(
            &NTRUPrime::sntrup761,
            &mut NISTKATRandom::new(&[5; 48], None),
            &folder
        ),
        Ok(())
    );
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
