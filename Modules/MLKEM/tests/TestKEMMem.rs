//! The memory test of liboqs `tests/test_kem_mem.c`: the key pair, the encapsulation and the
//! decapsulation of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::KEMMemoryTest;
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeMLKEM::{Kyber, MLKEM};

#[test]
fn testKEMMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-ml-kem-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let mechanisms: [&dyn KeyEncapsulating; 6] = [
        &MLKEM::mlkem512,
        &MLKEM::mlkem768,
        &MLKEM::mlkem1024,
        &Kyber::kyber512,
        &Kyber::kyber768,
        &Kyber::kyber1024,
    ];
    for mechanism in mechanisms {
        assert_eq!(
            KEMMemoryTest::run(mechanism, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
