//! The memory test of liboqs `tests/test_kem_mem.c`: the key pair, the encapsulation and the
//! decapsulation of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::KEMMemoryTest;
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeNTRU::NTRU;

#[test]
fn testKEMMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-ntru-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let mechanisms: [&dyn KeyEncapsulating; 6] = [
        &NTRU::ntruHPS2048509,
        &NTRU::ntruHPS2048677,
        &NTRU::ntruHPS4096821,
        &NTRU::ntruHPS40961229,
        &NTRU::ntruHRSS701,
        &NTRU::ntruHRSS1373,
    ];
    for mechanism in mechanisms {
        assert_eq!(
            KEMMemoryTest::run(mechanism, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
