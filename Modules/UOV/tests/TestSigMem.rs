//! The memory test of liboqs `tests/test_sig_mem.c`: the key pair, the signature and the
//! verification of each parameter set, with every value in a file between the steps.

use OQSNativeAlgorithmTests::SignatureMemoryTest;
use OQSNativeDomain::Signing;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeUOV::UOV;

#[test]
fn testSigMemPassesForEveryParameterSet() {
    let folder = std::env::temp_dir().join(format!("oqs-native-uov-{}", std::process::id()));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    let schemes: [&dyn Signing; 12] = [
        &UOV::ovIs,
        &UOV::ovIp,
        &UOV::ovIII,
        &UOV::ovV,
        &UOV::ovIsCompressedPublicKey,
        &UOV::ovIpCompressedPublicKey,
        &UOV::ovIIICompressedPublicKey,
        &UOV::ovVCompressedPublicKey,
        &UOV::ovIsCompressedKeys,
        &UOV::ovIpCompressedKeys,
        &UOV::ovIIICompressedKeys,
        &UOV::ovVCompressedKeys,
    ];
    for scheme in schemes {
        assert_eq!(
            SignatureMemoryTest::run(scheme, &mut NISTKATRandom::new(&[5; 48], None), &folder),
            Ok(())
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}
