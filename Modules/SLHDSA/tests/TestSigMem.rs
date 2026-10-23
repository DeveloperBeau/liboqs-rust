//! The memory test of liboqs `tests/test_sig_mem.c` through `SignatureMemoryTest`: the key
//! pair, the signature and the verification of each scheme, with every value in a file between
//! the steps.

use OQSNativeAlgorithmTests::{SignatureMemoryTest, SuiteSample};
use OQSNativeDomain::Signing;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSLHDSA::SLHDSA;

/// Runs the memory test on schemes, with the files in a folder of the test.
fn runMemoryTest(schemes: &[&dyn Signing], folderName: &str) {
    let folder = std::env::temp_dir().join(format!(
        "oqs-native-slh-dsa-{folderName}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&folder).expect("a temporary folder");
    for (index, scheme) in schemes.iter().enumerate() {
        let seed = index as u8;
        assert_eq!(
            SignatureMemoryTest::run(*scheme, &mut NISTKATRandom::new(&[seed; 48], None), &folder),
            Ok(()),
            "{}, the NIST DRBG seeded with 48 bytes {seed}",
            scheme.description().name
        );
    }
    std::fs::remove_dir_all(&folder).expect("remove the folder");
}

#[test]
fn testSigMemPassesForEachSchemeOfTheSuiteSampleAndEachPureSmallSet() {
    // The pure small sets sign in about a second each in a debug build, so the six of them
    // run here too.
    let schemes: Vec<&dyn Signing> = SLHDSA::schemes
        .iter()
        .copied()
        .filter(|scheme| {
            let name = scheme.description().name;
            SuiteSample::contains(name) || name.starts_with("SLH_DSA_PURE")
        })
        .collect();
    assert_eq!(schemes.len(), 24);
    runMemoryTest(&schemes, "sample");
}

#[test]
#[ignore = "the 156 schemes sign for minutes in a debug build, and parity run checks them in release builds"]
fn testSigMemPassesForEveryScheme() {
    runMemoryTest(SLHDSA::schemes, "every");
}
