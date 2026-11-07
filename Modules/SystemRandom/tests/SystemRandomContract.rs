//! The contract test of the `SystemRandom` adapter. It is the one test that reads the random
//! source of the operating system, because an adapter can be proved only against the service
//! that it adapts.

use OQSNativeDomain::RandomGenerating;
use OQSNativeSystemRandom::SystemRandom;

/// Two reads of 32 bytes differ, and a read is not all zero. A correct source fails either
/// check with a chance of about 2 to the power of minus 256.
#[test]
fn readsGiveFreshBytesThatAreNotZero() {
    let mut random = SystemRandom::new().expect("the random source opens");
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    random.fillRandomBytes(&mut first);
    random.fillRandomBytes(&mut second);
    assert_ne!(first, second);
    assert_ne!(first, [0u8; 32]);
}

#[test]
fn largeAndEmptyReadsComplete() {
    let mut random = SystemRandom::new().expect("the random source opens");
    let mut large = vec![0u8; 1 << 20];
    random.fillRandomBytes(&mut large);
    let zeroCount = large.iter().filter(|byte| **byte == 0).count();
    // A uniform source gives about 4096 zero bytes in one megabyte.
    assert!((3000..6000).contains(&zeroCount), "{zeroCount} zero bytes");
    random.fillRandomBytes(&mut []);
}
