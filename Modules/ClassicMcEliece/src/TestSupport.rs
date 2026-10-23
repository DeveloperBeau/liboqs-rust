//! The digest of the outputs of the unit tests.
//!
//! The programs that gave the known answers of the tests from the C code of liboqs 0.16.0 made
//! their inputs with SplitMix64, as `FuzzRandom::seeded` of the test support crate makes them,
//! so a test and its known answer share the input. They printed this digest of each output.

use OQSNativeSHA3::SHA3256;
use alloc::string::String;

/// The SHA3-256 of bytes in lower-case hexadecimal.
pub fn digest(bytes: &[u8]) -> String {
    SHA3256::hash(bytes)
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}
