//! Seeded inputs and digests for the unit tests.
//!
//! The programs that gave the known answers of the tests from the C code of liboqs 0.16.0 made
//! their inputs with the same generator, so a test and its known answer share the input.

use OQSNativeDomain::RandomGenerating;
use OQSNativeSHA3::SHA3256;
use alloc::string::String;

/// SplitMix64, the source of the seeded words of the tests.
pub struct SeededWords {
    state: u64,
}

impl SeededWords {
    /// Makes the source of a seed.
    pub fn new(seed: u64) -> Self {
        SeededWords { state: seed }
    }

    /// The next word.
    pub fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut word = self.state;
        word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        word ^ (word >> 31)
    }
}

/// A random source of SplitMix64 bytes: each request takes new words and the little-endian
/// bytes of each word, and drops the rest of the last word.
pub struct SeededRandom {
    words: SeededWords,
}

impl SeededRandom {
    /// Makes the source of a seed.
    pub fn new(seed: u64) -> Self {
        SeededRandom {
            words: SeededWords::new(seed),
        }
    }
}

impl RandomGenerating for SeededRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let word = self.words.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

/// The SHA3-256 of bytes in lower-case hexadecimal.
pub fn digest(bytes: &[u8]) -> String {
    SHA3256::hash(bytes)
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}
