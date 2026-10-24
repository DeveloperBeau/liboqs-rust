//! Seeded inputs and digests for the unit tests.
//!
//! The scripts that gave the known answers of the tests from the C code of liboqs 0.16.0 made
//! their inputs with the same generator, so a test and its known answer share the input.

use crate::Parameters;
use OQSNativeSHA3::SHA3256;
use alloc::string::String;
use alloc::vec::Vec;

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

    /// The next words.
    pub fn words(&mut self, count: usize) -> Vec<u64> {
        (0..count).map(|_| self.next()).collect()
    }
}

/// The polynomial of the bytes of `R_QWORDS` seeded words cut to `R_BYTES` bytes. A reduced
/// polynomial also clears the coefficients from `r` up.
pub fn seededPolynomial(parameters: &Parameters, seed: u64, isReduced: bool) -> Vec<u64> {
    let wordCount = parameters.wordCount();
    let mut words = SeededWords::new(seed).words(wordCount);
    let lastBytes = parameters.polynomialByteCount() - 8 * (wordCount - 1);
    words[wordCount - 1] &= u64::MAX >> (64 - 8 * lastBytes);
    if isReduced {
        words[wordCount - 1] &= parameters.lastWordMask();
    }
    words
}

/// The SHA3-256 of bytes in lower-case hexadecimal.
pub fn digest(bytes: &[u8]) -> String {
    SHA3256::hash(bytes)
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}

/// The bytes of a list of words, little-endian.
pub fn wordBytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
