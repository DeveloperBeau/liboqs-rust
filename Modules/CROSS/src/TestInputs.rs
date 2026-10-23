//! The inputs and the digests of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the CROSS code
//! of liboqs 0.16.0, such as `PQCLEAN_CROSSRSDP128BALANCED_CLEAN_tree_proof`, with the same
//! inputs. The program is not part of the repository.

use OQSNativeSHA3::SHAKE128;
use alloc::string::String;
use alloc::vec::Vec;

/// The seeded sequence of the C program: the state takes `state * 1103515245 + 12345` modulo
/// `2^32`, and each value is the high 16 bits of the state modulo a bound.
pub(crate) struct SeededSequence {
    state: u32,
}

impl SeededSequence {
    /// Makes the sequence of a seed.
    pub(crate) fn new(seed: u32) -> Self {
        SeededSequence { state: seed }
    }

    /// The next value below a bound.
    pub(crate) fn next(&mut self, bound: u32) -> u32 {
        self.state = self.state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        (self.state >> 16) % bound
    }

    /// The next values below a bound.
    pub(crate) fn values(&mut self, count: usize, bound: u32) -> Vec<u32> {
        (0..count).map(|_| self.next(bound)).collect()
    }

    /// The next bytes.
    pub(crate) fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.next(256) as u8).collect()
    }
}

/// The first 16 bytes of the SHAKE128 of some bytes in lower-case hexadecimal, the digest that
/// the C program printed.
pub(crate) fn shortDigest(bytes: &[u8]) -> String {
    let mut digest = [0u8; 16];
    SHAKE128::hash(bytes, &mut digest);
    hexadecimal(&digest)
}

/// The digest of values as 16-bit words, low byte first, as the C program printed unpacked
/// vectors.
pub(crate) fn wordsDigest(values: impl Iterator<Item = u32>) -> String {
    let bytes: Vec<u8> = values
        .flat_map(|value| (value as u16).to_le_bytes())
        .collect();
    shortDigest(&bytes)
}

/// Bytes in lower-case hexadecimal.
pub(crate) fn hexadecimal(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}
