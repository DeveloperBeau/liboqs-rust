//! The inputs and the digests of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the CROSS code
//! of liboqs 0.16.0, such as `PQCLEAN_CROSSRSDP128BALANCED_CLEAN_tree_proof`, with the same
//! inputs. The program is not part of the repository.

use OQSNativeAlgorithmTests::{LinearCongruentialSequence, OutputDigest};
use alloc::string::String;
use alloc::vec::Vec;

/// The values of the seeded sequence of the C program: each value is the high 16 bits of the
/// next state modulo a bound.
pub(crate) struct SeededSequence {
    sequence: LinearCongruentialSequence,
}

impl SeededSequence {
    /// Makes the sequence of a seed.
    pub(crate) fn new(seed: u32) -> Self {
        SeededSequence {
            sequence: LinearCongruentialSequence::new(seed),
        }
    }

    /// The next value below a bound.
    pub(crate) fn next(&mut self, bound: u32) -> u32 {
        (self.sequence.nextState() >> 16) % bound
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

/// The digest of values as 16-bit words, low byte first, as the C program printed unpacked
/// vectors.
pub(crate) fn wordsDigest(values: impl Iterator<Item = u32>) -> String {
    let bytes: Vec<u8> = values
        .flat_map(|value| (value as u16).to_le_bytes())
        .collect();
    OutputDigest::of(&bytes)
}

/// Bytes in lower-case hexadecimal, as the C program printed a Merkle root.
pub(crate) fn hexadecimal(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}
