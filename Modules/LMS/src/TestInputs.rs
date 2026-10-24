//! The inputs of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the hash-sigs
//! code of liboqs 0.16.0, such as `OQS_LMS_NAMESPACE_hss_seed_derive`, with the same inputs. The
//! program printed the `OutputDigest` of each output. It is not part of the repository.

use OQSNativeAlgorithmTests::LinearCongruentialSequence;
use alloc::vec::Vec;

/// The bytes of the seeded sequence of the C program: each byte is bits 16 to 23 of the next
/// state.
pub(crate) fn sequenceBytes(count: usize, seed: u32) -> Vec<u8> {
    let mut sequence = LinearCongruentialSequence::new(seed);
    (0..count)
        .map(|_| (sequence.nextState() >> 16) as u8)
        .collect()
}

/// The identifier I and the seed of the tree of the tests: the sequences of the seeds 1 and 2.
pub(crate) fn identifierAndSeed() -> ([u8; 16], [u8; 32]) {
    (
        sequenceBytes(16, 1).try_into().expect("16 bytes"),
        sequenceBytes(32, 2).try_into().expect("32 bytes"),
    )
}
