//! The inputs and the digest of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the FrodoKEM
//! code of liboqs 0.16.0, such as `oqs_kem_frodokem_640_aes_mul_add_as_plus_e`, with the same
//! inputs. The program is not part of the repository.

use OQSNativeAlgorithmTests::{LinearCongruentialSequence, OutputDigest};
use alloc::string::String;
use alloc::vec::Vec;

/// The values of the seeded sequence of the C program: each value is the high 16 bits of the
/// next state.
pub(crate) fn sequence(count: usize, seed: u32) -> Vec<u16> {
    let mut sequence = LinearCongruentialSequence::new(seed);
    (0..count)
        .map(|_| (sequence.nextState() >> 16) as u16)
        .collect()
}

/// The bytes of the values of a sequence, low byte first, as the C program reads them.
pub(crate) fn sequenceBytes(count: usize, seed: u32) -> Vec<u8> {
    sequence(count, seed)
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// The digest of values, each as two bytes, low byte first, as the C program prints them.
pub(crate) fn valuesDigest(values: &[u16]) -> String {
    let bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    OutputDigest::of(&bytes)
}
