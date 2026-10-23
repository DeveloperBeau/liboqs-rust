//! The inputs and the digest of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the FrodoKEM
//! code of liboqs 0.16.0, such as `oqs_kem_frodokem_640_aes_mul_add_as_plus_e`, with the same
//! inputs. The program is not part of the repository.

use OQSNativeSHA3::SHAKE128;
use alloc::string::String;
use alloc::vec::Vec;

/// The values of a simple seeded sequence, the inputs of the C program: the state takes
/// `state * 1103515245 + 12345` modulo `2^32`, and each value is the high 16 bits of the state.
pub(crate) fn sequence(count: usize, seed: u32) -> Vec<u16> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u16
        })
        .collect()
}

/// The bytes of the values of a sequence, low byte first, as the C program reads them.
pub(crate) fn sequenceBytes(count: usize, seed: u32) -> Vec<u8> {
    sequence(count, seed)
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// The digest of the C program: 32 bytes of SHAKE128 of the bytes, in lower-case hexadecimal.
pub(crate) fn digest(bytes: &[u8]) -> String {
    let mut output = [0u8; 32];
    SHAKE128::hash(bytes, &mut output);
    output
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}

/// The digest of values, each as two bytes, low byte first, as the C program prints them.
pub(crate) fn valuesDigest(values: &[u16]) -> String {
    let bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    digest(&bytes)
}
