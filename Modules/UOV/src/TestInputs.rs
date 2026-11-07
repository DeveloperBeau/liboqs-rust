//! The inputs of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the UOV
//! reference code of liboqs 0.16.0, such as `pqov_uov_Ip_ref_batch_trimat_madd_gf256`, with
//! the same inputs, and the field functions of `gf16.h`. `OutputDigest` gives the digest that
//! the program printed. The program is not part of the repository.

use OQSNativeAlgorithmTests::LinearCongruentialSequence;
use alloc::string::String;
use alloc::vec::Vec;

/// The bytes of the seeded sequence of the C program: each byte is the high byte of the next
/// state.
pub(crate) fn sequence(count: usize, seed: u32) -> Vec<u8> {
    let mut sequence = LinearCongruentialSequence::new(seed);
    (0..count)
        .map(|_| (sequence.nextState() >> 24) as u8)
        .collect()
}

/// Bytes in lower-case hexadecimal.
pub(crate) fn hexadecimal(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}
