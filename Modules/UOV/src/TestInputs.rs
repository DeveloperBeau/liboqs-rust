//! The inputs and the digest of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the UOV
//! reference code of liboqs 0.16.0, such as `pqov_uov_Ip_ref_batch_trimat_madd_gf256`, with
//! the same inputs, and the field functions of `gf16.h`. The program is not part of the
//! repository.

use OQSNativeSHA3::SHAKE128;
use alloc::string::String;
use alloc::vec::Vec;

/// The bytes of a simple seeded sequence, the inputs of the C program: the state takes
/// `state * 1103515245 + 12345` modulo `2^32`, and each byte is the high byte of the state.
pub(crate) fn sequence(count: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 24) as u8
        })
        .collect()
}

/// Bytes in lower-case hexadecimal.
pub(crate) fn hexadecimal(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}

/// The digest of the C program: 32 bytes of SHAKE128 of the bytes, in lower-case hexadecimal.
pub(crate) fn digest(bytes: &[u8]) -> String {
    let mut output = [0u8; 32];
    SHAKE128::hash(bytes, &mut output);
    hexadecimal(&output)
}
