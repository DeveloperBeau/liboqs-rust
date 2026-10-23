//! The inputs and the digests of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that included `mayo.c` and `arithmetic.c` of the
//! MAYO code of liboqs 0.16.0, built for each set with the flags of the oracle build and the
//! namespace of the reference build, so that its names do not clash with `liboqs.a`. It called
//! the functions, also the static ones such as `compute_A`, with the same inputs. Each input is
//! SHAKE256 of the name of the set and a label, and each output is the SHAKE256 of its bytes,
//! 32 bytes in hexadecimal. The program is not part of the repository.

use OQSNativeSHA3::SHAKE256;

/// The bytes of a label: SHAKE256 of `<set> <label>`.
pub(crate) fn inputBytes(set: &str, label: &str, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    SHAKE256::hash(format!("{set} {label}").as_bytes(), &mut bytes);
    bytes
}

/// The elements of a label: the low nibble of each byte of `inputBytes`.
pub(crate) fn inputNibbles(set: &str, label: &str, length: usize) -> Vec<u8> {
    inputBytes(set, label, length)
        .into_iter()
        .map(|byte| byte & 0x0F)
        .collect()
}

/// The 64-bit words of a label: `inputBytes` read as little-endian words, as the C program
/// fills an array of words.
pub(crate) fn inputWords(set: &str, label: &str, count: usize) -> Vec<u64> {
    inputBytes(set, label, 8 * count)
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8 bytes")))
        .collect()
}

/// The SHAKE256 of bytes, 32 bytes in hexadecimal.
pub(crate) fn digestOfBytes(bytes: &[u8]) -> String {
    let mut digest = [0u8; 32];
    SHAKE256::hash(bytes, &mut digest);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The SHAKE256 of words as little-endian bytes, as the C program digests an array of words.
pub(crate) fn digest(words: &[u64]) -> String {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    digestOfBytes(&bytes)
}
