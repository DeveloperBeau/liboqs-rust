//! The inputs and the digests of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that included `mayo.c` and `arithmetic.c` of the
//! MAYO code of liboqs 0.16.0, built for each set with the flags of the oracle build and the
//! namespace of the reference build, so that its names do not clash with `liboqs.a`. It called
//! the functions, also the static ones such as `compute_A`, with the same inputs. Each input comes
//! from `LinearCongruentialSequence`, and each output is compared by its `OutputDigest`, as for
//! every family. The program is not part of the repository.

use crate::Parameters;
use OQSNativeAlgorithmTests::{LinearCongruentialSequence, OutputDigest};

/// The seed of an input of the C program: 1000 times the number of the set, such as 5 for
/// MAYO-5, plus the number of the input.
pub(crate) fn seed(parameters: &Parameters, input: u32) -> u32 {
    let set: u32 = parameters.description.name["MAYO-".len()..]
        .parse()
        .expect("the number of the set");
    1000 * set + input
}

/// The bytes of a seed: bits 16 to 23 of each next state of the sequence, as the C program
/// takes them.
pub(crate) fn inputBytes(seed: u32, length: usize) -> Vec<u8> {
    let mut sequence = LinearCongruentialSequence::new(seed);
    (0..length)
        .map(|_| (sequence.nextState() >> 16) as u8)
        .collect()
}

/// The elements of a seed: the low nibble of each byte of `inputBytes`.
pub(crate) fn inputNibbles(seed: u32, length: usize) -> Vec<u8> {
    inputBytes(seed, length)
        .into_iter()
        .map(|byte| byte & 0x0F)
        .collect()
}

/// The 64-bit words of a seed: `inputBytes` read as little-endian words, as the C program
/// fills an array of words.
pub(crate) fn inputWords(seed: u32, count: usize) -> Vec<u64> {
    inputBytes(seed, 8 * count)
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("8 bytes")))
        .collect()
}

/// The digest of bytes, as the C program prints it.
pub(crate) fn digestOfBytes(bytes: &[u8]) -> String {
    OutputDigest::of(bytes)
}

/// The digest of words as little-endian bytes, as the C program digests an array of words.
pub(crate) fn digest(words: &[u64]) -> String {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    OutputDigest::of(&bytes)
}

#[cfg(test)]
mod tests {
    use super::{inputBytes, inputWords, seed};
    use crate::parameters::{mayo1, mayo5};

    #[test]
    fn inputsFollowTheSequenceOfTheCProgram() {
        // The states of seed 1 are 1103527590, 2524885223 and 662824084, so the bytes are their
        // bits 16 to 23: 0xC6, 0x7E and 0x81.
        assert_eq!(inputBytes(1, 3), vec![0xC6, 0x7E, 0x81]);
        assert_eq!(inputWords(1, 1)[0] & 0xFF_FFFF, 0x81_7EC6);
        assert_eq!(seed(&mayo1, 7), 1007);
        assert_eq!(seed(&mayo5, 103), 5103);
    }
}
