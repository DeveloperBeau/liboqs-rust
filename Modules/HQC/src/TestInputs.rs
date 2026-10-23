//! The inputs and the digest of the unit tests that compare a decoder function with its C
//! function.
//!
//! The known answers come from a C program that called the internal functions of the HQC code of
//! liboqs 0.16.0, such as `PQCHQC_HQC1_C_reed_solomon_decode`, with the same inputs. The program
//! is not part of the repository.

use crate::Parameters;
use crate::galoisField::GaloisField;
use OQSNativeSHA3::SHAKE128;
use alloc::string::String;
use alloc::vec::Vec;

/// The next value of the seeded sequence of the C program: the state takes
/// `state * 1103515245 + 12345` modulo `2^32`, and the value is bits 16 to 23 of the state.
pub(crate) fn nextByte(state: &mut u32) -> u8 {
    *state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    (*state >> 16) as u8
}

/// A word of `length` bytes with `weight` bytes that are not zero, as the C program makes the
/// input of `reed_solomon_decode`: a position is the next value modulo the length, skipped when
/// it is taken, and its byte is the value after it modulo 255, plus 1.
pub(crate) fn wordOfWeight(state: &mut u32, length: usize, weight: usize) -> Vec<u8> {
    assert!(
        weight <= length,
        "the weight {weight} fits in {length} bytes"
    );
    let mut word = alloc::vec![0u8; length];
    let mut placed = 0;
    while placed < weight {
        let position = usize::from(nextByte(state)) % length;
        if word[position] == 0 {
            word[position] = nextByte(state) % 255 + 1;
            placed += 1;
        }
    }
    word
}

/// The word `q(x) g(x)` of `length` bytes, as the C program makes the input of
/// `reed_solomon_decode`: `g` is the product of `x + alpha^i` for `i` from 1 to `zeros`, and the
/// `length - zeros` coefficients of `q` come from the sequence. The first `zeros` syndromes of
/// the word are zero.
pub(crate) fn wordWithLeadingZeroSyndromes(
    state: &mut u32,
    length: usize,
    zeros: usize,
) -> Vec<u8> {
    let mut generator = alloc::vec![1u8];
    for exponent in 1..=zeros {
        let root = GaloisField::power(exponent);
        let mut next = alloc::vec![0u8; generator.len() + 1];
        for (degree, coefficient) in generator.iter().enumerate() {
            next[degree + 1] ^= coefficient;
            next[degree] ^= GaloisField::product(*coefficient, root);
        }
        generator = next;
    }
    let mut word = alloc::vec![0u8; length];
    for index in 0..length - zeros {
        let coefficient = nextByte(state);
        for (offset, factor) in generator.iter().enumerate() {
            word[index + offset] ^= GaloisField::product(coefficient, *factor);
        }
    }
    word
}

/// A received word of the duplicated Reed-Muller code of a set, as the C program makes the input
/// of `reed_muller_decode` and `code_decode`.
///
/// Each of the `n1` blocks takes a message byte and a threshold from the sequence, with the
/// threshold shifted right by `shift`. Each copy of the block holds the codeword of the byte, with
/// each bit flipped when the next value is below the threshold. Bit `j` of the codeword of `m` is
/// bit 7 of `m` plus the parity of `m & j & 0x7F`, which is the sum of the rows of the generator
/// matrix.
pub(crate) fn receivedWord(state: &mut u32, parameters: &Parameters, shift: u32) -> Vec<u64> {
    let multiplicity = parameters.multiplicity();
    let mut words = alloc::vec![0u64; parameters.codewordWordCount()];
    for block in words.chunks_exact_mut(2 * multiplicity) {
        let message = nextByte(state);
        let threshold = nextByte(state) >> shift;
        for copy in block.chunks_exact_mut(2) {
            for position in 0..128u8 {
                let parity = (message & position & 0x7F).count_ones() & 1;
                let flip = u32::from(nextByte(state) < threshold);
                let bit = u64::from(u32::from(message >> 7) ^ parity ^ flip);
                copy[usize::from(position / 64)] |= bit << (position % 64);
            }
        }
    }
    words
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
