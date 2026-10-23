//! The inputs and the digest of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that included `sntrup761.c` of liboqs 0.16.0, so
//! that it could call the static functions of the file, such as `Rq_recip3`, with the same
//! inputs. The program is not part of the repository.

use OQSNativeSHA2::SHA256;
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

/// The digest of the C program: the SHA-256 of the bytes, in lower-case hexadecimal.
pub(crate) fn digest(bytes: &[u8]) -> String {
    SHA256::hash(bytes)
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}

/// The output of the C program: the function and the SHA-256 of its output, or a number.
const cAnswers: &str = "\
ternaryReciprocal 7dd1e4cf9ee95bc07f89691ee0003a68d74d04233082e95f900d96622a108e15
ternaryReciprocalMask 0
shortFromWords 4ea0a783ed8aa04be1a0ee7e282dc12d634ee3b12e8f2a327a26ed7cbbe664a9
reciprocalOfTriple ef21f2e71769bd39285aabcca2f24307faf86db18659b7bf2ff72488346a4528
reciprocalOfTripleMask 0
productWithSmall c28386494374e669dbcd2dcb05b6359e002fc1487fde93ea14f1aa90b82d3e04
ternaryProduct e009ec4d48f01cd0195bfeda84e34c4cacab877c2b549ca39c01b8dd641a8a2d
modulusBytes 2792c7e8d0f323aa4d6805a25a6d1365d209a7aab37be9b95d333ab27975a542
modulusPolynomial 33d97210849e4ccbec4a28ea35e07e4e8d52ca44ce1ac3f1c2b04ad6261726f6
roundedBytes f324ec537dc6541980922a6d71edf2867796ffdf00efab4e7e7c276e2c01bdfb
roundedPolynomial 1d64ebde2310af83ffaab9625d7ee67a8f9386745f82241065f69f8d58a1904b
smallBytes 17da3de2540eb3190f388b0e525780d15d90e9ac2ddd4f8b4e9516fb298f8a14
smallPolynomial 7de468b39a15f12c7297d34206bfa803049ebea3262f81dd9bcc9d2ed83f6343
smallFromWords cfe170618c00790554e66f4bcca23029f850c5fa654d27203282cb4471737cb2
publicKey 05b30568d14d6150e69386c3573c51fa338c31e6fbc0d0868e5ebc3d4df0ec75
secretKey ca88ea64ee510a8dcad315df5201ff7e1dac268d39624dc399579c1e8b44cd29
ciphertext 0a71f8e0f76b9d3c402d9a2fde6ba651588c33969b1917e5c95df90319116ba2
sharedSecret b2a7d592b9034eb5ecfac80d5a20ec3cb5c192695e652bf37759777702f8c76a
hostileSharedSecret dff0ebc98cde5428c3b529171d17cd74d1e0012cd0cf7dff761920c9f564bec5
hostileDecryption a78b69364bb7804a4fd5ee74fbf30e07c56dea5f616ff15320145a61998112e7
";

/// The answer of the C program for a function.
pub(crate) fn cAnswer(function: &str) -> &'static str {
    cAnswers
        .lines()
        .find_map(|line| {
            let (label, answer) = line.split_once(' ')?;
            (label == function).then_some(answer)
        })
        .unwrap_or_else(|| panic!("the C program gives no answer for {function}"))
}

/// The small polynomial of a sequence, each value modulo 3 minus 1.
pub(crate) fn smallSequence(seed: u32) -> Vec<i8> {
    sequence(761, seed)
        .iter()
        .map(|value| (value % 3) as i8 - 1)
        .collect()
}

/// The polynomial modulo q of a sequence, each value modulo q minus (q - 1) / 2.
pub(crate) fn modulusSequence(seed: u32) -> Vec<i16> {
    sequence(761, seed)
        .iter()
        .map(|value| (value % 4591) as i16 - 2295)
        .collect()
}

/// The 32-bit words of a sequence, each from two values, the high half first.
pub(crate) fn wordSequence(seed: u32) -> Vec<u32> {
    sequence(2 * 761, seed)
        .chunks_exact(2)
        .map(|pair| (u32::from(pair[0]) << 16) + u32::from(pair[1]))
        .collect()
}

/// The low bytes of the values of a sequence.
pub(crate) fn byteSequence(count: usize, seed: u32) -> Vec<u8> {
    sequence(count, seed)
        .iter()
        .map(|value| *value as u8)
        .collect()
}

/// The bytes of signed 8-bit values.
pub(crate) fn smallBytes(values: &[i8]) -> Vec<u8> {
    values.iter().map(|value| *value as u8).collect()
}

/// The bytes of signed 16-bit values, low byte first.
pub(crate) fn modulusBytes(values: &[i16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// The random source of the C program: the low bytes of the sequence of a seed, one request
/// after the other.
pub(crate) struct SequenceRandom {
    state: u32,
}

impl SequenceRandom {
    /// The source of a seed.
    pub(crate) fn new(seed: u32) -> Self {
        SequenceRandom { state: seed }
    }
}

impl OQSNativeDomain::RandomGenerating for SequenceRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        for byte in bytes.iter_mut() {
            self.state = self.state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            *byte = (self.state >> 16) as u8;
        }
    }
}
