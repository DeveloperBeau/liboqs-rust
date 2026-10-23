//! The inputs and the digest of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that included `sntrup761.c` of liboqs 0.16.0, so
//! that it could call the static functions of the file, such as `Rq_recip3`, with the same
//! inputs. The program is not part of the repository.

use OQSNativeAlgorithmTests::LinearCongruentialSequence;
use OQSNativeDomain::RandomGenerating;
use alloc::vec::Vec;

/// The values of the seeded sequence of the C program: each value is the high 16 bits of the
/// next state.
pub(crate) fn sequence(count: usize, seed: u32) -> Vec<u16> {
    let mut sequence = LinearCongruentialSequence::new(seed);
    (0..count)
        .map(|_| (sequence.nextState() >> 16) as u16)
        .collect()
}

/// The output of the C program: the function and the digest of its output, or a number.
const cAnswers: &str = "\
ternaryReciprocal 9c3eec63d4a15b2fa42c98a09883d180e4644f1dafcfe367014d983f9ad24013
ternaryReciprocalMask 0
shortFromWords 1797f0e6857a7e52cb972367a793bef8966576a34b22d8b005a30f0408a5a2fd
reciprocalOfTriple 6222fef9d8d7fc2ea3de2c2b2b5a21e34cd6e23d67c382c49d4b66f41d556a19
reciprocalOfTripleMask 0
productWithSmall dd873b04cc95c29e1f9fa38f67cecaf732de79a391cb33a7a97bc7c93c05dcad
ternaryProduct 2c64d4953c44ef89bd406369220b6b797e3b07d9c3d888948d6170217026559e
modulusBytes fa28ed294d8c1c6e4d85147a401172994352877ebf4b81f1bc57c14ede39aa28
modulusPolynomial 50ada00ca9933b7330e0c14503cac984b4005053c715451fff7383db3c075578
roundedBytes b0efd95cb1ac12ea6d5e5378c35f133f384d87be00d76a1f4b025d82711e29c2
roundedPolynomial 73cddd07953e0c629a1a2e33444f4c476d16fe49a07becfb04c9bbabe91b0464
smallBytes 4941f62ca01388bd2907d5334a05389e10fcef944acf863dfdbc14fbb2819ebd
smallPolynomial 7625ba3b17eff3a2ea2b4795180f2b88b7f259f1222db3e1ec87bc0a7ec2a6dc
smallFromWords 51ec7fb782ae65ac7bb45526856764bfb48998f1fc3146dfbceef63939c97309
publicKey 3d7540e190849c1cec6fb7c0087e5aa7dabfe2796b307121014bd4a6221f6cf1
secretKey fe66dd99e5188c6502f98ca5b359c456bab967eeb1eac64d5d78192f29c4735d
ciphertext 90c6d131c3d43e21d17e487a1286b407615679b6e5f52680733a55c1241d3a22
sharedSecret 43186dfaf7acd073954edca472804c6c181401c9311164a737e717a42d342ec0
hostileSharedSecret 8cd35eb3a142d6916067dff192eef3941ed281d703de09e475e64e91778f1e2b
hostileDecryption 81b9d1f3f5bf8c54f5aca642cad2e87f4a702ac188407e451a9e96eadd31241b
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
    sequence: LinearCongruentialSequence,
}

impl SequenceRandom {
    /// The source of a seed.
    pub(crate) fn new(seed: u32) -> Self {
        SequenceRandom {
            sequence: LinearCongruentialSequence::new(seed),
        }
    }
}

impl RandomGenerating for SequenceRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        for byte in bytes.iter_mut() {
            *byte = (self.sequence.nextState() >> 16) as u8;
        }
    }
}
