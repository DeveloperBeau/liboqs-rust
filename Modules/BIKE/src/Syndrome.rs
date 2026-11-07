use crate::Parameters;
use alloc::vec;
use alloc::vec::Vec;

/// The syndrome of the decoder in three copies, `syndrome_t` of the C code.
///
/// The words hold the `r` coefficients of the syndrome and then the same coefficients again
/// and again, so a rotation reads a window of the words with no wrap-around.
pub(crate) struct Syndrome<'parameters> {
    parameters: &'parameters Parameters,
    words: Vec<u64>,
}

impl<'parameters> Syndrome<'parameters> {
    /// The syndrome of a reduced polynomial, the copy of `compute_syndrome` and `dup_port` of
    /// the C code.
    pub(crate) fn new(parameters: &'parameters Parameters, polynomial: &[u64]) -> Self {
        let wordCount = parameters.wordCount();
        let mut words = vec![0u64; 3 * wordCount];
        words[..wordCount].copy_from_slice(polynomial);
        let lead = parameters.lastWordBits();
        let trail = 64 - lead;
        // The coefficients from r up in the last word start the second copy.
        words[wordCount - 1] =
            (words[0] << lead) + (words[wordCount - 1] & parameters.lastWordMask());
        for index in 0..2 * wordCount - 1 {
            words[wordCount + index] = (words[index] >> trail) + (words[index + 1] << lead);
        }
        Syndrome { parameters, words }
    }

    /// The number of coefficients of the syndrome that are one, `r_bits_vector_weight` of the
    /// first `r` coefficients.
    pub(crate) fn weight(&self) -> u64 {
        let wordCount = self.parameters.wordCount();
        let full: u64 = self.words[..wordCount - 1]
            .iter()
            .map(|word| u64::from(word.count_ones()))
            .sum();
        full + u64::from((self.words[wordCount - 1] & self.parameters.lastWordMask()).count_ones())
    }

    /// The words that a rotation writes: the polynomial and the reach of the largest step.
    pub(crate) fn rotationLength(parameters: &Parameters) -> usize {
        parameters.wordCount() + 2 * parameters.largestRotationStep()
    }

    /// Writes the syndrome rotated right by a number of coefficients into the first
    /// `R_QWORDS` words of an output of `rotationLength` words, `rotate_right_port` of the C
    /// code. The words after them are not part of the result.
    ///
    /// The rotation moves whole words by each power of two of the word count, from
    /// `largestRotationStep` down to one, with a mask in place of a branch, and then moves the
    /// bits within the words. A count above `r` comes from an invalid secret key. It moves at
    /// most `2 largestRotationStep - 1` words, as in the C code, and reads only the copies.
    pub(crate) fn rotateRight(&self, count: u32, output: &mut [u64]) {
        let wordCount = self.parameters.wordCount();
        let length = Self::rotationLength(self.parameters);
        output[..length].copy_from_slice(&self.words[..length]);
        let mut wordShift = count / 64;
        let mut step = self.parameters.largestRotationStep();
        while step >= 1 {
            // All ones when the remaining shift is at least the step, as `secure_l32_mask`.
            let takeMask = 0u64.wrapping_sub(u64::from(wordShift >= step as u32));
            wordShift -= (step as u32) & (takeMask as u32);
            for index in 0..wordCount + step {
                let moved = output[index + step];
                output[index] ^= takeMask & (output[index] ^ moved);
            }
            step >>= 1;
        }
        let bits = count % 64;
        // A shift by zero bits keeps the words, and avoids a shift of a word by 64.
        let nonzeroMask = 0u64.wrapping_sub(u64::from(bits != 0));
        let highShift = (64 - bits) & (nonzeroMask as u32);
        for index in 0..wordCount {
            let low = output[index] >> bits;
            let high = (output[index + 1] << highShift) & nonzeroMask;
            // The two parts hold different bits, so their sum is exact.
            output[index] = low + high;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Syndrome;
    use crate::parameters::{Parameters, bikeL1, bikeL3, bikeL5};
    use crate::testSupport::{digest, seededPolynomial, wordBytes};

    const parameterSets: [&Parameters; 3] = [&bikeL1, &bikeL3, &bikeL5];

    fn bitAt(words: &[u64], position: usize) -> u64 {
        words[position / 64] >> (position % 64) & 1
    }

    fn rotated(syndrome: &Syndrome<'_>, count: u32) -> Vec<u64> {
        let mut output = vec![0u64; Syndrome::rotationLength(syndrome.parameters)];
        syndrome.rotateRight(count, &mut output);
        output.truncate(syndrome.parameters.wordCount());
        output
    }

    #[test]
    fn copiesAreTheCopiesOfTheCCode() {
        // The SHA3-256 of the words of `dup_port` of liboqs 0.16.0 for the seeded reduced
        // polynomial of the seed 6.
        let expected = [
            "75f3e46b77b37b0b05bbd6b179eee60a0fbe23ce96926ad1365a06be57884ca2",
            "d11dd81f14eb9954c7a530899f04d71ccf32b7d904864cc895b8653380d7fbe9",
            "5d11db5a1a44813fa615d5b9b2a6962d930881cdb5f1ac7e7ccd73a01d4f8707",
        ];
        for (parameters, expected) in parameterSets.into_iter().zip(expected) {
            let syndrome = Syndrome::new(parameters, &seededPolynomial(parameters, 6, true));
            assert_eq!(digest(&wordBytes(&syndrome.words)), expected);
        }
    }

    #[test]
    fn eachCoefficientOfTheCopiesRepeatsTheCoefficientModuloR() {
        for parameters in parameterSets {
            let polynomial = seededPolynomial(parameters, 8, true);
            let syndrome = Syndrome::new(parameters, &polynomial);
            let r = parameters.blockBits;
            let wordCount = parameters.wordCount();
            // The last word is not part of the copies, and stays zero as in the C code.
            for position in 0..64 * (3 * wordCount - 1) {
                assert_eq!(
                    bitAt(&syndrome.words, position),
                    bitAt(&polynomial, position % r),
                    "{} position {position}",
                    parameters.description.name
                );
            }
            assert_eq!(syndrome.words[3 * wordCount - 1], 0);
        }
    }

    #[test]
    fn rotationsAreTheRotationsOfTheCCode() {
        // The SHA3-256 of the words of `rotate_right_port` of liboqs 0.16.0 for the syndrome of
        // the seeded reduced polynomial of the seed 6. The counts are 0, 1, 63, 64, 65, 1000,
        // r - 1, r, r + 1, 64 R_QWORDS - 1, 64 R_QWORDS, 2 r, the largest reach
        // 64 (2 largestRotationStep - 1) + 63, the next count, 2^31 - 1, 2^31 and 2^32 - 1.
        let expected: [[&str; 17]; 3] = [
            [
                "5338d501fa333e51664c76a2f3683c2f1a6413f1d68cf652fc31729f67798875",
                "6d616af4d2549bed37ae5b81c6f2b55eddb3da113555d53584b44631cb8f14bb",
                "fe4b6d472b4460c81e9c74effdf548288ce2ab91bdfce50da210864fc638891b",
                "8d66de330c8f7135ef252c2a1acd5dfd26a4fe716d5302421a3c9e34fc55f2d4",
                "4bf8d59588d55f54529fcc85df69d24576434fdbe0f0f18308669a506917b0bf",
                "4a7d3915d1f9d4b4254119bc124e1fa73a4d322c2147da342cc50711dcfa9a5e",
                "e0379af327e461fa3e1e6481b3fc55e83e71de11fff5fe25b9ac84a9c6ae5992",
                "5338d501fa333e51664c76a2f3683c2f1a6413f1d68cf652fc31729f67798875",
                "6d616af4d2549bed37ae5b81c6f2b55eddb3da113555d53584b44631cb8f14bb",
                "44c4201a9c42c055c217d16732a99e535392d49e3dbfda2a30346f2ef47b2b57",
                "118727f99f9c6977de71843fea7a2a4d6c0d62f137c7121fccfa2ebd89d9cb3e",
                "3501ae6e59695a5133cfab8829ee0838638bc15cfa8d643396bafecfd1ada52f",
                "794060100797ee5f8b245ea8bf63889f8d29229668cdd15f134a062cf1caa3da",
                "e4346c7d8e0d5d25e60a1e69daa9a6e6cf7a95974a7915a907cb1a3aa0ac3cf4",
                "794060100797ee5f8b245ea8bf63889f8d29229668cdd15f134a062cf1caa3da",
                "e4346c7d8e0d5d25e60a1e69daa9a6e6cf7a95974a7915a907cb1a3aa0ac3cf4",
                "794060100797ee5f8b245ea8bf63889f8d29229668cdd15f134a062cf1caa3da",
            ],
            [
                "f5f79f65aa260ae67cc67e129d8d3d530f1b209b51adfb1d8ae62606338ca40c",
                "295b7d04bc7d0c2c0fb859e7988f5a4286fc451cf23695cde094b989d20b843e",
                "4a9c8e0a33c0bf224fca05de9dafe4e550ba0e6e84a8283d2e64df4466efa27b",
                "fe97d28e326f0424972eea5f1a96fd0aea9e5f1f08c55908fddd3ba2642d5372",
                "3fad8de0764096fcf63b19af3775086166f54c7783408caef8c38a55551b19bc",
                "5460d9487c856938a731ee1e2f6cc17b5799f45c99aa6334cb50242c802736da",
                "4e06d0e662d299a16cd648a3345d0f8f7b39864d3d20b4d38a366844849c5c37",
                "f5f79f65aa260ae67cc67e129d8d3d530f1b209b51adfb1d8ae62606338ca40c",
                "295b7d04bc7d0c2c0fb859e7988f5a4286fc451cf23695cde094b989d20b843e",
                "537d60b67f5588acbaa723295b989606558e3bd166814731117ba97137160b76",
                "da8bb8eaaec46840a43d378f745d617214d6f5049b105df1dec3f08a6363139a",
                "96afa9b54a138dbb41ff341daf0b98aa2a5b4ac31be070d79278b43512680d04",
                "396a48a850c615f22451b22929d8250edc56560001b41eb868f470f46d3ad0b4",
                "e30e8620984821b6892d3b98a855c6dfb225f74bdedd8541e6326d3692c8051f",
                "396a48a850c615f22451b22929d8250edc56560001b41eb868f470f46d3ad0b4",
                "e30e8620984821b6892d3b98a855c6dfb225f74bdedd8541e6326d3692c8051f",
                "396a48a850c615f22451b22929d8250edc56560001b41eb868f470f46d3ad0b4",
            ],
            [
                "7866927dfd966a921c81f3640850cff86fca0c9f3c5135dfb569986ab9bb5ec8",
                "e58cec551c6d3a611b241427b5650be6d25f271ada51cf6acd7301d9abb7008b",
                "b4196eccb4530e7b4803b1066d6c931ff8e9dd4fb9b2ec17ede1e706f47d1c92",
                "af748eaca0c850aa77865385929b249802f9c1029260d40ec99966f403ca88f2",
                "512ed1947209c8e176ad6e0f1551574adac0b5631e0797623dd945454b0f0052",
                "968d3d3e3f25197445787cfdf4ffca496df3cbb09ef1e492f8a8490697c412cf",
                "73613ff34a66622c46713c3abf0b8f620196c2897ee280c9bd7623bd7a976a1e",
                "7866927dfd966a921c81f3640850cff86fca0c9f3c5135dfb569986ab9bb5ec8",
                "e58cec551c6d3a611b241427b5650be6d25f271ada51cf6acd7301d9abb7008b",
                "c867f6edba70acc43dd017a03fd6d0adaaa6b7a84ea958d35a4a78e05bb7f8a5",
                "07ef4bf6f08abdf122c775f5bf79b25fce1f96644c9abbebb6e1ffb2646f92b9",
                "42a7f1ddd313710dfccfff3656e61f8c4c84b12e6117a1fa175cc67276f54f72",
                "5479bcc0c35e1215b375d0e204b75fe3451abce5d378f2cb7f699698522581cc",
                "6401c87723e487229461b771f19ae45d7d00ba11514a0c7b56b9dfea216669ef",
                "5479bcc0c35e1215b375d0e204b75fe3451abce5d378f2cb7f699698522581cc",
                "6401c87723e487229461b771f19ae45d7d00ba11514a0c7b56b9dfea216669ef",
                "5479bcc0c35e1215b375d0e204b75fe3451abce5d378f2cb7f699698522581cc",
            ],
        ];
        for (parameters, expected) in parameterSets.into_iter().zip(expected) {
            let r = parameters.blockBits as u32;
            let words = parameters.wordCount() as u32;
            let step = parameters.largestRotationStep() as u32;
            let counts = [
                0,
                1,
                63,
                64,
                65,
                1000,
                r - 1,
                r,
                r + 1,
                64 * words - 1,
                64 * words,
                2 * r,
                64 * (2 * step - 1) + 63,
                64 * 2 * step,
                (1 << 31) - 1,
                1 << 31,
                u32::MAX,
            ];
            let syndrome = Syndrome::new(parameters, &seededPolynomial(parameters, 6, true));
            for (count, expected) in counts.into_iter().zip(expected) {
                assert_eq!(
                    digest(&wordBytes(&rotated(&syndrome, count))),
                    expected,
                    "{} count {count}",
                    parameters.description.name
                );
            }
        }
    }

    #[test]
    fn rotationByACountBelowRIsACyclicRotation() {
        for parameters in parameterSets {
            let polynomial = seededPolynomial(parameters, 9, true);
            let syndrome = Syndrome::new(parameters, &polynomial);
            let r = parameters.blockBits;
            for count in [0usize, 1, 64, 127, r / 3, r - 64, r - 1] {
                let result = rotated(&syndrome, count as u32);
                for position in 0..r {
                    assert_eq!(
                        bitAt(&result, position),
                        bitAt(&polynomial, (position + count) % r),
                        "{} count {count} position {position}",
                        parameters.description.name
                    );
                }
            }
        }
    }

    #[test]
    fn aCountOfAnInvalidKeyMovesAtMostTheLargestReach() {
        // The words move by at most 2 largestRotationStep - 1 for any count, and then the bits
        // move by the count modulo 64, so the copies cover every read.
        for parameters in parameterSets {
            let syndrome = Syndrome::new(parameters, &seededPolynomial(parameters, 10, true));
            let reach = 64 * (2 * parameters.largestRotationStep() as u32 - 1);
            for bits in [0u32, 5, 63] {
                let capped = rotated(&syndrome, reach + bits);
                assert_eq!(rotated(&syndrome, u32::MAX - 63 + bits), capped);
                assert_eq!(rotated(&syndrome, reach + 64 + bits), capped);
                assert_ne!(rotated(&syndrome, reach - 64 + bits), capped);
            }
        }
    }

    #[test]
    fn weightCountsTheCoefficientsBelowR() {
        for parameters in parameterSets {
            let polynomial = seededPolynomial(parameters, 11, true);
            let expected: u32 = polynomial.iter().map(|word| word.count_ones()).sum();
            let syndrome = Syndrome::new(parameters, &polynomial);
            // The copies hold more ones in the last word and after it, which do not count.
            assert_ne!(syndrome.words[parameters.wordCount() - 1].count_ones(), 0);
            assert_eq!(syndrome.weight(), u64::from(expected));
            let ones: Vec<u64> = (0..parameters.wordCount())
                .map(|index| {
                    if index + 1 == parameters.wordCount() {
                        parameters.lastWordMask()
                    } else {
                        u64::MAX
                    }
                })
                .collect();
            assert_eq!(
                Syndrome::new(parameters, &ones).weight(),
                parameters.blockBits as u64
            );
        }
    }
}
