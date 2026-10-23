use alloc::vec::Vec;

/// The duplicated Reed-Muller code RM(1,7) of HQC, `reed_muller.c` of the reference code.
///
/// Each byte becomes a codeword of 128 bits, which the code repeats `n2 / 128` times. A copy of
/// a codeword is two 64-bit words, the first eight bytes in the first word. The decoder sums the
/// copies, takes their Hadamard transform and keeps the position of the largest absolute value,
/// with no branch on the received bits.
pub(crate) struct ReedMuller;

/// The number of bits of one codeword.
const codewordBits: usize = 128;

impl ReedMuller {
    /// The four 32-bit words of the codeword of a byte, `encode`.
    ///
    /// Bit 7 of the byte sets every bit, and bits 0 to 6 add the rows of the generator matrix.
    fn codeword(message: u8) -> [u32; 4] {
        let mask = |bit: u32| 0u32.wrapping_sub(u32::from((message >> bit) & 1));
        let first = mask(7)
            ^ (mask(0) & 0xAAAA_AAAA)
            ^ (mask(1) & 0xCCCC_CCCC)
            ^ (mask(2) & 0xF0F0_F0F0)
            ^ (mask(3) & 0xFF00_FF00)
            ^ (mask(4) & 0xFFFF_0000);
        let second = first ^ mask(5);
        let fourth = second ^ mask(6);
        let third = fourth ^ mask(5);
        [first, second, third, fourth]
    }

    /// The codewords of a message, each repeated `multiplicity` times, `reed_muller_encode`.
    pub(crate) fn encoded(message: &[u8], multiplicity: usize) -> Vec<u64> {
        let mut words = Vec::with_capacity(2 * multiplicity * message.len());
        for byte in message {
            let [first, second, third, fourth] = Self::codeword(*byte);
            let low = u64::from(first) + (u64::from(second) << 32);
            let high = u64::from(third) + (u64::from(fourth) << 32);
            for _ in 0..multiplicity {
                words.push(low);
                words.push(high);
            }
        }
        words
    }

    /// The message of `byteCount` bytes of a received word, `reed_muller_decode`.
    pub(crate) fn decoded(received: &[u64], byteCount: usize, multiplicity: usize) -> Vec<u8> {
        received
            .chunks_exact(2 * multiplicity)
            .take(byteCount)
            .map(|copies| {
                let mut transform = Self::hadamardTransform(Self::bitCounts(copies));
                // The sums count ones and not signs, so the first entry is too high by half the
                // sum of every copy.
                transform[0] -= 64 * multiplicity as i16;
                Self::peakPosition(&transform)
            })
            .collect()
    }

    /// For each of the 128 bit positions, the number of copies with that bit set,
    /// `expand_and_sum`.
    fn bitCounts(copies: &[u64]) -> [i16; codewordBits] {
        let mut counts = [0i16; codewordBits];
        for copy in copies.chunks_exact(2) {
            for (position, count) in counts.iter_mut().enumerate() {
                *count += ((copy[position / 64] >> (position % 64)) & 1) as i16;
            }
        }
        counts
    }

    /// The Hadamard transform of the counts, `hadamard`: seven passes of sums and differences.
    fn hadamardTransform(counts: [i16; codewordBits]) -> [i16; codewordBits] {
        let mut source = counts;
        for _ in 0..7 {
            let mut target = [0i16; codewordBits];
            for (index, pair) in source.chunks_exact(2).enumerate() {
                target[index] = pair[0] + pair[1];
                target[index + 64] = pair[0] - pair[1];
            }
            source = target;
        }
        source
    }

    /// The position of the first largest absolute value, plus 128 when that value is positive,
    /// `find_peaks`. A tie keeps the lower position.
    fn peakPosition(transform: &[i16; codewordBits]) -> u8 {
        let mut peakAbsolute = 0i32;
        let mut peakValue = 0i32;
        let mut peakPosition = 0i32;
        for (position, value) in transform.iter().enumerate() {
            let value = i32::from(*value);
            let positiveMask = -i32::from(value > 0);
            let absolute = -value ^ (positiveMask & (value ^ -value));
            let largerMask = -i32::from(absolute > peakAbsolute);
            peakValue ^= largerMask & (value ^ peakValue);
            peakPosition ^= largerMask & (position as i32 ^ peakPosition);
            peakAbsolute ^= largerMask & (absolute ^ peakAbsolute);
        }
        (peakPosition + 128 * i32::from(peakValue > 0)) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::ReedMuller;
    use crate::parameters::{hqc1, hqc3, hqc5};
    use crate::testInputs::{digest, receivedWord};

    /// The bit of a codeword at a position, from the four 32-bit words.
    fn bit(codeword: [u32; 4], position: usize) -> u32 {
        (codeword[position / 32] >> (position % 32)) & 1
    }

    #[test]
    fn codewordsAreTheRowsOfTheGeneratorMatrix() {
        // The rows of the comment of `encode`: bit 7 is all ones, and bit `j` below 7 is bit `j`
        // of the position.
        for message in 0..=255u8 {
            let codeword = ReedMuller::codeword(message);
            for position in 0..128 {
                let mut expected = u32::from(message >> 7);
                for row in 0..7 {
                    expected ^= u32::from((message >> row) & 1) & ((position as u32 >> row) & 1);
                }
                assert_eq!(bit(codeword, position), expected, "{message}, {position}");
            }
        }
        assert_eq!(ReedMuller::codeword(0x80), [u32::MAX; 4]);
        assert_eq!(ReedMuller::codeword(0x01), [0xAAAA_AAAA; 4]);
        assert_eq!(ReedMuller::codeword(0x20), [0, u32::MAX, 0, u32::MAX]);
        assert_eq!(ReedMuller::codeword(0x40), [0, 0, u32::MAX, u32::MAX]);
    }

    #[test]
    fn encodingRepeatsTheTwoWordsOfEachCodeword() {
        let words = ReedMuller::encoded(&[0x01, 0x20], 3);
        assert_eq!(words.len(), 12);
        for copy in 0..3 {
            assert_eq!(words[2 * copy], 0xAAAA_AAAA_AAAA_AAAA);
            assert_eq!(words[2 * copy + 1], 0xAAAA_AAAA_AAAA_AAAA);
            assert_eq!(words[6 + 2 * copy], 0xFFFF_FFFF_0000_0000);
            assert_eq!(words[6 + 2 * copy + 1], 0xFFFF_FFFF_0000_0000);
        }
    }

    #[test]
    fn decodingInvertsEncodingForEveryByte() {
        for multiplicity in [3, 5] {
            let message: Vec<u8> = (0..=255).collect();
            let words = ReedMuller::encoded(&message, multiplicity);
            assert_eq!(ReedMuller::decoded(&words, 256, multiplicity), message);
        }
    }

    #[test]
    fn decodingCorrectsFlipsBelowHalfTheDistance() {
        // RM(1,7) has the minimum distance 64, and three copies give 192, so 95 flipped bits
        // of the 384 still decode.
        let message = [0x5Cu8, 0xA3];
        let mut words = ReedMuller::encoded(&message, 3);
        let mut state = 7u32;
        let mut flipped = std::collections::BTreeSet::new();
        while flipped.len() < 95 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            flipped.insert((state >> 8) as usize % 384);
        }
        for position in flipped {
            words[position / 64] ^= 1 << (position % 64);
        }
        assert_eq!(ReedMuller::decoded(&words, 2, 3), message);
    }

    #[test]
    fn peakKeepsTheFirstLargestAbsoluteValueAndItsSign() {
        let mut transform = [0i16; 128];
        assert_eq!(ReedMuller::peakPosition(&transform), 0);
        transform[5] = -7;
        transform[9] = 7;
        assert_eq!(ReedMuller::peakPosition(&transform), 5);
        transform[3] = 7;
        assert_eq!(ReedMuller::peakPosition(&transform), 128 + 3);
        transform[127] = -8;
        assert_eq!(ReedMuller::peakPosition(&transform), 127);
    }

    #[test]
    fn peakFollowsEachLargerAbsoluteValueInTurn() {
        // The absolute values 1, 2 and 3 in turn: each one is larger than the peak before it, so
        // the peak is the last one. The values -1, 3 and -3: the second 3 is not larger, so the
        // peak is the first 3, which is positive.
        let mut rising = [0i16; 128];
        rising[10] = 1;
        rising[20] = -2;
        rising[30] = 3;
        assert_eq!(ReedMuller::peakPosition(&rising), 128 + 30);
        let mut repeated = [0i16; 128];
        repeated[10] = -1;
        repeated[20] = 3;
        repeated[30] = -3;
        assert_eq!(ReedMuller::peakPosition(&repeated), 128 + 20);
    }

    #[test]
    fn decodingOfManyErrorsAndTiesGivesTheBytesOfTheCFunction() {
        // The digests of `reed_muller_decode` of liboqs 0.16.0 for three received words of each
        // set, with the seeds 400, 401 and 402. A block flips each bit of a codeword with a
        // probability from 0 to almost 1, so the words hold clean blocks, blocks with more flips
        // than the code corrects, and ties of the largest absolute value.
        let mut tieCount = 0;
        for (seed, parameters, expected) in [
            (
                400,
                &hqc1,
                "eb8f92a7a326b3e107f91dbba78cc1e77f8be832b9a4db9b3adfe83c050c8270",
            ),
            (
                401,
                &hqc3,
                "da51333fde077b6b4cb7d5216df7bb306acc36065b5c8d885dc49d4c5b9500a5",
            ),
            (
                402,
                &hqc5,
                "4aab8ca4de4b5242c5e82d3bc562eb18590d899d03b1a5cf7a646ffa28ca2c88",
            ),
        ] {
            let multiplicity = parameters.multiplicity();
            let mut state = seed;
            let mut decoded = Vec::new();
            for shift in 0..3 {
                let word = receivedWord(&mut state, parameters, shift);
                decoded.extend(ReedMuller::decoded(
                    &word,
                    parameters.reedSolomonLength,
                    multiplicity,
                ));
                for copies in word.chunks_exact(2 * multiplicity) {
                    let mut transform =
                        ReedMuller::hadamardTransform(ReedMuller::bitCounts(copies));
                    transform[0] -= 64 * multiplicity as i16;
                    let largest = transform.iter().map(|value| value.unsigned_abs()).max();
                    let peakCount = transform
                        .iter()
                        .filter(|value| Some(value.unsigned_abs()) == largest)
                        .count();
                    tieCount += usize::from(peakCount > 1);
                }
            }
            assert_eq!(
                digest(&decoded),
                expected,
                "{}, seed {seed}",
                parameters.description.name
            );
        }
        // The seeds reach ties of the largest absolute value.
        assert!(tieCount > 0);
    }

    #[test]
    fn hadamardTransformOfACodewordPeaksAtItsMessage() {
        // The counts of one copy of the codeword of 0x13 are its bits, and the transform has
        // its peak at position 0x13 after the correction of the first entry.
        let words = ReedMuller::encoded(&[0x13], 1);
        let mut transform = ReedMuller::hadamardTransform(ReedMuller::bitCounts(&words));
        transform[0] -= 64;
        assert_eq!(transform[0x13], -64);
        assert_eq!(ReedMuller::peakPosition(&transform), 0x13);
        assert_eq!(transform.iter().filter(|value| **value != 0).count(), 1);
    }
}
