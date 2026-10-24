use OQSNativeDomain::RandomGenerating;

/// A random source for the fuzz programs: seeded SplitMix64 bytes, or one fixed byte.
///
/// `tests/fuzz_test_kem.c` and `tests/fuzz_test_sig.c` of liboqs feed `rand()` of a seed from
/// the fuzzer to the algorithm. This source plays that role with a seed of the test.
pub struct FuzzRandom {
    state: u64,
    fixedByte: Option<u8>,
}

impl FuzzRandom {
    /// A source of seeded SplitMix64 bytes.
    pub fn seeded(seed: u64) -> Self {
        FuzzRandom {
            state: seed,
            fixedByte: None,
        }
    }

    /// A source that gives one byte again and again, such as all zeros.
    pub fn fixed(byte: u8) -> Self {
        FuzzRandom {
            state: 0,
            fixedByte: Some(byte),
        }
    }

    /// The source of a fuzz case: all zeros for case 0, all ones for case 1, and seeded bytes
    /// for every other case.
    pub fn forCase(seed: u64, case: u64) -> Self {
        match case {
            0 => Self::fixed(0x00),
            1 => Self::fixed(0xFF),
            _ => Self::seeded(seed ^ case.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
        }
    }

    /// The source of the hostile values of a fuzz case, apart from the source of the case, so
    /// the values of a reported case and seed can be made again.
    pub fn hostile(seed: u64, case: u64) -> Self {
        Self::seeded(seed ^ !case)
    }

    /// A wrong length for an input of a fuzz case: `1 + case % 7` bytes longer for an even
    /// case, and that many bytes shorter, down to zero, for an odd case.
    pub fn wrongLength(case: u64, length: usize) -> usize {
        let difference = 1 + (case % 7) as usize;
        if case.is_multiple_of(2) {
            length + difference
        } else {
            length.saturating_sub(difference)
        }
    }

    /// The next 64 bits of SplitMix64.
    pub fn nextWord(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut word = self.state;
        word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        word ^ (word >> 31)
    }
}

impl RandomGenerating for FuzzRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        match self.fixedByte {
            Some(byte) => bytes.fill(byte),
            None => {
                for chunk in bytes.chunks_mut(8) {
                    let word = self.nextWord().to_le_bytes();
                    chunk.copy_from_slice(&word[..chunk.len()]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FuzzRandom;
    use OQSNativeDomain::RandomGenerating;

    fn drawn(random: &mut FuzzRandom, length: usize) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![0u8; length];
        random.fillRandomBytes(&mut bytes);
        bytes
    }

    #[test]
    fn casesZeroAndOneAreTheExtremesAndTheOthersAreSeeded() {
        assert!(
            drawn(&mut FuzzRandom::forCase(5, 0), 20)
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            drawn(&mut FuzzRandom::forCase(5, 1), 20)
                .iter()
                .all(|byte| *byte == 0xFF)
        );
        // Case 2 of seed 0xFF starts SplitMix64 at 0xFF ^ 2 * 0x9E37_79B9_7F4A_7C15, so the
        // bytes of a reported case can be made again.
        assert_eq!(
            drawn(&mut FuzzRandom::forCase(0xFF, 2), 8),
            0x3150_25C4_9661_6B4Cu64.to_le_bytes().to_vec()
        );
        let second = drawn(&mut FuzzRandom::forCase(5, 2), 20);
        assert_eq!(second, drawn(&mut FuzzRandom::forCase(5, 2), 20));
        assert_ne!(second, drawn(&mut FuzzRandom::forCase(5, 3), 20));
        assert_ne!(second, drawn(&mut FuzzRandom::forCase(6, 2), 20));
    }

    #[test]
    fn hostileValuesStartSplitMix64AtTheSeedAndTheComplementOfTheCase() {
        // SplitMix64 from 0xFF ^ !3, which is 0xFFFF_FFFF_FFFF_FF03.
        assert_eq!(
            drawn(&mut FuzzRandom::hostile(0xFF, 3), 8),
            0x4276_1CBE_DE15_74E2u64.to_le_bytes().to_vec()
        );
    }

    #[test]
    fn wrongLengthsAreLongerForEvenCasesAndShorterForOddCases() {
        assert_eq!(FuzzRandom::wrongLength(0, 16), 17);
        assert_eq!(FuzzRandom::wrongLength(2, 16), 19);
        assert_eq!(FuzzRandom::wrongLength(8, 16), 18);
        assert_eq!(FuzzRandom::wrongLength(3, 16), 12);
        assert_eq!(FuzzRandom::wrongLength(13, 16), 9);
        assert_eq!(FuzzRandom::wrongLength(5, 3), 0);
    }

    #[test]
    fn seededBytesFollowSplitMix64() {
        let mut random = FuzzRandom::seeded(0);
        // The first output of SplitMix64 from seed 0, as the reference implementation gives.
        assert_eq!(
            drawn(&mut random, 8),
            0xE220_A839_7B1D_CDAFu64.to_le_bytes().to_vec()
        );
        assert_eq!(
            drawn(&mut random, 3),
            0x6E78_9E6A_A1B9_65F4u64.to_le_bytes()[..3].to_vec()
        );
    }
}
