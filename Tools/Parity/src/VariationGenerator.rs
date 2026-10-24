/// The seeded generator of the inputs of the parity variations: SplitMix64.
///
/// The inputs of a variation depend only on the run seed, the algorithm name and the case
/// number, so a case gives the same inputs in any shard and in any order.
#[derive(Clone)]
pub struct VariationGenerator {
    state: u64,
}

impl VariationGenerator {
    /// Makes a generator from a seed.
    pub fn new(seed: u64) -> Self {
        VariationGenerator { state: seed }
    }

    /// Makes the generator of one case of one algorithm.
    pub fn forCase(runSeed: u64, algorithm: &str, case: u64) -> Self {
        // FNV-1a of the name keeps the cases of two algorithms apart.
        let nameHash = algorithm
            .bytes()
            .fold(0xCBF2_9CE4_8422_2325u64, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01B3)
            });
        let mut generator = VariationGenerator::new(runSeed ^ nameHash);
        let mixed = generator.nextWord() ^ case.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        VariationGenerator::new(mixed)
    }

    /// The next 64 bits.
    pub fn nextWord(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut word = self.state;
        word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        word ^ (word >> 31)
    }

    /// A number below a bound, which must not be zero.
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound > 0, "the bound of a random number must not be zero");
        self.nextWord() % bound
    }

    /// Random bytes of a length.
    pub fn bytes(&mut self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        for chunk in bytes.chunks_mut(8) {
            let word = self.nextWord().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        bytes
    }

    /// A 48-byte entropy input for a KAT generator.
    pub fn entropy(&mut self) -> [u8; 48] {
        self.bytes(48).try_into().expect("48 bytes")
    }

    /// A copy of bytes, which must not be empty, with one random bit changed.
    pub fn withChangedBit(&mut self, bytes: &[u8]) -> Vec<u8> {
        let bit = self.below(8 * bytes.len() as u64) as usize;
        let mut changed = bytes.to_vec();
        changed[bit / 8] ^= 1 << (bit % 8);
        changed
    }

    /// The length of a variation message: empty in one case of eight, else short, medium or
    /// long, up to 9280 bytes.
    pub fn messageLength(&mut self) -> usize {
        match self.below(8) {
            0 => 0,
            1..=3 => 1 + self.below(64) as usize,
            4..=6 => 65 + self.below(1024) as usize,
            _ => 1089 + self.below(8192) as usize,
        }
    }

    /// True when a signature variation uses the context form of signing and verification:
    /// always with a non-empty context, and in one case of two with the empty context.
    pub fn usesContextForm(&mut self, contextLength: usize) -> bool {
        contextLength > 0 || self.below(2) == 0
    }

    /// The length of a variation context string. A scheme with context support gets 0 to 255
    /// bytes, empty in one case of four. A scheme without it gets an empty context, except in
    /// one case of eight, where it gets 1 to 32 bytes that both sides must refuse.
    pub fn contextLength(&mut self, isSupported: bool) -> usize {
        if isSupported {
            if self.below(4) == 0 {
                0
            } else {
                1 + self.below(255) as usize
            }
        } else if self.below(8) == 0 {
            1 + self.below(32) as usize
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VariationGenerator;

    #[test]
    fn splitMixGivesItsPublishedFirstOutputs() {
        // The first outputs of SplitMix64 from seed 0, as the reference implementation gives.
        let mut generator = VariationGenerator::new(0);
        assert_eq!(generator.nextWord(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(generator.nextWord(), 0x6E78_9E6A_A1B9_65F4);
    }

    #[test]
    fn caseGeneratorsGiveTheOutputsOfAnIndependentModel() {
        // A Python model of FNV-1a and SplitMix64 gives these first words.
        assert_eq!(
            VariationGenerator::forCase(1, "ML-KEM-512", 0).nextWord(),
            0x7176_987E_2348_0893
        );
        assert_eq!(
            VariationGenerator::forCase(16, "ML-DSA-44", 7).nextWord(),
            0xC0E8_E8F4_3E4E_0A06
        );
    }

    #[test]
    fn entropyInputsAreTheNext48BytesOfTheGenerator() {
        let mut generator = VariationGenerator::new(11);
        let mut copy = generator.clone();
        let first = generator.entropy();
        assert_eq!(first.to_vec(), copy.bytes(48));
        let second = generator.entropy();
        assert_ne!(first, second);
        assert!(first.iter().any(|byte| *byte > 1));
    }

    #[test]
    fn casesOfOneSeedDifferByNameAndByCase() {
        let first = VariationGenerator::forCase(1, "ML-KEM-512", 0).nextWord();
        assert_eq!(
            first,
            VariationGenerator::forCase(1, "ML-KEM-512", 0).nextWord()
        );
        assert_ne!(
            first,
            VariationGenerator::forCase(1, "ML-KEM-768", 0).nextWord()
        );
        assert_ne!(
            first,
            VariationGenerator::forCase(1, "ML-KEM-512", 1).nextWord()
        );
        assert_ne!(
            first,
            VariationGenerator::forCase(2, "ML-KEM-512", 0).nextWord()
        );
    }

    #[test]
    fn bytesAndNumbersStayInTheirRanges() {
        let mut generator = VariationGenerator::new(9);
        assert_eq!(generator.bytes(13).len(), 13);
        assert_eq!(generator.entropy().len(), 48);
        assert!((0..1000).all(|_| generator.below(7) < 7));
        assert_eq!(generator.below(1), 0);
    }

    #[test]
    #[should_panic(expected = "must not be zero")]
    fn aZeroBoundIsADefectOfTheCaller() {
        VariationGenerator::new(0).below(0);
    }

    #[test]
    fn aChangedBitChangesExactlyOneBitAndReachesEveryBit() {
        let mut generator = VariationGenerator::new(3);
        let bytes: Vec<u8> = (0..20u32).map(|value| (value * 37) as u8).collect();
        let mut reached = [false; 160];
        for _ in 0..4000 {
            let changed = generator.withChangedBit(&bytes);
            let differences: Vec<(usize, u8)> = changed
                .iter()
                .zip(&bytes)
                .enumerate()
                .filter(|(_, (changedByte, byte))| changedByte != byte)
                .map(|(index, (changedByte, byte))| (index, changedByte ^ byte))
                .collect();
            assert_eq!(differences.len(), 1);
            let (index, difference) = differences[0];
            assert_eq!(difference.count_ones(), 1);
            reached[8 * index + difference.trailing_zeros() as usize] = true;
        }
        assert!(reached.iter().all(|isReached| *isReached));
    }

    #[test]
    fn messageLengthsCoverEachRangeAndStayInTheLimit() {
        let mut generator = VariationGenerator::new(4);
        let lengths: Vec<usize> = (0..4000).map(|_| generator.messageLength()).collect();
        let inRange = |low: usize, high: usize| -> Vec<usize> {
            lengths
                .iter()
                .copied()
                .filter(|length| (low..=high).contains(length))
                .collect()
        };
        // The short range has 64 values and about 1500 draws, so both ends appear.
        let short = inRange(1, 64);
        assert_eq!(short.iter().min(), Some(&1));
        assert_eq!(short.iter().max(), Some(&64));
        let medium = inRange(65, 1088);
        assert!(medium.iter().min().is_some_and(|minimum| *minimum < 75));
        assert!(medium.iter().max().is_some_and(|maximum| *maximum > 1078));
        let long = inRange(1089, 9280);
        assert!(long.iter().min().is_some_and(|minimum| *minimum < 1189));
        assert!(long.iter().max().is_some_and(|maximum| *maximum > 9180));
        assert!(lengths.iter().all(|length| *length <= 9280));
        let empty = lengths.iter().filter(|length| **length == 0).count();
        assert_eq!(
            empty + short.len() + medium.len() + long.len(),
            lengths.len()
        );
        assert!((380..620).contains(&empty), "{empty}");
    }

    #[test]
    fn aNonEmptyContextAlwaysUsesTheContextFormAndAnEmptyOneUsesBoth() {
        let mut generator = VariationGenerator::new(6);
        assert!((0..500).all(|_| {
            let length = 1 + generator.below(255) as usize;
            generator.usesContextForm(length)
        }));
        let forms: Vec<bool> = (0..500).map(|_| generator.usesContextForm(0)).collect();
        assert!(forms.contains(&true) && forms.contains(&false));
    }

    #[test]
    fn contextLengthsFollowTheSupportOfTheScheme() {
        let mut generator = VariationGenerator::new(5);
        let supported: Vec<usize> = (0..2000).map(|_| generator.contextLength(true)).collect();
        assert!(supported.iter().all(|length| *length <= 255));
        assert!(supported.contains(&255) && supported.contains(&1));
        let emptySupported = supported.iter().filter(|length| **length == 0).count();
        assert!((400..600).contains(&emptySupported), "{emptySupported}");
        let unsupported: Vec<usize> = (0..2000).map(|_| generator.contextLength(false)).collect();
        assert!(unsupported.iter().all(|length| *length <= 32));
        assert!(unsupported.contains(&32) && unsupported.contains(&1));
        let emptyUnsupported = unsupported.iter().filter(|length| **length == 0).count();
        assert!(
            (1650..1850).contains(&emptyUnsupported),
            "{emptyUnsupported}"
        );
    }
}
