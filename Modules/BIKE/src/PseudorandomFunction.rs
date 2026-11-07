use OQSNativeSHA3::{SHAKE256, SHAKEReader};

/// The pseudorandom function of BIKE, `shake_prf.c` of the C code: SHAKE256 of a 32-byte seed,
/// read one block of 136 bytes at a time.
///
/// A request that fits in the rest of the current block takes the next bytes of the block. A
/// request that does not fit squeezes a new block and takes its first bytes, so the rest of the
/// old block is lost. The C code also counts the blocks and fails after `2^32 - 1` of them,
/// which no operation of BIKE reaches.
pub(crate) struct PseudorandomFunction {
    reader: SHAKEReader,
    block: [u8; SHAKE256::rate],
    position: usize,
}

impl PseudorandomFunction {
    /// Makes the function of a seed, `init_prf_state`. The first request squeezes a block.
    pub(crate) fn new(seed: &[u8; 32]) -> Self {
        let mut function = SHAKE256::new();
        function.absorb(seed);
        PseudorandomFunction {
            reader: function.finalize(),
            block: [0u8; SHAKE256::rate],
            position: SHAKE256::rate,
        }
    }

    /// Fills an output of at most one block with the next bytes, `get_prf_output`.
    pub(crate) fn fill(&mut self, output: &mut [u8]) {
        let length = output.len();
        debug_assert!(length <= SHAKE256::rate);
        if length + self.position <= SHAKE256::rate {
            output.copy_from_slice(&self.block[self.position..self.position + length]);
            self.position += length;
        } else {
            self.reader.squeeze(&mut self.block);
            output.copy_from_slice(&self.block[..length]);
            self.position = length;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PseudorandomFunction;
    use OQSNativeSHA3::SHAKE256;

    fn counting() -> [u8; 32] {
        core::array::from_fn(|index| index as u8)
    }

    /// The first bytes of the SHAKE256 output of a seed.
    fn stream(seed: &[u8; 32], length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        SHAKE256::hash(seed, &mut output);
        output
    }

    fn requests(function: &mut PseudorandomFunction, lengths: &[usize]) -> Vec<Vec<u8>> {
        lengths
            .iter()
            .map(|length| {
                let mut output = vec![0u8; *length];
                function.fill(&mut output);
                output
            })
            .collect()
    }

    #[test]
    fn requestsThatFitTakeTheNextBytesOfTheBlock() {
        let seed = counting();
        let outputs = requests(&mut PseudorandomFunction::new(&seed), &[4, 4, 128, 4]);
        // `get_prf_output` of liboqs 0.16.0 for the seed 0 to 31 gives these first and last
        // requests.
        assert_eq!(outputs[0], [0x69, 0xF0, 0x7C, 0x88]);
        assert_eq!(outputs[3], [0xDC, 0xF0, 0x55, 0x71]);
        // The three first requests fill the first block of 136 bytes exactly, and the fourth
        // starts the second block.
        let expected = stream(&seed, 140);
        assert_eq!(outputs[0], expected[..4]);
        assert_eq!(outputs[1], expected[4..8]);
        assert_eq!(outputs[2], expected[8..136]);
        assert_eq!(outputs[3], expected[136..140]);
    }

    #[test]
    fn aRequestThatDoesNotFitSkipsTheRestOfTheBlock() {
        let seed = counting();
        let outputs = requests(&mut PseudorandomFunction::new(&seed), &[100, 50]);
        let expected = stream(&seed, 186);
        assert_eq!(outputs[0], expected[..100]);
        // `get_prf_output` of liboqs 0.16.0: the second request starts with byte 136 of the
        // output, so bytes 100 to 135 are never used.
        assert_eq!(outputs[1][..4], [0xDC, 0xF0, 0x55, 0x71]);
        assert_eq!(outputs[1], expected[136..186]);
    }

    #[test]
    fn eachSeedGivesItsOwnStream() {
        let first = requests(&mut PseudorandomFunction::new(&[1; 32]), &[16]);
        let second = requests(&mut PseudorandomFunction::new(&[2; 32]), &[16]);
        assert_ne!(first, second);
        assert_eq!(first[0], stream(&[1; 32], 16));
    }
}
