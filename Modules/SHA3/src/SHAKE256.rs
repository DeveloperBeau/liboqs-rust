use crate::{KeccakSponge, SHAKEReader};

/// The SHAKE256 extendable-output function while it absorbs input.
///
/// `finalize` ends the input and returns the reader of the output stream.
#[derive(Clone)]
pub struct SHAKE256 {
    sponge: KeccakSponge,
}

impl SHAKE256 {
    /// The number of bytes that the sponge absorbs and squeezes for each permutation.
    pub const rate: usize = 136;

    /// Makes a function with no input yet.
    pub fn new() -> Self {
        SHAKE256 {
            sponge: KeccakSponge::new(Self::rate),
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.sponge.absorb(input);
    }

    /// Ends the input and returns the reader of the output stream.
    pub fn finalize(mut self) -> SHAKEReader {
        self.sponge.finalize(0x1F);
        SHAKEReader::new(self.sponge)
    }

    /// Absorbs one input and ends it, as `shake256_absorb_once` of liboqs does.
    pub fn absorbOnce(input: &[u8]) -> SHAKEReader {
        let mut function = Self::new();
        function.absorb(input);
        function.finalize()
    }

    /// Fills an output buffer with the output of one input, as liboqs `OQS_SHA3_shake256`
    /// does.
    pub fn hash(input: &[u8], output: &mut [u8]) {
        Self::absorbOnce(input).squeeze(output);
    }
}

impl Default for SHAKE256 {
    fn default() -> Self {
        Self::new()
    }
}
