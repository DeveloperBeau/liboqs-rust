use crate::KeccakSponge;

/// The SHA3-256 hash function, which absorbs input in any number of calls.
#[derive(Clone)]
pub struct SHA3256 {
    sponge: KeccakSponge,
}

impl SHA3256 {
    /// The length of a digest in bytes.
    pub const outputLength: usize = 32;
    /// The number of bytes that the sponge absorbs for each permutation.
    pub const rate: usize = 136;

    /// Makes a hash with no input yet.
    pub fn new() -> Self {
        SHA3256 {
            sponge: KeccakSponge::new(Self::rate),
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.sponge.absorb(input);
    }

    /// Returns the digest of all absorbed input.
    pub fn finalize(mut self) -> [u8; 32] {
        self.sponge.finalize(0x06);
        let mut digest = [0u8; 32];
        self.sponge.squeeze(&mut digest);
        digest
    }

    /// Returns the digest of one input, as liboqs `OQS_SHA3_sha3_256` does.
    pub fn hash(input: &[u8]) -> [u8; 32] {
        let mut hash = Self::new();
        hash.absorb(input);
        hash.finalize()
    }
}

impl Default for SHA3256 {
    fn default() -> Self {
        Self::new()
    }
}
