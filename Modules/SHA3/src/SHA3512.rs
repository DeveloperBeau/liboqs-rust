use crate::KeccakSponge;

/// The SHA3-512 hash function, which absorbs input in any number of calls.
#[derive(Clone)]
pub struct SHA3512 {
    sponge: KeccakSponge,
}

impl SHA3512 {
    /// The length of a digest in bytes.
    pub const outputLength: usize = 64;
    /// The number of bytes that the sponge absorbs for each permutation.
    pub const rate: usize = 72;

    /// Makes a hash with no input yet.
    pub fn new() -> Self {
        SHA3512 {
            sponge: KeccakSponge::new(Self::rate),
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.sponge.absorb(input);
    }

    /// Returns the digest of all absorbed input.
    pub fn finalize(mut self) -> [u8; 64] {
        self.sponge.finalize(0x06);
        let mut digest = [0u8; 64];
        self.sponge.squeeze(&mut digest);
        digest
    }

    /// Returns the digest of one input, as liboqs `OQS_SHA3_sha3_512` does.
    pub fn hash(input: &[u8]) -> [u8; 64] {
        let mut hash = Self::new();
        hash.absorb(input);
        hash.finalize()
    }
}

impl Default for SHA3512 {
    fn default() -> Self {
        Self::new()
    }
}
