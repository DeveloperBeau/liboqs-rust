use crate::KeccakSponge;

/// The SHA3-224 hash function of FIPS 202, which absorbs input in any number of calls.
///
/// The SHA-3 API of liboqs has no SHA3-224, so the type follows the API of the other hashes.
#[derive(Clone)]
pub struct SHA3224 {
    sponge: KeccakSponge,
}

impl SHA3224 {
    /// The length of a digest in bytes.
    pub const outputLength: usize = 28;
    /// The number of bytes that the sponge absorbs for each permutation.
    pub const rate: usize = 144;

    /// Makes a hash with no input yet.
    pub fn new() -> Self {
        SHA3224 {
            sponge: KeccakSponge::new(Self::rate),
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.sponge.absorb(input);
    }

    /// Returns the digest of all absorbed input.
    pub fn finalize(mut self) -> [u8; 28] {
        self.sponge.finalize(0x06);
        let mut digest = [0u8; 28];
        self.sponge.squeeze(&mut digest);
        digest
    }

    /// Returns the digest of one input.
    pub fn hash(input: &[u8]) -> [u8; 28] {
        let mut hash = Self::new();
        hash.absorb(input);
        hash.finalize()
    }
}

impl Default for SHA3224 {
    fn default() -> Self {
        Self::new()
    }
}
