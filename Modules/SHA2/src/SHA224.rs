use crate::SHA256;

/// The SHA-224 hash function of FIPS 180-4, which absorbs input in any number of calls.
///
/// SHA-224 is SHA-256 with another initial hash value, and its digest is the first 28 bytes of
/// the final state. The SHA-2 API of liboqs has no SHA-224, so the type follows the API of
/// the other hashes.
#[derive(Clone)]
pub struct SHA224 {
    hash: SHA256,
}

/// The initial hash value of FIPS 180-4, Section 5.3.2.
const initialState: [u32; 8] = [
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
];

impl SHA224 {
    /// The length of a digest in bytes.
    pub const outputLength: usize = 28;
    /// The length of a block in bytes.
    pub const blockLength: usize = 64;

    /// Makes a hash with no input yet.
    pub fn new() -> Self {
        SHA224 {
            hash: SHA256::withInitialState(initialState),
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.hash.absorb(input);
    }

    /// Returns the digest of all absorbed input.
    pub fn finalize(self) -> [u8; 28] {
        let mut digest = [0u8; 28];
        digest.copy_from_slice(&self.hash.finalize()[..28]);
        digest
    }

    /// Returns the digest of one input.
    pub fn hash(input: &[u8]) -> [u8; 28] {
        let mut hash = Self::new();
        hash.absorb(input);
        hash.finalize()
    }
}

impl Default for SHA224 {
    fn default() -> Self {
        Self::new()
    }
}
