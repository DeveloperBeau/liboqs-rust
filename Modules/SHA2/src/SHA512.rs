use crate::SHA512Core;

/// The SHA-512 hash function, which absorbs input in any number of calls.
#[derive(Clone)]
pub struct SHA512 {
    core: SHA512Core,
}

/// The initial hash value of FIPS 180-4.
const initialState: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

impl SHA512 {
    /// The length of a digest in bytes.
    pub const outputLength: usize = 64;
    /// The length of a block in bytes.
    pub const blockLength: usize = 128;

    /// Makes a hash with no input yet.
    pub fn new() -> Self {
        SHA512 {
            core: SHA512Core::new(initialState),
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.core.absorb(input);
    }

    /// Returns the digest of all absorbed input.
    pub fn finalize(self) -> [u8; 64] {
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&self.core.finalize()[..64]);
        digest
    }

    /// Returns the digest of one input, as liboqs `OQS_SHA2_sha512` does.
    pub fn hash(input: &[u8]) -> [u8; 64] {
        let mut hash = Self::new();
        hash.absorb(input);
        hash.finalize()
    }
}

impl Default for SHA512 {
    fn default() -> Self {
        Self::new()
    }
}
