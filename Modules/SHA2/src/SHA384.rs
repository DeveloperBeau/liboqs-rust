use crate::SHA512Core;

/// The SHA-384 hash function, which absorbs input in any number of calls.
#[derive(Clone)]
pub struct SHA384 {
    core: SHA512Core,
}

/// The initial hash value of FIPS 180-4.
const initialState: [u64; 8] = [
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
];

impl SHA384 {
    /// The length of a digest in bytes.
    pub const outputLength: usize = 48;
    /// The length of a block in bytes.
    pub const blockLength: usize = 128;

    /// Makes a hash with no input yet.
    pub fn new() -> Self {
        SHA384 {
            core: SHA512Core::new(initialState),
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.core.absorb(input);
    }

    /// Returns the digest of all absorbed input.
    pub fn finalize(self) -> [u8; 48] {
        let mut digest = [0u8; 48];
        digest.copy_from_slice(&self.core.finalize()[..48]);
        digest
    }

    /// Returns the digest of one input, as liboqs `OQS_SHA2_sha384` does.
    pub fn hash(input: &[u8]) -> [u8; 48] {
        let mut hash = Self::new();
        hash.absorb(input);
        hash.finalize()
    }
}

impl Default for SHA384 {
    fn default() -> Self {
        Self::new()
    }
}
