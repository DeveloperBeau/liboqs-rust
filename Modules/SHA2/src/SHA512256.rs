use crate::SHA512Core;

/// The SHA-512/256 hash function of FIPS 180-4, which absorbs input in any number of calls.
///
/// SHA-512/256 is SHA-512 with another initial hash value, and its digest is the first 32 bytes
/// of the final state. The SHA-2 API of liboqs has no SHA-512/256, so the type follows the
/// API of the other hashes.
#[derive(Clone)]
pub struct SHA512256 {
    core: SHA512Core,
}

/// The initial hash value of FIPS 180-4, Section 5.3.6.2.
const initialState: [u64; 8] = [
    0x22312194FC2BF72C,
    0x9F555FA3C84C64C2,
    0x2393B86B6F53B151,
    0x963877195940EABD,
    0x96283EE2A88EFFE3,
    0xBE5E1E2553863992,
    0x2B0199FC2C85B8AA,
    0x0EB72DDC81C52CA2,
];

impl SHA512256 {
    /// The length of a digest in bytes.
    pub const outputLength: usize = 32;
    /// The length of a block in bytes.
    pub const blockLength: usize = 128;

    /// Makes a hash with no input yet.
    pub fn new() -> Self {
        SHA512256 {
            core: SHA512Core::new(initialState),
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.core.absorb(input);
    }

    /// Returns the digest of all absorbed input.
    pub fn finalize(self) -> [u8; 32] {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&self.core.finalize()[..32]);
        digest
    }

    /// Returns the digest of one input.
    pub fn hash(input: &[u8]) -> [u8; 32] {
        let mut hash = Self::new();
        hash.absorb(input);
        hash.finalize()
    }
}

impl Default for SHA512256 {
    fn default() -> Self {
        Self::new()
    }
}
