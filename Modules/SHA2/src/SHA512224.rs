use crate::SHA512Core;

/// The SHA-512/224 hash function of FIPS 180-4, which absorbs input in any number of calls.
///
/// SHA-512/224 is SHA-512 with another initial hash value, and its digest is the first 28 bytes
/// of the final state. The SHA-2 API of liboqs has no SHA-512/224, so the type follows the
/// API of the other hashes.
#[derive(Clone)]
pub struct SHA512224 {
    core: SHA512Core,
}

/// The initial hash value of FIPS 180-4, Section 5.3.6.1.
const initialState: [u64; 8] = [
    0x8C3D37C819544DA2,
    0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82,
    0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8,
    0x77E36F7304C48942,
    0x3F9D85A86A1D36C8,
    0x1112E6AD91D692A1,
];

impl SHA512224 {
    /// The length of a digest in bytes.
    pub const outputLength: usize = 28;
    /// The length of a block in bytes.
    pub const blockLength: usize = 128;

    /// Makes a hash with no input yet.
    pub fn new() -> Self {
        SHA512224 {
            core: SHA512Core::new(initialState),
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.core.absorb(input);
    }

    /// Returns the digest of all absorbed input.
    pub fn finalize(self) -> [u8; 28] {
        let mut digest = [0u8; 28];
        digest.copy_from_slice(&self.core.finalize()[..28]);
        digest
    }

    /// Returns the digest of one input.
    pub fn hash(input: &[u8]) -> [u8; 28] {
        let mut hash = Self::new();
        hash.absorb(input);
        hash.finalize()
    }
}

impl Default for SHA512224 {
    fn default() -> Self {
        Self::new()
    }
}
