/// The SHA-256 hash function, which absorbs input in any number of calls.
#[derive(Clone)]
pub struct SHA256 {
    state: [u32; 8],
    block: [u8; 64],
    blockLength: usize,
    totalLength: u64,
}

/// The round constants: the first 32 bits of the fractional parts of the cube roots of the
/// first 64 primes.
const roundConstants: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

/// The initial hash value: the first 32 bits of the fractional parts of the square roots of
/// the first 8 primes.
const initialState: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

impl SHA256 {
    /// The length of a digest in bytes.
    pub const outputLength: usize = 32;
    /// The length of a block in bytes.
    pub const blockLength: usize = 64;

    /// Makes a hash with no input yet.
    pub fn new() -> Self {
        Self::withInitialState(initialState)
    }

    /// Makes a hash with no input yet that starts from another initial hash value, as SHA-224
    /// does.
    pub(crate) fn withInitialState(state: [u32; 8]) -> Self {
        SHA256 {
            state,
            block: [0; 64],
            blockLength: 0,
            totalLength: 0,
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.totalLength = self.totalLength.wrapping_add(input.len() as u64);
        for byte in input {
            self.block[self.blockLength] = *byte;
            self.blockLength += 1;
            if self.blockLength == Self::blockLength {
                compress(&mut self.state, &self.block);
                self.blockLength = 0;
            }
        }
    }

    /// Returns the digest of all absorbed input.
    pub fn finalize(mut self) -> [u8; 32] {
        let bitLength = self.totalLength.wrapping_mul(8);
        self.absorbPadding();
        let mut lengthBlock = self.block;
        lengthBlock[56..].copy_from_slice(&bitLength.to_be_bytes());
        compress(&mut self.state, &lengthBlock);
        let mut digest = [0u8; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// Returns the digest of one input, as liboqs `OQS_SHA2_sha256` does.
    pub fn hash(input: &[u8]) -> [u8; 32] {
        let mut hash = Self::new();
        hash.absorb(input);
        hash.finalize()
    }

    /// Appends the `0x80` byte and the zero bytes, so that the block has room for the length
    /// in its last 8 bytes.
    fn absorbPadding(&mut self) {
        self.block[self.blockLength] = 0x80;
        self.block[self.blockLength + 1..].fill(0);
        if self.blockLength >= 56 {
            compress(&mut self.state, &self.block);
            self.block = [0; 64];
        }
    }
}

impl Default for SHA256 {
    fn default() -> Self {
        Self::new()
    }
}

/// The compression function: mixes one block of 64 bytes into the state.
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut schedule = [0u32; 64];
    for (word, bytes) in schedule.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for index in 16..64 {
        let previous15 = schedule[index - 15];
        let previous2 = schedule[index - 2];
        let sigma0 = previous15.rotate_right(7) ^ previous15.rotate_right(18) ^ (previous15 >> 3);
        let sigma1 = previous2.rotate_right(17) ^ previous2.rotate_right(19) ^ (previous2 >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(sigma1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (roundConstant, word) in roundConstants.iter().zip(schedule) {
        let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        // The choice of f or g by e. The forms avoid disjoint terms joined by `^` or `|`, whose
        // mutation to the other operator would give the same value.
        let choice = g ^ (e & (f ^ g));
        let temporary1 = h
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(*roundConstant)
            .wrapping_add(word);
        let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        // The majority of a, b and c. The two terms never share a bit, so `+` joins them.
        let majority = (a & b) + (c & (a ^ b));
        let temporary2 = sum0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temporary1);
        d = c;
        c = b;
        b = a;
        a = temporary1.wrapping_add(temporary2);
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}
