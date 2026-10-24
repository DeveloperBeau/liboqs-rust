/// The SHA-512 compression and padding, shared by SHA-384 and SHA-512, which differ only in
/// their initial state and in the length of their digest.
#[derive(Clone)]
pub struct SHA512Core {
    state: [u64; 8],
    block: [u8; 128],
    blockLength: usize,
    totalLength: u128,
}

/// The round constants: the first 64 bits of the fractional parts of the cube roots of the
/// first 80 primes.
const roundConstants: [u64; 80] = [
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
];

impl SHA512Core {
    /// Makes a core with no input yet and an initial state.
    pub fn new(initialState: [u64; 8]) -> Self {
        SHA512Core {
            state: initialState,
            block: [0; 128],
            blockLength: 0,
            totalLength: 0,
        }
    }

    /// Absorbs more input.
    pub fn absorb(&mut self, input: &[u8]) {
        self.totalLength = self.totalLength.wrapping_add(input.len() as u128);
        for byte in input {
            self.block[self.blockLength] = *byte;
            self.blockLength += 1;
            if self.blockLength == 128 {
                compress(&mut self.state, &self.block);
                self.blockLength = 0;
            }
        }
    }

    /// Pads the input and returns the final state as bytes, of which a digest takes a prefix.
    pub fn finalize(mut self) -> [u8; 64] {
        let bitLength = self.totalLength.wrapping_mul(8);
        self.block[self.blockLength] = 0x80;
        self.block[self.blockLength + 1..].fill(0);
        if self.blockLength >= 112 {
            compress(&mut self.state, &self.block);
            self.block = [0; 128];
        }
        self.block[112..].copy_from_slice(&bitLength.to_be_bytes());
        compress(&mut self.state, &self.block);
        let mut digest = [0u8; 64];
        for (chunk, word) in digest.chunks_exact_mut(8).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

/// The compression function: mixes one block of 128 bytes into the state.
fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut schedule = [0u64; 80];
    for (word, bytes) in schedule.iter_mut().zip(block.chunks_exact(8)) {
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        *word = u64::from_be_bytes(array);
    }
    for index in 16..80 {
        let previous15 = schedule[index - 15];
        let previous2 = schedule[index - 2];
        let sigma0 = previous15.rotate_right(1) ^ previous15.rotate_right(8) ^ (previous15 >> 7);
        let sigma1 = previous2.rotate_right(19) ^ previous2.rotate_right(61) ^ (previous2 >> 6);
        schedule[index] = schedule[index - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(sigma1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (roundConstant, word) in roundConstants.iter().zip(schedule) {
        let sum1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        // The choice of f or g by e. The forms avoid disjoint terms joined by `^` or `|`, whose
        // mutation to the other operator would give the same value.
        let choice = g ^ (e & (f ^ g));
        let temporary1 = h
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(*roundConstant)
            .wrapping_add(word);
        let sum0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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
