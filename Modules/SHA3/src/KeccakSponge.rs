use crate::KeccakF1600;

/// The sponge construction of FIPS 202 over Keccak-f[1600], with a rate and a domain suffix.
///
/// The sponge absorbs bytes into the first `rate` bytes of the state, permutes when a block
/// is full, pads with the domain suffix and `pad10*1` at the end, and then squeezes output
/// blocks. `position` is the byte offset in the current block, for absorbing and squeezing.
#[derive(Clone)]
pub struct KeccakSponge {
    state: [u64; 25],
    rate: usize,
    position: usize,
}

impl KeccakSponge {
    /// Makes an empty sponge with a rate in bytes.
    pub fn new(rate: usize) -> Self {
        KeccakSponge {
            state: [0; 25],
            rate,
            position: 0,
        }
    }

    /// Absorbs input bytes.
    pub fn absorb(&mut self, input: &[u8]) {
        for byte in input {
            self.xorByte(self.position, *byte);
            self.position += 1;
            if self.position == self.rate {
                KeccakF1600::permute(&mut self.state);
                self.position = 0;
            }
        }
    }

    /// Pads the absorbed input with a domain suffix, such as `0x06` for SHA-3 and `0x1F` for
    /// SHAKE, and permutes, so the sponge is ready to squeeze.
    pub fn finalize(&mut self, domainSuffix: u8) {
        self.xorByte(self.position, domainSuffix);
        self.xorByte(self.rate - 1, 0x80);
        KeccakF1600::permute(&mut self.state);
        self.position = 0;
    }

    /// Squeezes output bytes from a finalized sponge.
    pub fn squeeze(&mut self, output: &mut [u8]) {
        for byte in output.iter_mut() {
            if self.position == self.rate {
                KeccakF1600::permute(&mut self.state);
                self.position = 0;
            }
            *byte = self.byte(self.position);
            self.position += 1;
        }
    }

    fn xorByte(&mut self, offset: usize, value: u8) {
        self.state[offset / 8] ^= u64::from(value) << (8 * (offset % 8));
    }

    fn byte(&self, offset: usize) -> u8 {
        (self.state[offset / 8] >> (8 * (offset % 8))) as u8
    }
}
