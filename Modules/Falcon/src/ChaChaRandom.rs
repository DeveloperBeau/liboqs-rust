use OQSNativeSHA3::SHAKEReader;

/// The pseudorandom generator of the Falcon sampler, `prng` of `rng.c` of the Falcon code of
/// PQClean: ChaCha20 with a key, an IV and a block counter from a SHAKE256 stream.
///
/// A refill makes eight ChaCha20 blocks at once. The counter of each block is the exclusive or
/// of the generator counter with the last two IV words, as the C code computes it, and the
/// output words of the eight blocks interleave in the 512-byte buffer as the AVX2 code of
/// Falcon writes them. The bytes are the bytes of the C generator for the same stream.
pub(crate) struct ChaChaRandom {
    buffer: [u8; bufferLength],
    position: usize,
    /// The 32-byte key and the 16-byte IV, as twelve little-endian words.
    keyWords: [u32; 12],
    counter: u64,
}

/// The length of the buffer of eight blocks.
const bufferLength: usize = 512;

/// The four constant words of ChaCha20, "expand 32-byte k".
const constants: [u32; 4] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574];

/// The quarter round of ChaCha20 on four words of the state.
fn quarterRound(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

impl ChaChaRandom {
    /// A generator seeded with the next 56 bytes of a SHAKE256 stream, as `prng_init` does:
    /// the key and the IV, then the counter, all little-endian.
    pub(crate) fn seeded(reader: &mut SHAKEReader) -> Self {
        let mut seed = [0u8; 56];
        reader.squeeze(&mut seed);
        let mut keyWords = [0u32; 12];
        for (word, bytes) in keyWords.iter_mut().zip(seed.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().expect("4 bytes"));
        }
        let counter = u64::from_le_bytes(seed[48..].try_into().expect("8 bytes"));
        Self::withState(keyWords, counter)
    }

    /// A generator with a key, an IV and a counter, and a full buffer.
    fn withState(keyWords: [u32; 12], counter: u64) -> Self {
        let mut generator = ChaChaRandom {
            buffer: [0; bufferLength],
            position: 0,
            keyWords,
            counter,
        };
        generator.refill();
        generator
    }

    /// Fills the buffer with eight blocks and moves the counter on by eight, as
    /// `prng_refill` does.
    fn refill(&mut self) {
        for block in 0..8 {
            let counterLow = self.counter as u32;
            let counterHigh = (self.counter >> 32) as u32;
            let mut state = [0u32; 16];
            state[..4].copy_from_slice(&constants);
            state[4..].copy_from_slice(&self.keyWords);
            state[14] ^= counterLow;
            state[15] ^= counterHigh;
            for _ in 0..10 {
                quarterRound(&mut state, 0, 4, 8, 12);
                quarterRound(&mut state, 1, 5, 9, 13);
                quarterRound(&mut state, 2, 6, 10, 14);
                quarterRound(&mut state, 3, 7, 11, 15);
                quarterRound(&mut state, 0, 5, 10, 15);
                quarterRound(&mut state, 1, 6, 11, 12);
                quarterRound(&mut state, 2, 7, 8, 13);
                quarterRound(&mut state, 3, 4, 9, 14);
            }
            for (word, constant) in state[..4].iter_mut().zip(constants) {
                *word = word.wrapping_add(constant);
            }
            for (word, keyWord) in state[4..14].iter_mut().zip(&self.keyWords) {
                *word = word.wrapping_add(*keyWord);
            }
            state[14] = state[14].wrapping_add(self.keyWords[10] ^ counterLow);
            state[15] = state[15].wrapping_add(self.keyWords[11] ^ counterHigh);
            self.counter = self.counter.wrapping_add(1);
            // Word v of block u goes to bytes 4 u + 32 v.
            for (wordIndex, word) in state.iter().enumerate() {
                let start = (block << 2) + (wordIndex << 5);
                self.buffer[start..start + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        self.position = 0;
    }

    /// The next little-endian 64-bit value, as `prng_get_u64` does. When fewer than nine bytes
    /// are left, the buffer refills first and the last bytes are skipped.
    pub(crate) fn nextWord(&mut self) -> u64 {
        if self.position >= bufferLength - 9 {
            self.refill();
        }
        let start = self.position;
        self.position = start + 8;
        u64::from_le_bytes(self.buffer[start..start + 8].try_into().expect("8 bytes"))
    }

    /// The next byte, as `prng_get_u8` does. The buffer refills after its last byte.
    pub(crate) fn nextByte(&mut self) -> u32 {
        let byte = self.buffer[self.position];
        self.position += 1;
        if self.position == bufferLength {
            self.refill();
        }
        u32::from(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::ChaChaRandom;
    use OQSNativeSHA3::SHAKE256;

    #[test]
    fn firstBlockIsTheChaCha20BlockOfRFC8439() {
        // RFC 8439, Section 2.3.2: the key 00..1f, the block count 1 and the nonce
        // 000000090000004a00000000. With a zero generator counter the first block is the
        // standard block, and its word v lies at bytes 32 v to 32 v + 3.
        let mut keyWords = [0u32; 12];
        for (index, word) in keyWords[..8].iter_mut().enumerate() {
            let base = 4 * index as u8;
            *word = u32::from_le_bytes([base, base + 1, base + 2, base + 3]);
        }
        keyWords[8] = 1;
        keyWords[9] = 0x0900_0000;
        keyWords[10] = 0x4A00_0000;
        let generator = ChaChaRandom::withState(keyWords, 0);
        let expected: [u32; 16] = [
            0xE4E7_F110,
            0x1559_3BD1,
            0x1FDD_0F50,
            0xC471_20A3,
            0xC7F4_D1C7,
            0x0368_C033,
            0x9AAA_2204,
            0x4E6C_D4C3,
            0x4664_82D2,
            0x09AA_9F07,
            0x05D7_C214,
            0xA202_8BD9,
            0xD19C_12B5,
            0xB94E_16DE,
            0xE883_D0CB,
            0x4E3C_50A2,
        ];
        for (wordIndex, word) in expected.iter().enumerate() {
            let start = 32 * wordIndex;
            assert_eq!(
                &generator.buffer[start..start + 4],
                &word.to_le_bytes(),
                "word {wordIndex}"
            );
        }
    }

    #[test]
    fn outputIsTheOutputOfTheCGenerator() {
        // Known answers of `prng_init`, `prng_get_u64` and `prng_get_u8` of the C library for
        // the stream SHAKE256("Falcon"): 70 words, which cross a refill, then 600 bytes, which
        // cross another one.
        let mut generator = ChaChaRandom::seeded(&mut SHAKE256::absorbOnce(b"Falcon"));
        let words: Vec<u64> = (0..70).map(|_| generator.nextWord()).collect();
        assert_eq!(words[0], 0x276E_04CF_59A6_0045);
        assert_eq!(words[63], 0xF493_83C9_7857_6756);
        assert_eq!(words[69], 0x4B93_359D_3678_6700);
        let total = words
            .iter()
            .fold(0u64, |total, word| total.wrapping_add(*word));
        assert_eq!(total, 0xBB24_7DAF_14F9_C7BE);
        let bytes: Vec<u32> = (0..600).map(|_| generator.nextByte()).collect();
        assert_eq!(bytes.iter().sum::<u32>(), 75430);
        assert_eq!(&bytes[..4], &[14, 92, 128, 73]);
    }
}
