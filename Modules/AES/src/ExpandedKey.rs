// Translated from the `aes_ecb`, `aes_ctr` and `aes256_ctr_upd_blks` functions of liboqs
// `src/common/aes/aes_c.c`, which is based on BearSSL. Copyright (c) 2016 Thomas Pornin.
// MIT license, see `THIRD_PARTY_NOTICES.md`.

use crate::bitsliced;

/// The round keys of one AES key in the bitsliced form, with the number of rounds.
#[derive(Clone)]
pub struct ExpandedKey {
    words: [u64; 120],
    rounds: usize,
}

impl ExpandedKey {
    /// Expands a key of 16 or 32 bytes.
    pub fn new(key: &[u8]) -> Self {
        let rounds = 10 + (key.len() - 16) / 4;
        let mut compressed = [0u64; 30];
        bitsliced::scheduleKey(&mut compressed, key);
        let mut words = [0u64; 120];
        bitsliced::expandScheduledKey(&mut words, &compressed, rounds);
        ExpandedKey { words, rounds }
    }

    /// Encrypts up to four blocks, given as 16 little-endian words, and returns 64 bytes.
    pub fn encryptFourBlocks(&self, blockWords: &[u32; 16]) -> [u8; 64] {
        bitsliced::encryptFourBlocks(blockWords, &self.words, self.rounds)
    }

    /// Encrypts whole blocks in ECB mode, as liboqs `aes_ecb` does.
    pub fn encryptBlocks(&self, plaintext: &[u8], ciphertext: &mut [u8]) {
        assert_eq!(
            plaintext.len() % 16,
            0,
            "AES encrypts whole blocks of 16 bytes"
        );
        assert_eq!(
            plaintext.len(),
            ciphertext.len(),
            "the ciphertext buffer has the length of the plaintext"
        );
        for (input, output) in plaintext.chunks(64).zip(ciphertext.chunks_mut(64)) {
            let mut words = [0u32; 16];
            bitsliced::decodeLittleEndian(input, &mut words[..input.len() / 4]);
            let encrypted = self.encryptFourBlocks(&words);
            output.copy_from_slice(&encrypted[..output.len()]);
        }
    }

    /// Fills an output buffer with the counter-mode keystream that starts at a counter block,
    /// and returns the counter value after the last block, as liboqs `aes_ctr` and
    /// `aes256_ctr_upd_blks` do.
    pub fn fillCounterKeystream(&self, counterBlock: &[u8; 16], output: &mut [u8]) -> u32 {
        let mut words = [0u32; 16];
        bitsliced::decodeLittleEndian(&counterBlock[..12], &mut words[..3]);
        let start = u32::from_be_bytes([
            counterBlock[12],
            counterBlock[13],
            counterBlock[14],
            counterBlock[15],
        ]);
        let mut blockCount: u32 = 0;
        for chunk in output.chunks_mut(64) {
            for lane in 0..4 {
                words.copy_within(0..3, lane * 4);
                words[lane * 4 + 3] = start
                    .wrapping_add(blockCount)
                    .wrapping_add(lane as u32)
                    .swap_bytes();
            }
            let encrypted = self.encryptFourBlocks(&words);
            chunk.copy_from_slice(&encrypted[..chunk.len()]);
            blockCount = blockCount.wrapping_add(4);
        }
        start.wrapping_add((output.len() / 16) as u32)
    }
}
