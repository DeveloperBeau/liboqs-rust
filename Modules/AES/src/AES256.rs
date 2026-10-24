use crate::ExpandedKey;

/// AES-256 with an expanded key, for ECB and CTR encryption.
#[derive(Clone)]
pub struct AES256 {
    expandedKey: ExpandedKey,
}

impl AES256 {
    /// The length of a key in bytes.
    pub const keyLength: usize = 32;

    /// Expands a key, as liboqs `OQS_AES256_ECB_load_schedule` does.
    pub fn new(key: &[u8; 32]) -> Self {
        AES256 {
            expandedKey: ExpandedKey::new(key),
        }
    }

    /// Encrypts whole blocks in ECB mode, as liboqs `OQS_AES256_ECB_enc_sch` does.
    ///
    /// # Panics
    ///
    /// Panics when the plaintext is not a whole number of 16-byte blocks, or when the
    /// ciphertext buffer has another length.
    pub fn encryptBlocks(&self, plaintext: &[u8], ciphertext: &mut [u8]) {
        self.expandedKey.encryptBlocks(plaintext, ciphertext);
    }

    /// Fills an output buffer with the counter-mode keystream of an initialization vector,
    /// as liboqs `OQS_AES256_CTR_inc_stream_iv` does.
    ///
    /// A 12-byte vector starts the 32-bit counter at zero. A 16-byte vector is the first
    /// counter block.
    ///
    /// # Panics
    ///
    /// Panics when the vector has neither 12 nor 16 bytes.
    pub fn fillCounterKeystream(&self, initializationVector: &[u8], output: &mut [u8]) {
        let mut counterBlock = [0u8; 16];
        match initializationVector.len() {
            12 | 16 => {
                counterBlock[..initializationVector.len()].copy_from_slice(initializationVector)
            }
            length => panic!("an AES counter-mode vector has 12 or 16 bytes, not {length}"),
        }
        self.expandedKey.fillCounterKeystream(&counterBlock, output);
    }

    /// Fills whole blocks with the counter-mode keystream that continues from a counter
    /// block, and advances the counter block past them, as liboqs
    /// `aes256_ctr_upd_blks` does.
    ///
    /// # Panics
    ///
    /// Panics when the output is not a whole number of 16-byte blocks.
    pub fn fillCounterBlocks(&self, counterBlock: &mut [u8; 16], output: &mut [u8]) {
        assert_eq!(
            output.len() % 16,
            0,
            "the output is a whole number of 16-byte blocks"
        );
        let next = self.expandedKey.fillCounterKeystream(counterBlock, output);
        counterBlock[12..].copy_from_slice(&next.to_be_bytes());
    }
}
