use crate::bitsliced;

/// Rijndael with a 256-bit block and a 256-bit key, for ECB encryption.
///
/// AES is Rijndael with a 128-bit block. MQOM of liboqs encrypts its seeds of the levels 3 and 5
/// with this wider form, as `rijndael256_ct64_enc` of its C code does. The rounds use the
/// bitsliced S-box and the MixColumns of the AES code of this crate, two blocks at a time, so
/// they have no table lookup and no branch that depends on the key or the data.
#[derive(Clone)]
pub struct Rijndael256 {
    roundKeys: [u64; 120],
}

impl Rijndael256 {
    /// The length of a key in bytes.
    pub const keyLength: usize = 32;

    /// The length of a block in bytes.
    pub const blockLength: usize = 32;

    /// Expands a key, as `rijndael256_ct64_setkey_enc` of the MQOM code of liboqs does.
    pub fn new(key: &[u8; 32]) -> Self {
        Rijndael256 {
            roundKeys: bitsliced::rijndael256RoundKeys(key),
        }
    }

    /// Encrypts whole blocks in ECB mode, two blocks at a time.
    ///
    /// # Panics
    ///
    /// Panics when the plaintext is not a whole number of 32-byte blocks, or when the
    /// ciphertext buffer has another length.
    pub fn encryptBlocks(&self, plaintext: &[u8], ciphertext: &mut [u8]) {
        assert_eq!(
            plaintext.len() % Self::blockLength,
            0,
            "Rijndael-256 encrypts whole blocks of 32 bytes"
        );
        assert_eq!(
            plaintext.len(),
            ciphertext.len(),
            "the ciphertext buffer has the length of the plaintext"
        );
        for (input, output) in plaintext.chunks(64).zip(ciphertext.chunks_mut(64)) {
            let mut pair = [0u8; 64];
            pair[..input.len()].copy_from_slice(input);
            let encrypted = bitsliced::encryptTwoRijndael256Blocks(&pair, &self.roundKeys);
            output.copy_from_slice(&encrypted[..output.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rijndael256;

    /// The product in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, by shift and add.
    fn product(left: u8, right: u8) -> u8 {
        let (mut shifted, mut result) = (left, 0u8);
        for bit in 0..8 {
            if (right >> bit) & 1 == 1 {
                result ^= shifted;
            }
            let carry = shifted & 0x80 != 0;
            shifted <<= 1;
            if carry {
                shifted ^= 0x1B;
            }
        }
        result
    }

    /// The S-box of its definition in the Rijndael proposal: the inverse in GF(2^8), with 0 for
    /// 0, then the affine map `b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63`.
    fn substituted(value: u8) -> u8 {
        // The inverse is value^254, by square and multiply.
        let mut inverse = 1u8;
        for bit in (0..8).rev() {
            inverse = product(inverse, inverse);
            if (254 >> bit) & 1 == 1 {
                inverse = product(inverse, value);
            }
        }
        inverse
            ^ inverse.rotate_left(1)
            ^ inverse.rotate_left(2)
            ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4)
            ^ 0x63
    }

    /// Rijndael with a 256-bit block and key, byte by byte, from the Rijndael proposal: the
    /// state byte (row, column) is byte `4 column + row` of the block.
    fn definedEncryption(key: &[u8; 32], plaintext: &[u8; 32]) -> [u8; 32] {
        let mut words: Vec<[u8; 4]> = key
            .chunks_exact(4)
            .map(|chunk| chunk.try_into().expect("four bytes"))
            .collect();
        let mut roundConstant = 1u8;
        for index in 8..120 {
            let mut temporary = words[index - 1];
            if index % 8 == 0 {
                temporary.rotate_left(1);
                temporary = temporary.map(substituted);
                temporary[0] ^= roundConstant;
                roundConstant = product(roundConstant, 2);
            } else if index % 8 == 4 {
                temporary = temporary.map(substituted);
            }
            let previous = words[index - 8];
            words.push(core::array::from_fn(|byte| {
                previous[byte] ^ temporary[byte]
            }));
        }
        let roundKey = |round: usize| -> Vec<u8> { words[8 * round..8 * round + 8].concat() };
        let mut state = *plaintext;
        let addKey = |state: &mut [u8; 32], round: usize| {
            for (byte, key) in state.iter_mut().zip(roundKey(round)) {
                *byte ^= key;
            }
        };
        addKey(&mut state, 0);
        for round in 1..=14 {
            state = state.map(substituted);
            let offsets = [0, 1, 3, 4];
            let previous = state;
            for row in 0..4 {
                for column in 0..8 {
                    state[4 * column + row] = previous[4 * ((column + offsets[row]) % 8) + row];
                }
            }
            if round != 14 {
                for column in state.chunks_exact_mut(4) {
                    let [a, b, c, d] = [column[0], column[1], column[2], column[3]];
                    column[0] = product(a, 2) ^ product(b, 3) ^ c ^ d;
                    column[1] = a ^ product(b, 2) ^ product(c, 3) ^ d;
                    column[2] = a ^ b ^ product(c, 2) ^ product(d, 3);
                    column[3] = product(a, 3) ^ b ^ c ^ product(d, 2);
                }
            }
            addKey(&mut state, round);
        }
        state
    }

    /// Seeded bytes: the high bytes of a 64-bit linear congruential sequence.
    fn seededBytes<const Length: usize>(state: &mut u64) -> [u8; Length] {
        core::array::from_fn(|_| {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (*state >> 56) as u8
        })
    }

    #[test]
    fn theDefinedEncryptionGivesTheRijndaelVectorOfBrianGladman() {
        // The vector of block length 256 and key length 256 of the Rijndael vector set of
        // Brian Gladman, which the bitsliced form also meets in `tests/KnownAnswers.rs`. It
        // proves the definition above, which then checks the bitsliced form on seeded inputs.
        let key: [u8; 32] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5, 0x6a, 0x78, 0x4d, 0x90,
            0x45, 0x19, 0x0c, 0xfe,
        ];
        let plaintext: [u8; 32] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34, 0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9,
            0x8e, 0xc4, 0xe6, 0xc8,
        ];
        let expected: [u8; 32] = [
            0xa4, 0x94, 0x06, 0x11, 0x5d, 0xfb, 0x30, 0xa4, 0x04, 0x18, 0xaa, 0xfa, 0x48, 0x69,
            0xb7, 0xc6, 0xa8, 0x86, 0xff, 0x31, 0x60, 0x2a, 0x7d, 0xd1, 0x9c, 0x88, 0x9d, 0xc6,
            0x4f, 0x7e, 0x4e, 0x7a,
        ];
        assert_eq!(definedEncryption(&key, &plaintext), expected);
        assert_eq!(substituted(0x00), 0x63);
        assert_eq!(substituted(0x53), 0xED);
    }

    #[test]
    fn bitslicedEncryptionEqualsTheDefinitionOnSeededKeysAndBlocks() {
        let blockSeed = 0x5249_4A4E_4441_454Cu64;
        let mut state = blockSeed;
        for case in 0..40 {
            let key: [u8; 32] = seededBytes(&mut state);
            let cipher = Rijndael256::new(&key);
            // One, two and three blocks: an odd count encrypts its last block alone.
            let count = 1 + case % 3;
            let blocks: Vec<[u8; 32]> = (0..count).map(|_| seededBytes(&mut state)).collect();
            let plaintext = blocks.concat();
            let mut ciphertext = vec![0u8; plaintext.len()];
            cipher.encryptBlocks(&plaintext, &mut ciphertext);
            for (block, encrypted) in blocks.iter().zip(ciphertext.chunks_exact(32)) {
                assert_eq!(
                    encrypted,
                    definedEncryption(&key, block).as_slice(),
                    "case {case} of seed {blockSeed:#x}"
                );
            }
        }
    }

    #[test]
    fn anEmptyPlaintextEncryptsToNothing() {
        let cipher = Rijndael256::new(&[0u8; 32]);
        let mut ciphertext = [0u8; 0];
        cipher.encryptBlocks(&[], &mut ciphertext);
        assert_eq!(Rijndael256::keyLength, 32);
        assert_eq!(Rijndael256::blockLength, 32);
    }

    #[test]
    #[should_panic(expected = "whole blocks of 32 bytes")]
    fn aPartialBlockPanics() {
        let mut ciphertext = [0u8; 48];
        Rijndael256::new(&[0u8; 32]).encryptBlocks(&[0u8; 48], &mut ciphertext);
    }

    #[test]
    #[should_panic(expected = "the length of the plaintext")]
    fn aCiphertextBufferOfAnotherLengthPanics() {
        let mut ciphertext = [0u8; 32];
        Rijndael256::new(&[0u8; 32]).encryptBlocks(&[0u8; 64], &mut ciphertext);
    }
}
