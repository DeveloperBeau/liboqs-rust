use OQSNativeAES::{AES128, Rijndael256};
use alloc::vec;
use alloc::vec::Vec;

/// The block cipher of a parameter set with one key, which encrypts seeds of λ / 8 bytes.
///
/// For λ = 128 it is AES-128, through the AES API of liboqs as `enc_liboqs.h` calls it. For
/// λ = 192 it is Rijndael-256 with the key and the block padded with eight zero bytes and the
/// output cut to 24 bytes, and for λ = 256 it is Rijndael-256, as `enc_local.h` encrypts them.
/// The key is always a tweaked salt, which is public, and the seeds are secret.
pub(crate) enum SeedCipher {
    /// AES-128 with a 16-byte key and block.
    aes128(AES128),
    /// Rijndael-256 with a 24-byte key and block, each padded with zeros.
    truncatedRijndael256(Rijndael256),
    /// Rijndael-256 with a 32-byte key and block.
    rijndael256(Rijndael256),
}

/// The selector of the tweak of the commitments of the leaves of a tree, `SeedCommit`.
pub(crate) const commitmentTweak: u8 = 0;

/// The selector of the tweak of the levels of a seed tree, `GGMTree_Expand`.
pub(crate) const treeTweak: u8 = 2;

/// The selector of the tweak of the blocks of the PRG, `PRG`.
pub(crate) const generatorTweak: u8 = 3;

impl SeedCipher {
    /// The cipher of a key of 16, 24 or 32 bytes, the seed length of the set.
    ///
    /// # Panics
    ///
    /// Panics for a key of another length. The seed length of every set is one of the three.
    pub(crate) fn new(key: &[u8]) -> Self {
        match key.len() {
            16 => SeedCipher::aes128(AES128::new(key.try_into().expect("16 bytes"))),
            24 => {
                let mut padded = [0u8; 32];
                padded[..24].copy_from_slice(key);
                SeedCipher::truncatedRijndael256(Rijndael256::new(&padded))
            }
            32 => SeedCipher::rijndael256(Rijndael256::new(key.try_into().expect("32 bytes"))),
            length => panic!("a seed cipher has a key of 16, 24 or 32 bytes, not {length}"),
        }
    }

    /// The cipher of a salt with a tweak, as `TweakSalt` makes the key: the selector plus four
    /// times the repetition is added to byte 0, and the 16-bit index to the bytes 1 and 2.
    pub(crate) fn tweaked(salt: &[u8], selector: u8, repetition: usize, index: usize) -> Self {
        let mut key = salt.to_vec();
        // `TweakSalt` takes the repetition as a byte and the index as a 16-bit value, and
        // keeps the low byte of the sum, as the C conversions do.
        let repetition = repetition as u8;
        let index = index as u16;
        key[0] ^= (u32::from(selector) + 4 * u32::from(repetition)) as u8;
        key[1] ^= index as u8;
        key[2] ^= (index >> 8) as u8;
        Self::new(&key)
    }

    /// Encrypts seeds of the key length, one after another, as `enc_encrypt` and its forms of
    /// two, four and eight blocks do.
    pub(crate) fn encrypt(&self, seeds: &[u8], output: &mut [u8]) {
        match self {
            SeedCipher::aes128(cipher) => cipher.encryptBlocks(seeds, output),
            SeedCipher::rijndael256(cipher) => cipher.encryptBlocks(seeds, output),
            SeedCipher::truncatedRijndael256(cipher) => {
                // Each seed fills a block of its own, with eight zeros after it. The blocks
                // come from the seeds themselves, so the cipher encrypts exactly the blocks
                // that the seeds fill.
                let padded: Vec<u8> = seeds
                    .chunks_exact(24)
                    .flat_map(|seed| seed.iter().copied().chain([0u8; 8]))
                    .collect();
                let mut encrypted = vec![0u8; padded.len()];
                cipher.encryptBlocks(&padded, &mut encrypted);
                for (block, out) in encrypted.chunks_exact(32).zip(output.chunks_exact_mut(24)) {
                    out.copy_from_slice(&block[..24]);
                }
            }
        }
    }

    /// The derived seed of each seed: its encryption plus `LinOrtho` of the seed, as
    /// `SeedDerive`, `SeedCommit` and `PRG` compute it.
    pub(crate) fn derive(&self, seeds: &[u8], output: &mut [u8]) {
        self.encrypt(seeds, output);
        let seedLength = self.seedLength();
        let half = seedLength / 2;
        for (derived, seed) in output
            .chunks_exact_mut(seedLength)
            .zip(seeds.chunks_exact(seedLength))
        {
            // LinOrtho(seed) is (high + low) || low for the two halves of the seed.
            for index in 0..half {
                derived[index] ^= seed[half + index] ^ seed[index];
                derived[half + index] ^= seed[index];
            }
        }
    }

    /// The seed length of the cipher in bytes.
    fn seedLength(&self) -> usize {
        match self {
            SeedCipher::aes128(_) => 16,
            SeedCipher::truncatedRijndael256(_) => 24,
            SeedCipher::rijndael256(_) => 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SeedCipher;
    use OQSNativeAES::{AES128, Rijndael256};

    #[test]
    fn theTruncatedFormIsRijndael256OfTheZeroPaddedKeyAndBlock() {
        let key: Vec<u8> = (0..24).collect();
        let seeds: Vec<u8> = (100..148).collect();
        let mut output = vec![0u8; 48];
        SeedCipher::new(&key).encrypt(&seeds, &mut output);
        let mut paddedKey = [0u8; 32];
        paddedKey[..24].copy_from_slice(&key);
        let cipher = Rijndael256::new(&paddedKey);
        for (seed, encrypted) in seeds.chunks_exact(24).zip(output.chunks_exact(24)) {
            let mut block = [0u8; 32];
            block[..24].copy_from_slice(seed);
            let mut full = [0u8; 32];
            cipher.encryptBlocks(&block, &mut full);
            assert_eq!(encrypted, &full[..24]);
        }
    }

    #[test]
    fn theDerivedSeedAddsLinOrthoToTheEncryption() {
        // LinOrtho of the seed 0, 1, ..., 15 is (8 ^ 0, 9 ^ 1, ..., 15 ^ 7) || (0, ..., 7).
        let key = [7u8; 16];
        let seed: Vec<u8> = (0..16).collect();
        let mut encrypted = [0u8; 16];
        AES128::new(&key).encryptBlocks(&seed, &mut encrypted);
        let mut derived = [0u8; 16];
        SeedCipher::new(&key).derive(&seed, &mut derived);
        let orthomorphism: Vec<u8> = (0..8)
            .map(|index| index ^ (index + 8))
            .chain(0..8)
            .collect();
        for index in 0..16 {
            assert_eq!(derived[index], encrypted[index] ^ orthomorphism[index]);
        }
    }

    #[test]
    fn theTweakAddsTheSelectorTheRepetitionAndTheIndex() {
        // `TweakSalt` of `common.h` adds `sel + 4 e`, `j & 0xff` and `j >> 8` to the bytes 0, 1
        // and 2 with an exclusive or. Each salt byte 0x13 shares a set bit with its tweak, so
        // an or in place of an exclusive or gives another key.
        let salt = [0x13u8; 16];
        let seed = [0x33u8; 16];
        let mut tweaked = [0u8; 16];
        SeedCipher::tweaked(&salt, 3, 5, 0x0201).encrypt(&seed, &mut tweaked);
        // 0x13 ^ (3 + 4 * 5) is 0x04, 0x13 ^ 0x01 is 0x12 and 0x13 ^ 0x02 is 0x11.
        let mut key = salt;
        key[..3].copy_from_slice(&[0x04, 0x12, 0x11]);
        let mut expected = [0u8; 16];
        SeedCipher::new(&key).encrypt(&seed, &mut expected);
        assert_eq!(tweaked, expected);
    }

    #[test]
    #[should_panic(expected = "16, 24 or 32 bytes")]
    fn aKeyOfAnotherLengthPanics() {
        SeedCipher::new(&[0u8; 20]);
    }
}
