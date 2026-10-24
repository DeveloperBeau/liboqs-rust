use OQSNativeAES::AES128;
use OQSNativeSHA3::SHAKE128;
use alloc::vec;
use alloc::vec::Vec;

/// The function that expands the public seed into the bytes of the public map, `pk_expand` of
/// `snova_kernel.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicKeyExpansion {
    /// AES-128 in counter mode, with the seed as the key and a 12-byte zero vector, so the
    /// counter starts at zero: `AES_128_CTR` of `snova_aes.c`.
    aes128Counter,
    /// SHAKE128 in counter mode: block `i` is the first 168 bytes of SHAKE128 of the seed and
    /// `i` in 8 little-endian bytes, `snova_shake` of `snova_shake.c` in its liboqs form.
    shake128Counter,
}

impl PublicKeyExpansion {
    /// The first bytes of the expansion of a public seed.
    pub(crate) fn expanded(self, publicSeed: &[u8; 16], length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        match self {
            PublicKeyExpansion::aes128Counter => {
                AES128::new(publicSeed).fillCounterKeystream(&[0u8; 12], &mut output);
            }
            PublicKeyExpansion::shake128Counter => {
                for (block, chunk) in output.chunks_mut(SHAKE128::rate).enumerate() {
                    let mut sponge = SHAKE128::new();
                    sponge.absorb(publicSeed);
                    sponge.absorb(&(block as u64).to_le_bytes());
                    sponge.finalize().squeeze(chunk);
                }
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::PublicKeyExpansion;
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The digest of `OutputDigest` of the first bytes of each expansion of the seed 0 to
    /// 15, from `AES_128_CTR` and `snova_shake` of the oracle build of liboqs, for each
    /// length.
    const knownAnswers: [(usize, &str, &str); 8] = [
        (
            1,
            "aaa6cdd5e68f5090cec9511fe196cf6e4489ab68dd837c53f41fea4be08efd6c",
            "5a2cf27eaff297eb8f8e38e56c332d174fa6b6d635322b32ec6ff49661278ebe",
        ),
        (
            16,
            "79dcb8542cec838643d903e3a0282d2574315a4c4ae479a69a3f911a16bb62a4",
            "d525e07ece7e8f34eb7bd2024bde4d3609438c7d10d2b3ce973aefa71488d37d",
        ),
        (
            167,
            "fce3a88837922b9191d18b5bd2c9c363ea72249c74045adeeb44afefc4bd736e",
            "b302a5bce3f2813db5e486dee15bf3641bb1ecaec9012371580404db0dbe2dae",
        ),
        (
            168,
            "e8d5cdec4128692ec148a18e8193fcc2a17562a494edc7a791859bee2b4e87ed",
            "936d7be638149bf5ae8f27abb6b640aba2ae71838b5c9db17b4c8cabb6e74a83",
        ),
        (
            169,
            "a44897f179dd0cb88456e27ae88e2d82966cb9b483abce91fbeb6be04612ce06",
            "47784b9dee130946e1c611a9d4f4fb5d9510cab4e1f26af803d8b53fb3a2e502",
        ),
        (
            336,
            "74946e0d1d96e01e469b18fbb0bc33f6044e19f0c016e8129a4d70655473e925",
            "b05fbf8b380b5044e3dff8161de3bf13ff120e6bbd1b37f3d2245e2c2a77c9cd",
        ),
        (
            1000,
            "a707e75563ac4276f991444374418d8279b097a33d1ad8836d41cb2163444743",
            "93afe8a638c2b0b78fb5a2e4ede075cb784583b2f5533397994857c4a004efe6",
        ),
        (
            8000,
            "0ae577b0683a84a5a71375e7cb1d17388c8cd01b6cf7b0e3619db42af7863e70",
            "e4194c4a5df4d288ef345a833ed19015c08c4ea04c6c313f6649262595624901",
        ),
    ];

    #[test]
    fn eachExpansionGivesTheBytesOfTheCFunctionForEachLength() {
        let seed: [u8; 16] = core::array::from_fn(|index| index as u8);
        for (length, aesDigest, shakeDigest) in knownAnswers {
            let aes = PublicKeyExpansion::aes128Counter.expanded(&seed, length);
            assert_eq!(OutputDigest::of(&aes), aesDigest, "AES, {length}");
            let shake = PublicKeyExpansion::shake128Counter.expanded(&seed, length);
            assert_eq!(OutputDigest::of(&shake), shakeDigest, "SHAKE, {length}");
        }
    }

    #[test]
    fn aLongerExpansionStartsWithTheShorterOne() {
        let seed = [7u8; 16];
        for expansion in [
            PublicKeyExpansion::aes128Counter,
            PublicKeyExpansion::shake128Counter,
        ] {
            let long = expansion.expanded(&seed, 1000);
            assert_eq!(expansion.expanded(&seed, 169), long[..169]);
            assert_ne!(expansion.expanded(&[8u8; 16], 169), long[..169]);
        }
    }
}
