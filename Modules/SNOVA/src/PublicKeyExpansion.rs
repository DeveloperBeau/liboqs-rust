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
    use OQSNativeSHA3::SHA3256;

    fn lowerHex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The SHA3-256 of the first bytes of each expansion of the seed 0 to 15, from
    /// `AES_128_CTR` and `snova_shake` of the oracle build of liboqs, for each length.
    const knownAnswers: [(usize, &str, &str); 8] = [
        (
            1,
            "16890c874a9866761e8ddfe9dcc43db13e7d0be0a84aa19a8e404d81211f6b80",
            "3ad30c155d0447cd2aed572e9cf838704b5f1f22a9de7734ceb11ee83a781947",
        ),
        (
            16,
            "513567a88f5745c3659116c35fecb3f201fdea6a9ca717b3711386c11d926bad",
            "12b6a9510c62911e4081b4793f1acb65e9192d944af155d937fd78a6e4c24ca9",
        ),
        (
            167,
            "fb3c36e2762cff2b7ff7798d7c26b8c1be49b040e705c0b8db6d6e2e3b5ba00f",
            "437cf31b2a3185558810248c10622dd1078e2f4ed3a8edf0e2994617011dd061",
        ),
        (
            168,
            "313678ff7f05e34643d2849da95464bc67b89221b5ebb9b2fe2382e80c541482",
            "fd3c4dcb289d91e554dc957ab93d5d6e2aee5df585a25af4efee090415ef7c0a",
        ),
        (
            169,
            "a3ddfbda237ad39b370ca14a553e1d1b25a0988db1b7666028f04d96e5dd9b42",
            "ee8865d2a1c2d5cb23da4752165d1b5ee02b68346cf5fb9e4774dcdd865ee957",
        ),
        (
            336,
            "51fb6edac342f42d5dde99c83af35717d8e379e761dcf84e6889841e390a1c8a",
            "fab4d63b3840c603c0b0e5d3ade49478169de67cae230f6b38ef3e46f1dd1d01",
        ),
        (
            1000,
            "a4fd0c73963802e1c68486c70a7082286624cae8c76745d620a49a7c3bd049b3",
            "8719d68d0611041fb8a21316ff67e9f29081654742abac464afc25a0f0da5957",
        ),
        (
            8000,
            "31e403aa10c6201a428532af4040dd56b691f8c9df10b921bf8f243b5352c220",
            "c68cabfadfcec5f20e6f42c9a2576409330aa634f27cb5b8596f0936ca984833",
        ),
    ];

    #[test]
    fn eachExpansionGivesTheBytesOfTheCFunctionForEachLength() {
        let seed: [u8; 16] = core::array::from_fn(|index| index as u8);
        for (length, aesDigest, shakeDigest) in knownAnswers {
            let aes = PublicKeyExpansion::aes128Counter.expanded(&seed, length);
            assert_eq!(lowerHex(&SHA3256::hash(&aes)), aesDigest, "AES, {length}");
            let shake = PublicKeyExpansion::shake128Counter.expanded(&seed, length);
            assert_eq!(
                lowerHex(&SHA3256::hash(&shake)),
                shakeDigest,
                "SHAKE, {length}"
            );
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
