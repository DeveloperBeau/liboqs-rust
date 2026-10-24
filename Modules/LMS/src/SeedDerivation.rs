use crate::parameters::{hashLength, identifierLength, seedLength};
use OQSNativeSHA2::SHA256;

/// The length of the input of a derivation: I, q, j, the byte `0xFF` and the seed.
pub(crate) const derivationInputLength: usize = identifierLength + 4 + 2 + 1 + seedLength;

/// The secret values of one tree, derived from its identifier I and its seed by the method of
/// RFC 8554, Appendix A, as `hss_seed_derive` of hash-sigs computes them with the seed method
/// 2 of liboqs: `H(I || u32str(q) || u16str(j) || u8str(0xFF) || SEED)`.
///
/// The private key element j of the one-time key of leaf q is the value of (q, j). The seed and
/// the identifier of the child tree under leaf q, and the randomizer C of the signature of leaf
/// q, are the values of q with the j values `0xFFFE`, `0xFFFF` and `0xFFFD`, the low 16 bits
/// of `SEED_CHILD_SEED`, `SEED_CHILD_I` and `SEED_RANDOMIZER_INDEX` of hash-sigs.
pub(crate) struct SeedDerivation<'tree> {
    identifier: &'tree [u8; identifierLength],
    seed: &'tree [u8; seedLength],
}

/// The j value of the seed of a child tree.
const childSeedIndex: u16 = 0xFFFE;

/// The j value of the identifier of a child tree.
const childIdentifierIndex: u16 = 0xFFFF;

/// The j value of the randomizer C of a signature.
const randomizerIndex: u16 = 0xFFFD;

impl<'tree> SeedDerivation<'tree> {
    /// The derivation of a tree.
    pub(crate) fn new(
        identifier: &'tree [u8; identifierLength],
        seed: &'tree [u8; seedLength],
    ) -> Self {
        SeedDerivation { identifier, seed }
    }

    /// The input of the values of leaf q, with j = 0. `value` sets j for each value.
    pub(crate) fn input(&self, q: u32) -> [u8; derivationInputLength] {
        let mut input = [0u8; derivationInputLength];
        input[..identifierLength].copy_from_slice(self.identifier);
        input[identifierLength..identifierLength + 4].copy_from_slice(&q.to_be_bytes());
        input[identifierLength + 6] = 0xFF;
        input[identifierLength + 7..].copy_from_slice(self.seed);
        input
    }

    /// The value of an input of `input` with an index j.
    pub(crate) fn value(input: &mut [u8; derivationInputLength], j: u16) -> [u8; hashLength] {
        input[identifierLength + 4..identifierLength + 6].copy_from_slice(&j.to_be_bytes());
        SHA256::hash(input)
    }

    /// The value of leaf q and an index j.
    pub(crate) fn valueOf(&self, q: u32, j: u16) -> [u8; hashLength] {
        Self::value(&mut self.input(q), j)
    }

    /// The seed of the child tree under leaf q, `hss_generate_child_seed_I_value`.
    pub(crate) fn childSeed(&self, q: u32) -> [u8; seedLength] {
        self.valueOf(q, childSeedIndex)
    }

    /// The identifier I of the child tree under leaf q: the first 16 bytes of its value.
    pub(crate) fn childIdentifier(&self, q: u32) -> [u8; identifierLength] {
        let value = self.valueOf(q, childIdentifierIndex);
        value[..identifierLength].try_into().expect("16 bytes")
    }

    /// The randomizer C of the signature of leaf q, `lm_ots_generate_randomizer`.
    pub(crate) fn randomizer(&self, q: u32) -> [u8; hashLength] {
        self.valueOf(q, randomizerIndex)
    }
}

#[cfg(test)]
mod tests {
    use super::SeedDerivation;
    use crate::testInputs::identifierAndSeed;
    use OQSNativeAlgorithmTests::OutputDigest;
    use OQSNativeSHA2::SHA256;

    #[test]
    fn valuesHashTheLayoutOfRFC8554AppendixA() {
        let (identifier, seed) = identifierAndSeed();
        let derivation = SeedDerivation::new(&identifier, &seed);
        // I, u32str(q), u16str(j), u8str(0xFF) and SEED, written out by hand.
        let mut expected = identifier.to_vec();
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x01, 0x07, 0xFF]);
        expected.extend_from_slice(&seed);
        assert_eq!(
            derivation.valueOf(0x0102_0304, 0x0107),
            SHA256::hash(&expected)
        );
    }

    #[test]
    fn valuesGiveTheKnownAnswersOfHashSigs() {
        // `OQS_LMS_NAMESPACE_hss_seed_derive`, `hss_generate_child_seed_I_value` and
        // `lm_ots_generate_randomizer` of the C oracle, for the leaf q = 5.
        let (identifier, seed) = identifierAndSeed();
        let derivation = SeedDerivation::new(&identifier, &seed);
        assert_eq!(
            OutputDigest::of(&derivation.valueOf(5, 0)),
            "8bbfc3db36b71c2a1f448619db59a37ea1ebfc47a486d95f57b924bef0e50200"
        );
        assert_eq!(
            OutputDigest::of(&derivation.valueOf(5, 264)),
            "ee97c1e77b1047f7752ac9d90aeb9f0d47dbda472278c2acb092de006e8f78db"
        );
        assert_eq!(
            OutputDigest::of(&derivation.childSeed(5)),
            "9094d27ea43ebf1e50e6efeaff39ed604f752e08fc31a89aa6569fa342be37b0"
        );
        assert_eq!(
            OutputDigest::of(&derivation.childIdentifier(5)),
            "a617d9a5b3617474b57cf61e141f108a843d6c1fa6e15483bb956f8ebb4ed7d0"
        );
        assert_eq!(
            OutputDigest::of(&derivation.randomizer(5)),
            "9a5bdacd6600bb2233c79b2f395b970d28eadf708d62011a37782e80dae604e8"
        );
    }
}
