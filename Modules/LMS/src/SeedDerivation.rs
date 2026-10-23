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
    use OQSNativeSHA2::SHA256;

    /// The identifier and the seed of the tests: the bytes 0 to 15, and 32 to 63.
    fn identifierAndSeed() -> ([u8; 16], [u8; 32]) {
        (
            core::array::from_fn(|index| index as u8),
            core::array::from_fn(|index| 32 + index as u8),
        )
    }

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
        // `OQS_LMS_NAMESPACE_hss_seed_derive` and `hss_generate_child_seed_I_value` of the C
        // oracle, for I = 0..15, SEED = 32..63 and the leaf q = 5.
        let (identifier, seed) = identifierAndSeed();
        let derivation = SeedDerivation::new(&identifier, &seed);
        let hex =
            |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
        assert_eq!(
            hex(&derivation.valueOf(5, 0)),
            "09b9bb4731fb235f52aa5ab4ce59dac47a845741c6015c61cd6dafadf7f4df07"
        );
        assert_eq!(
            hex(&derivation.valueOf(5, 264)),
            "0c61c863f5b7fdd39330246e37cf2f182e27d7ffb18111b4795eb3905d8c79b6"
        );
        assert_eq!(
            hex(&derivation.childSeed(5)),
            "bf7afd272bc066ac75aa84ede3ec2f07f06d0b67fe242069883cca9c09a33f2a"
        );
        assert_eq!(
            hex(&derivation.childIdentifier(5)),
            "5f0e0da7f543ed414a89cfbbcb2ed043"
        );
        assert_eq!(
            hex(&derivation.randomizer(5)),
            "4d700088a6b38f5554da983d187ee3ccff2d4d052c29180b38e51804d98324bb"
        );
    }
}
