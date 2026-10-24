use crate::Parameters;
use crate::benesNetwork::BenesNetwork;
use crate::galoisField::GaloisField;
use alloc::vec;
use alloc::vec::Vec;

/// The Niederreiter decryption of the C code with the Berlekamp-Massey decoder, `decrypt.c`,
/// with `synd.c`, `bm.c` and `root` of `root.c`.
///
/// The decoder computes the double syndrome of the received word, the error locator, and the
/// error vector of the roots of the locator in the support. It accepts the error vector when
/// its weight is `t` and its double syndrome equals the double syndrome of the received word.
pub(crate) struct Decryption<'parameters> {
    parameters: &'parameters Parameters,
    field: GaloisField,
}

/// The outcome of a decryption: the error vector, and zero for an accepted or one for a
/// refused error vector, as `decrypt` returns it.
pub(crate) struct DecryptedError {
    /// The error vector of `n` bits.
    pub(crate) error: Vec<u8>,
    /// Zero when the error vector has weight `t` and the double syndromes are equal, else one.
    pub(crate) failure: u8,
}

impl<'parameters> Decryption<'parameters> {
    /// Makes the decryption of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Decryption {
            parameters,
            field: parameters.field(),
        }
    }

    /// The factors `1 / g(L_i)^2` of the points of the support, which `synd` computes for each
    /// point. A decryption computes two double syndromes with the same polynomial and support,
    /// so it computes the factors once.
    pub(crate) fn syndromeFactors(&self, goppaPolynomial: &[u16], support: &[u16]) -> Vec<u16> {
        let field = self.field;
        support
            .iter()
            .map(|point| {
                let value = field.evaluation(goppaPolynomial, *point);
                field.inverse(field.product(value, value))
            })
            .collect()
    }

    /// The double syndrome of a received word of `n` bits, `synd`: for `j` below `2 t`, the sum
    /// over the set bits of `L_i^j / g(L_i)^2`, from the factors of the support.
    ///
    /// The C code adds `gf_mul(e_inv, c)` for the bit `c` of each point. The term `e_inv` is
    /// always a reduced element, so the product is the term or zero, and the port masks the
    /// term with the bit.
    pub(crate) fn syndrome(&self, factors: &[u16], support: &[u16], received: &[u8]) -> Vec<u16> {
        let field = self.field;
        let mut syndrome = vec![0u16; 2 * self.parameters.errorWeight];
        for (position, (point, factor)) in support.iter().zip(factors).enumerate() {
            let bitMask =
                0u16.wrapping_sub(u16::from((received[position / 8] >> (position % 8)) & 1));
            let mut term = *factor;
            for entry in syndrome.iter_mut() {
                *entry ^= term & bitMask;
                term = field.product(term, *point);
            }
        }
        syndrome
    }

    /// The error locator of a double syndrome, `bm`: the Berlekamp-Massey algorithm with masks
    /// in place of branches, as `t + 1` coefficients from the constant term.
    pub(crate) fn errorLocator(&self, syndrome: &[u16]) -> Vec<u16> {
        let field = self.field;
        let degree = self.parameters.errorWeight;
        let mut length: u16 = 0;
        let mut connection = vec![0u16; degree + 1];
        let mut previous = vec![0u16; degree + 1];
        let mut saved = vec![0u16; degree + 1];
        let mut previousDiscrepancy: u16 = 1;
        connection[0] = 1;
        previous[1] = 1;
        for step in 0..2 * degree {
            let mut discrepancy = 0u16;
            for index in 0..=step.min(degree) {
                discrepancy ^= field.product(connection[index], syndrome[step - index]);
            }
            let isNonzero = (discrepancy.wrapping_sub(1) >> 15).wrapping_sub(1);
            let isLonger =
                ((step as u16).wrapping_sub(2 * length) >> 15).wrapping_sub(1) & isNonzero;
            saved.copy_from_slice(&connection);
            let factor = field.quotient(discrepancy, previousDiscrepancy);
            for (entry, previousEntry) in connection.iter_mut().zip(&previous) {
                *entry ^= field.product(factor, *previousEntry) & isNonzero;
            }
            length = (length & !isLonger)
                + ((step as u16).wrapping_add(1).wrapping_sub(length) & isLonger);
            for (previousEntry, savedEntry) in previous.iter_mut().zip(&saved) {
                *previousEntry = (*previousEntry & !isLonger) + (savedEntry & isLonger);
            }
            previousDiscrepancy = (previousDiscrepancy & !isLonger) + (discrepancy & isLonger);
            previous.copy_within(..degree, 1);
            previous[0] = 0;
        }
        connection.reverse();
        connection
    }

    /// The decision of `decrypt`: zero when the weight is `t` and the two double syndromes are
    /// equal, and one otherwise.
    ///
    /// The C code folds the weight difference and each 16-bit difference of the syndromes with
    /// an or, and tests the result for zero with no branch.
    pub(crate) fn failure(&self, weight: u16, syndrome: &[u16], recomputed: &[u16]) -> u8 {
        let mut check = weight ^ self.parameters.errorWeight as u16;
        for (value, recomputedValue) in syndrome.iter().zip(recomputed) {
            check |= value ^ recomputedValue;
        }
        ((check.wrapping_sub(1) >> 15) ^ 1) as u8
    }

    /// Decrypts a ciphertext with the part of the secret key after the seed and the pivots,
    /// `decrypt`: the Goppa polynomial, the control bits of the support, and the error vector.
    pub(crate) fn decrypted(&self, secretKey: &[u8], ciphertext: &[u8]) -> DecryptedError {
        let parameters = self.parameters;
        let field = self.field;
        let goppaLength = parameters.goppaPolynomialLength();
        let mut goppaPolynomial: Vec<u16> = secretKey[..goppaLength]
            .chunks_exact(2)
            .map(|pair| field.loaded(pair))
            .collect();
        goppaPolynomial.push(1);
        let controlBits = &secretKey[goppaLength..goppaLength + parameters.controlBitsLength()];
        let support = BenesNetwork::new(parameters).support(controlBits);
        let mut received = vec![0u8; parameters.errorVectorLength()];
        received[..ciphertext.len()].copy_from_slice(ciphertext);
        let factors = self.syndromeFactors(&goppaPolynomial, &support);
        let syndrome = self.syndrome(&factors, &support, &received);
        let locator = self.errorLocator(&syndrome);
        let mut error = vec![0u8; parameters.errorVectorLength()];
        let mut weight = 0u16;
        for (position, point) in support.iter().enumerate() {
            let isRoot = GaloisField::zeroMask(field.evaluation(&locator, *point)) & 1;
            error[position / 8] += (isRoot as u8) << (position % 8);
            weight += isRoot;
        }
        let recomputed = self.syndrome(&factors, &support, &error);
        let failure = self.failure(weight, &syndrome, &recomputed);
        DecryptedError { error, failure }
    }
}

#[cfg(test)]
mod tests {
    use super::Decryption;
    use crate::parameters::{allParameters, classicMcEliece348864, classicMcEliece6960119};
    use OQSNativeAlgorithmTests::{FuzzRandom, OutputDigest};

    #[test]
    fn theDecisionFoldsTheWeightAndEverySyndromeValueWithAnOr() {
        for parameters in [&classicMcEliece348864, &classicMcEliece6960119] {
            let decryption = Decryption::new(parameters);
            let weight = parameters.errorWeight as u16;
            let syndrome: Vec<u16> = (0..2 * weight).map(|value| value * 3).collect();
            assert_eq!(decryption.failure(weight, &syndrome, &syndrome), 0);
            // A weight of t - 1 or t + 1 alone.
            assert_eq!(decryption.failure(weight - 1, &syndrome, &syndrome), 1);
            assert_eq!(decryption.failure(weight + 1, &syndrome, &syndrome), 1);
            // One value of the syndrome alone, the first and the last.
            for index in [0, syndrome.len() - 1] {
                let mut changed = syndrome.clone();
                changed[index] ^= 0x1000;
                assert_eq!(
                    decryption.failure(weight, &syndrome, &changed),
                    1,
                    "{index}"
                );
            }
            // The same bit in two values: an exclusive or of the differences would cancel.
            let mut changed = syndrome.clone();
            changed[3] ^= 0x0400;
            changed[2 * weight as usize - 2] ^= 0x0400;
            assert_eq!(decryption.failure(weight, &syndrome, &changed), 1);
            // The weight difference and a value with the same bits.
            let difference = (weight - 1) ^ weight;
            let mut changed = syndrome.clone();
            changed[0] ^= difference;
            assert_eq!(decryption.failure(weight - 1, &syndrome, &changed), 1);
            // The top bit of a 16-bit value.
            let mut changed = syndrome.clone();
            changed[1] ^= 0x8000;
            assert_eq!(decryption.failure(weight, &syndrome, &changed), 1);
        }
    }

    #[test]
    fn theLocatorOfASingleErrorAtZeroIsXToTheT() {
        // The syndrome of one error at a point 0 is (1 / g(0)^2, 0, ..., 0). The algorithm
        // gives the connection polynomial 1, so the locator is x^t, written by hand.
        let parameters = &classicMcEliece348864;
        let decryption = Decryption::new(parameters);
        let mut syndrome = vec![0u16; 2 * parameters.errorWeight];
        syndrome[0] = 0x123;
        let mut expected = vec![0u16; parameters.errorWeight + 1];
        expected[parameters.errorWeight] = 1;
        assert_eq!(decryption.errorLocator(&syndrome), expected);
    }

    #[test]
    fn syndromesLocatorsAndDecryptionsGiveTheKnownAnswersOfTheCFunctions() {
        // The `OutputDigest` of the outputs of `synd`, `bm` and `decrypt` of liboqs 0.16.0 for
        // each base set, as little-endian 16-bit values, with inputs from SplitMix64: a Goppa
        // polynomial and a support of the seed 61, a received word of the seed 62, and a secret
        // key and a ciphertext of the seed 63. The decryption adds its error vector and its
        // return value.
        let expected = [
            (
                "2d656484608d8519abb4bc159aceceb7634cd3e2688fcb2a060dfb163ee99a19",
                "49afe425bf55e59794716820b3ec4bb9901a47f86a3a86158c7a052e4c7e801f",
                "c776972af868f971a885d4362cb9ee3de4202597989a582bd9f59c9296bb82c6",
            ),
            (
                "aa186a71cb75e0c94356974f73cf5529e2e4b617bd14ffe1d0e5cc92702f8061",
                "3c4a93afe210ff1dc5308386611d7ef7da4ca78b534cbdc82d14f187c64f37c6",
                "7e77b0e035d1e31830c8d10ae97da99fc3c3ed9038e93f114bd1e77b1e9c09c3",
            ),
            (
                "36cf98c0ed0fe3dad0d50a591b29928f1453081b7cf5cd555c004d9c4cf8e6ba",
                "d4523e1355791253b8a60647dd682248ff519b2bc22805bdd7ce8462bfd6927e",
                "b76ef15e11c03c5d5e600d67b945909f3a06cb5efcf69b98389a8b5d4ff14504",
            ),
            (
                "2fb5376fd6f9f6d5f7eca744f7eef7d32ef84d34ffbb346a920153ff8117abc1",
                "d864f774cf336bca03a2cdc4dc1cb6dee011776c74a68233ee7b70a8ac130286",
                "f31c759cc40435a6b7b8a1ce857fcdd4eff52afa1f90d0ec573af3b0edfcf55a",
            ),
            (
                "8af07f45022a15e25ca6c726e2d7990047a0b1add6b32c5d97f2c5b9ce9ee31b",
                "32d2ff9100046e70a60d0ae3b4d2072f4178be6fe42fd18b7b9206837a8474d9",
                "2f049416725a1e76111ff6e1252d2e9ab17d246721da829f708c438f4f89bbe7",
            ),
        ];
        for (parameters, (syndromeDigest, locatorDigest, decryptionDigest)) in
            allParameters.iter().step_by(2).zip(expected)
        {
            let name = parameters.description.name;
            let decryption = Decryption::new(parameters);
            let mask = parameters.field().mask();
            let mut words = FuzzRandom::seeded(61);
            let mut goppa: Vec<u16> = (0..parameters.errorWeight)
                .map(|_| words.nextWord() as u16 & mask)
                .collect();
            goppa.push(1);
            let support: Vec<u16> = (0..parameters.codeLength)
                .map(|_| words.nextWord() as u16 & mask)
                .collect();
            let mut words = FuzzRandom::seeded(62);
            let received: Vec<u8> = (0..parameters.errorVectorLength())
                .map(|_| words.nextWord() as u8)
                .collect();
            let factors = decryption.syndromeFactors(&goppa, &support);
            let syndrome = decryption.syndrome(&factors, &support, &received);
            let locator = decryption.errorLocator(&syndrome);
            let bytes = |values: &[u16]| -> Vec<u8> {
                values
                    .iter()
                    .flat_map(|value| value.to_le_bytes())
                    .collect()
            };
            assert_eq!(
                OutputDigest::of(&bytes(&syndrome)),
                syndromeDigest,
                "{name}"
            );
            assert_eq!(OutputDigest::of(&bytes(&locator)), locatorDigest, "{name}");
            let mut words = FuzzRandom::seeded(63);
            let secretKey: Vec<u8> = (0..parameters.description.secretKeyLength - 40)
                .map(|_| words.nextWord() as u8)
                .collect();
            let ciphertext: Vec<u8> = (0..parameters.description.ciphertextLength)
                .map(|_| words.nextWord() as u8)
                .collect();
            let decrypted = decryption.decrypted(&secretKey, &ciphertext);
            let mut output = decrypted.error.clone();
            output.push(decrypted.failure);
            assert_eq!(OutputDigest::of(&output), decryptionDigest, "{name}");
        }
    }
}
