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
    use crate::testSupport::{SeededWords, digest};

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
        // The SHA3-256 of the outputs of `synd`, `bm` and `decrypt` of liboqs 0.16.0 for each
        // base set, as little-endian 16-bit values, with inputs from SplitMix64: a Goppa
        // polynomial and a support of the seed 61, a received word of the seed 62, and a secret
        // key and a ciphertext of the seed 63. The decryption adds its error vector and its
        // return value.
        let expected = [
            (
                "ff920cc0153d27136d58a9bb19cee6805ddcc2bddd9386f30a7381140688be84",
                "66a415180b797ab09f034f3d96acf1a5a082eb8f5fd195583fc2fe2a6e33f294",
                "b765ef2d4df9581c6f03717edbc070bf46178aa96410a29bd6601875d545084b",
            ),
            (
                "f0852fe04fd89da29ecd9a47497c0f4119fa24b115a2c3348da2f2e7ab6ab973",
                "e84ff69a973633ec2053d46044067e39b7f21ac9a50a46287bffce767cd2530d",
                "96585d709232b69150530272ec3937aebdfcc27fa382cc7fa89c109d9a0eeab6",
            ),
            (
                "6255f8d2eebd99ad4f3fa2e0dc5881329935ecfa8a4c3f1431bc1bc1fe18ac5b",
                "0a939556fe6de7c21397ef8a9abbd2fb043cdbbae191ec493ed16e17ce24c888",
                "5c52a3407a57ac29d91ba258b265aea982a5a1217c1b2ba49455016cce8ddc22",
            ),
            (
                "ed41b0ae657e0e7073e1b0a231bf0850e62cc235383573e37c0e016b96a4bf5c",
                "9de7f6d4ed17d9d691c825518a55861fb622b43cf0a7c560a29f61a795c87b7f",
                "2cff008b47f41bdef5b8fb398e2184e9022a715b61e1b35acb3d0d680bdadf3f",
            ),
            (
                "af8e3df7262cf35f70bb08a08c1d5c845168a00072942d5da7a325649db085b3",
                "a36a2119b54c6e490504b5f3b4d31e52ed4e6b3a399559ee67ac704ee09a8266",
                "872dd099f6a2f745aeea16ca9782b2c19994924ad8597664551e1dfac8ce4e3d",
            ),
        ];
        for (parameters, (syndromeDigest, locatorDigest, decryptionDigest)) in
            allParameters.iter().step_by(2).zip(expected)
        {
            let name = parameters.description.name;
            let decryption = Decryption::new(parameters);
            let mask = parameters.field().mask();
            let mut words = SeededWords::new(61);
            let mut goppa: Vec<u16> = (0..parameters.errorWeight)
                .map(|_| words.next() as u16 & mask)
                .collect();
            goppa.push(1);
            let support: Vec<u16> = (0..parameters.codeLength)
                .map(|_| words.next() as u16 & mask)
                .collect();
            let mut words = SeededWords::new(62);
            let received: Vec<u8> = (0..parameters.errorVectorLength())
                .map(|_| words.next() as u8)
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
            assert_eq!(digest(&bytes(&syndrome)), syndromeDigest, "{name}");
            assert_eq!(digest(&bytes(&locator)), locatorDigest, "{name}");
            let mut words = SeededWords::new(63);
            let secretKey: Vec<u8> = (0..parameters.description.secretKeyLength - 40)
                .map(|_| words.next() as u8)
                .collect();
            let ciphertext: Vec<u8> = (0..parameters.description.ciphertextLength)
                .map(|_| words.next() as u8)
                .collect();
            let decrypted = decryption.decrypted(&secretKey, &ciphertext);
            let mut output = decrypted.error.clone();
            output.push(decrypted.failure);
            assert_eq!(digest(&output), decryptionDigest, "{name}");
        }
    }
}
