use OQSNativeEntities::KEMDescription;
use core::ops::Range;

/// The parameters of one BIKE parameter set, as `bike_defs.h` and `gf2x_inv.c` of the C code
/// give them, with the liboqs facts of the set.
pub(crate) struct Parameters {
    /// The block length `r`: the number of coefficients of each polynomial.
    pub(crate) blockBits: usize,
    /// The weight `d` of each of the two secret blocks `h0` and `h1`.
    pub(crate) blockWeight: usize,
    /// The weight `t` of the error vector.
    pub(crate) errorWeight: usize,
    /// The constant term of the threshold of the decoder, scaled by `10^8`.
    pub(crate) thresholdConstant: u64,
    /// The factor of the syndrome weight in the threshold of the decoder, scaled by `10^8`.
    pub(crate) thresholdSlope: u64,
    /// The lowest threshold of the decoder.
    pub(crate) thresholdMinimum: u64,
    /// The exponent `k` of the first power `f^(2^k)` of each step of the inversion.
    pub(crate) firstPowerExponents: &'static [usize],
    /// The value `2^-k mod r` of each first power, for the permutation that computes it.
    pub(crate) firstPowerInverses: &'static [usize],
    /// The exponent `k` of the second power of each step of the inversion, or zero for a step
    /// without one.
    pub(crate) secondPowerExponents: &'static [usize],
    /// The value `2^-k mod r` of each second power.
    pub(crate) secondPowerInverses: &'static [usize],
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: KEMDescription,
}

impl Parameters {
    /// The number of iterations of the Black-Gray-Flip decoder.
    pub(crate) const decoderIterations: usize = 5;

    /// The value that the decoder adds to each counter to find the gray positions.
    pub(crate) const grayDelta: usize = 3;

    /// The length of the seed of each key pair and each encapsulation, and of a message.
    pub(crate) const seedLength: usize = 32;

    /// The length of a shared secret.
    pub(crate) const sharedSecretLength: usize = 32;

    /// The bytes of one polynomial, `R_BYTES` of the C code: `ceil(r / 8)`.
    pub(crate) const fn byteCount(blockBits: usize) -> usize {
        blockBits.div_ceil(8)
    }

    /// The length of a secret key: the two position lists of four bytes each, the blocks `h0` and
    /// `h1`, the public key and the rejection seed `sigma`.
    pub(crate) const fn secretKeyLength(blockBits: usize, blockWeight: usize) -> usize {
        8 * blockWeight + 3 * Self::byteCount(blockBits) + Self::seedLength
    }

    /// Makes the parameters of a set with the liboqs facts.
    #[allow(clippy::too_many_arguments)]
    const fn new(
        name: &'static str,
        algorithmVersion: &'static str,
        claimedNISTLevel: u8,
        blockBits: usize,
        blockWeight: usize,
        errorWeight: usize,
        threshold: (u64, u64, u64),
        firstPowers: (&'static [usize], &'static [usize]),
        secondPowers: (&'static [usize], &'static [usize]),
    ) -> Self {
        Parameters {
            blockBits,
            blockWeight,
            errorWeight,
            thresholdConstant: threshold.0,
            thresholdSlope: threshold.1,
            thresholdMinimum: threshold.2,
            firstPowerExponents: firstPowers.0,
            firstPowerInverses: firstPowers.1,
            secondPowerExponents: secondPowers.0,
            secondPowerInverses: secondPowers.1,
            description: KEMDescription {
                name,
                algorithmVersion,
                claimedNISTLevel,
                isINDCCASecure: false,
                publicKeyLength: Self::byteCount(blockBits),
                secretKeyLength: Self::secretKeyLength(blockBits, blockWeight),
                ciphertextLength: Self::byteCount(blockBits) + Self::seedLength,
                sharedSecretLength: Self::sharedSecretLength,
                keyPairSeedLength: 0,
                encapsulationSeedLength: 0,
            },
        }
    }

    /// The bytes of one polynomial, `R_BYTES`.
    pub(crate) const fn polynomialByteCount(&self) -> usize {
        Self::byteCount(self.blockBits)
    }

    /// The 64-bit words of one polynomial, `R_QWORDS`: `ceil(r / 64)`.
    pub(crate) const fn wordCount(&self) -> usize {
        self.blockBits.div_ceil(64)
    }

    /// The coefficients of the last word of a polynomial, `LAST_R_QWORD_LEAD`.
    pub(crate) const fn lastWordBits(&self) -> u32 {
        (self.blockBits % 64) as u32
    }

    /// The mask of the coefficients of the last word, `LAST_R_QWORD_MASK`.
    pub(crate) const fn lastWordMask(&self) -> u64 {
        (1u64 << self.lastWordBits()) - 1
    }

    /// The bit slices of each counter of the decoder, `SLICES`: one more than the bit length of
    /// `d`, so that a counter minus a threshold keeps its sign in the top slice.
    pub(crate) const fn sliceCount(&self) -> usize {
        Self::bitLength(self.blockWeight) + 1
    }

    /// The number of bits of a value, `LOG2_MSB` of the C code.
    pub(crate) const fn bitLength(value: usize) -> usize {
        (usize::BITS - value.leading_zeros()) as usize
    }

    /// The largest word step of a rotation of the syndrome, `R_QWORDS_HALF_LOG2`: the smallest
    /// power of two that is at least half the words of a polynomial.
    pub(crate) const fn largestRotationStep(&self) -> usize {
        (self.wordCount() / 2).next_power_of_two()
    }

    /// The bytes of the positions of the secret block `h0` or `h1` in a secret key: `d` values
    /// of 4 bytes each, `wlist` of `sk_t` in the C code.
    pub(crate) const fn positionsRange(&self, block: usize) -> Range<usize> {
        let length = 4 * self.blockWeight;
        block * length..(block + 1) * length
    }

    /// The bytes of the secret block `h0` or `h1` in a secret key, `bin` of `sk_t`.
    pub(crate) const fn secretBlockRange(&self, block: usize) -> Range<usize> {
        let start = 8 * self.blockWeight + block * self.polynomialByteCount();
        start..start + self.polynomialByteCount()
    }

    /// The bytes of the public key in a secret key, `pk` of `sk_t`.
    pub(crate) const fn publicKeyRange(&self) -> Range<usize> {
        let start = 8 * self.blockWeight + 2 * self.polynomialByteCount();
        start..start + self.polynomialByteCount()
    }

    /// The bytes of the rejection seed `sigma` at the end of a secret key.
    pub(crate) const fn sigmaRange(&self) -> Range<usize> {
        let start = 8 * self.blockWeight + 3 * self.polynomialByteCount();
        start..start + Self::seedLength
    }

    /// The threshold of the second and third steps of the first iteration of the decoder:
    /// `((D + 1) / 2) + 1` of the C code, one more than half of `d` rounded up.
    pub(crate) const fn majorityThreshold(&self) -> u8 {
        (self.blockWeight.div_ceil(2) + 1) as u8
    }
}

/// The exponents `2^(i - 1)` of the first powers of the inversion, `EXP0_K_VALS` of each level.
const firstPowerExponents: [usize; 16] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
];

/// BIKE-L1, with `r = 12323`, `d = 71` and `t = 134`.
pub(crate) const bikeL1: Parameters = Parameters::new(
    "BIKE-L1",
    "Additional - 01/27/2023",
    1,
    12323,
    71,
    134,
    (1_353_000_000, 697_220, 36),
    (
        firstPowerExponents.split_at(14).0,
        &[
            6162, 3081, 3851, 5632, 22, 484, 119, 1838, 1742, 3106, 10650, 1608, 10157, 8816,
        ],
    ),
    (
        &[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 33, 4129],
        &[0, 0, 0, 0, 0, 6162, 0, 0, 0, 0, 0, 0, 242, 5717],
    ),
);

/// BIKE-L3, with `r = 24659`, `d = 103` and `t = 199`.
pub(crate) const bikeL3: Parameters = Parameters::new(
    "BIKE-L3",
    "Additional - 01/27/2023",
    3,
    24659,
    103,
    199,
    (1_525_880_000, 526_500, 52),
    (
        firstPowerExponents.split_at(15).0,
        &[
            12330, 6165, 7706, 3564, 2711, 1139, 15053, 1258, 4388, 20524, 9538, 6393, 10486, 1715,
            6804,
        ],
    ),
    (
        &[0, 0, 0, 0, 1, 0, 17, 0, 0, 0, 0, 0, 0, 81, 8273],
        &[0, 0, 0, 0, 12330, 0, 13685, 0, 0, 0, 0, 0, 0, 23678, 19056],
    ),
);

/// BIKE-L5, with `r = 40973`, `d = 137` and `t = 264`. liboqs gives this set another date in
/// its version text than the two other sets.
pub(crate) const bikeL5: Parameters = Parameters::new(
    "BIKE-L5",
    "Additional - 01/07/2023",
    5,
    40973,
    137,
    264,
    (1_787_850_000, 402_312, 69),
    (
        &firstPowerExponents,
        &[
            20487, 30730, 28169, 9443, 13001, 12376, 8302, 6618, 38760, 21582, 1660, 10409, 14669,
            30338, 17745, 7520,
        ],
    ),
    (
        &[0, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 8203],
        &[
            0, 20487, 0, 15365, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6302, 0, 10058,
        ],
    ),
);

#[cfg(test)]
mod tests {
    use super::{Parameters, bikeL1, bikeL3, bikeL5};

    const parameterSets: [&Parameters; 3] = [&bikeL1, &bikeL3, &bikeL5];

    #[test]
    fn lengthsAreTheLengthsOfTheLiboqsHeader() {
        // `src/kem/bike/kem_bike.h` of liboqs.
        let lengths = |parameters: &Parameters| {
            let description = &parameters.description;
            (
                description.publicKeyLength,
                description.secretKeyLength,
                description.ciphertextLength,
                description.sharedSecretLength,
            )
        };
        assert_eq!(lengths(&bikeL1), (1541, 5223, 1573, 32));
        assert_eq!(lengths(&bikeL3), (3083, 10105, 3115, 32));
        assert_eq!(lengths(&bikeL5), (5122, 16494, 5154, 32));
    }

    #[test]
    fn derivedSizesAreTheSizesOfTheCDefinitions() {
        // R_BYTES, R_QWORDS, LAST_R_QWORD_LEAD, SLICES and R_QWORDS_HALF_LOG2 of the C code.
        let sizes = |parameters: &Parameters| {
            (
                parameters.polynomialByteCount(),
                parameters.wordCount(),
                parameters.lastWordBits(),
                parameters.sliceCount(),
                parameters.largestRotationStep(),
            )
        };
        assert_eq!(sizes(&bikeL1), (1541, 193, 35, 8, 128));
        assert_eq!(sizes(&bikeL3), (3083, 386, 19, 8, 256));
        assert_eq!(sizes(&bikeL5), (5122, 641, 13, 9, 512));
        assert_eq!(bikeL1.lastWordMask(), (1 << 35) - 1);
        assert_eq!(
            [
                bikeL1.majorityThreshold(),
                bikeL3.majorityThreshold(),
                bikeL5.majorityThreshold()
            ],
            [37, 53, 70]
        );
    }

    #[test]
    fn theSecretKeyIsThePositionsTheBlocksThePublicKeyAndSigmaInOrder() {
        // `sk_t` of `types.h`, packed with no padding.
        for parameters in parameterSets {
            let ranges = [
                parameters.positionsRange(0),
                parameters.positionsRange(1),
                parameters.secretBlockRange(0),
                parameters.secretBlockRange(1),
                parameters.publicKeyRange(),
                parameters.sigmaRange(),
            ];
            assert_eq!(ranges[0].start, 0);
            for pair in ranges.windows(2) {
                assert_eq!(pair[0].end, pair[1].start);
            }
            assert_eq!(ranges[5].end, parameters.description.secretKeyLength);
            assert_eq!(ranges[1].len(), 4 * parameters.blockWeight);
            assert_eq!(ranges[4].len(), parameters.description.publicKeyLength);
            assert_eq!(ranges[5].len(), 32);
        }
        assert_eq!(bikeL1.publicKeyRange(), 3650..5191);
    }

    #[test]
    fn bitLengthCountsTheBitsOfAValueAsTheCMacroDoes() {
        // LOG2_MSB of defs.h: 0 for 0, 1 for 1, 2 for 2 and 3, and so on.
        let expected = [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 3),
            (7, 3),
            (8, 4),
            (71, 7),
        ];
        for (value, length) in expected {
            assert_eq!(Parameters::bitLength(value), length, "{value}");
        }
        assert_eq!(Parameters::bitLength(128), 8);
        assert_eq!(Parameters::bitLength(255), 8);
        assert_eq!(Parameters::bitLength(256), 9);
    }

    #[test]
    fn eachInverseUndoesItsPowerOfTwoModuloR() {
        for parameters in parameterSets {
            let r = parameters.blockBits;
            let tables = [
                (
                    parameters.firstPowerExponents,
                    parameters.firstPowerInverses,
                ),
                (
                    parameters.secondPowerExponents,
                    parameters.secondPowerInverses,
                ),
            ];
            for (exponents, inverses) in tables {
                assert_eq!(exponents.len(), inverses.len());
                for (exponent, inverse) in exponents.iter().zip(inverses.iter()) {
                    if *exponent == 0 {
                        assert_eq!(*inverse, 0);
                        continue;
                    }
                    // 2^k mod r by repeated doubling, then the product with the inverse.
                    let power = (0..*exponent).fold(1usize, |value, _| value * 2 % r);
                    assert_eq!(power * inverse % r, 1, "r {r}, k {exponent}");
                }
            }
        }
    }

    #[test]
    fn theInversionTablesAreTheValuesOfTheScriptOfTheCCode() {
        // The comment of `gf2x_inv.c` gives the tables as `max_i = floor(log(r - 2, 2)) + 1`,
        // `exp0_k = [2^i]` and `exp1_k = [(r - 2) % 2^i if bit i of r - 2 is set, else 0]`.
        for parameters in parameterSets {
            let r = parameters.blockBits;
            let steps = parameters.firstPowerExponents.len();
            assert_eq!(steps, Parameters::bitLength(r - 2));
            for (index, exponent) in parameters.secondPowerExponents.iter().enumerate() {
                let expected = if (r - 2) >> index & 1 == 1 {
                    (r - 2) % (1 << index)
                } else {
                    0
                };
                assert_eq!(*exponent, expected, "r {r}, step {index}");
            }
            for (index, exponent) in parameters.firstPowerExponents.iter().enumerate() {
                assert_eq!(*exponent, 1 << index);
            }
        }
    }
}
