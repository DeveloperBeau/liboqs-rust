use crate::chaChaRandom::ChaChaRandom;
use crate::floatingPoint::FloatingPoint;

/// The sampler of integers along a discrete Gaussian distribution, `sampler` of `sign.c` of the
/// Falcon code of PQClean, with its ChaCha20 generator and the minimum standard deviation of a
/// degree.
///
/// A sample draws from the half-Gaussian of standard deviation `sigma0 = 1.8205`, makes it
/// bimodal with a random bit, and keeps it with the probability of the Bernoulli trial of
/// FACCT, as the C code does. Each refused candidate draws again from the same generator.
pub(crate) struct GaussianSampler {
    random: ChaChaRandom,
    sigmaMinimum: FloatingPoint,
}

/// `1 / (2 sigma0^2)`, for `sigma0 = 1.8205`.
const inverseOfTwiceSigma0Squared: FloatingPoint =
    FloatingPoint::fromBits(4_594_603_506_513_722_306);

/// `log(2)`.
const logarithmOf2: FloatingPoint = FloatingPoint::fromBits(4_604_418_534_313_441_775);

/// `1 / log(2)`.
const inverseOfLogarithmOf2: FloatingPoint = FloatingPoint::fromBits(4_609_176_140_021_203_710);

/// The cumulative table of the half-Gaussian of `gaussian0_sampler`, as 72-bit values in three
/// 24-bit limbs, the most significant limb first.
const halfGaussianTable: [[u32; 3]; 18] = [
    [10745844, 3068844, 3741698],
    [5559083, 1580863, 8248194],
    [2260429, 13669192, 2736639],
    [708981, 4421575, 10046180],
    [169348, 7122675, 4136815],
    [30538, 13063405, 7650655],
    [4132, 14505003, 7826148],
    [417, 16768101, 11363290],
    [31, 8444042, 8086568],
    [1, 12844466, 265321],
    [0, 1232676, 13644283],
    [0, 38047, 9111839],
    [0, 870, 6138264],
    [0, 14, 12545723],
    [0, 0, 3104126],
    [0, 0, 28824],
    [0, 0, 198],
    [0, 0, 1],
];

impl GaussianSampler {
    /// A sampler with a generator and the minimum standard deviation of the degree.
    pub(crate) fn new(random: ChaChaRandom, sigmaMinimum: FloatingPoint) -> Self {
        GaussianSampler {
            random,
            sigmaMinimum,
        }
    }

    /// An integer of the discrete Gaussian distribution centered on `center` with the
    /// standard deviation `1 / inverseSigma`, which lies between 1 and 2.
    pub(crate) fn sample(&mut self, center: FloatingPoint, inverseSigma: FloatingPoint) -> i32 {
        // center = s + r, with s an integer and 0 <= r < 1.
        let integerPart = center.roundedDown() as i32;
        let fraction = center - FloatingPoint::of(i64::from(integerPart));
        // 1 / (2 sigma^2) and sigma_min / sigma.
        let halfInverseVariance = inverseSigma.squared().halved();
        let scale = inverseSigma * self.sigmaMinimum;
        loop {
            // A half-Gaussian value and a random bit give z >= 1 around 1 or z <= 0 around 0.
            let halfGaussian = self.halfGaussian();
            let bit = (self.random.nextByte() & 1) as i32;
            let candidate = bit + ((bit << 1) - 1) * halfGaussian;
            // Keep z with the probability exp(-x), for
            // x = (z - r)^2 / (2 sigma^2) - (z - b)^2 / (2 sigma0^2).
            let mut exponent = (FloatingPoint::of(i64::from(candidate)) - fraction).squared()
                * halfInverseVariance;
            exponent = exponent
                - FloatingPoint::of(i64::from(halfGaussian * halfGaussian))
                    * inverseOfTwiceSigma0Squared;
            if self.isBernoulliExponentialTrue(exponent, scale) {
                return integerPart + candidate;
            }
        }
    }

    /// A nonnegative integer of the half-Gaussian of standard deviation 1.8205, from 72 random
    /// bits, as `gaussian0_sampler` does.
    fn halfGaussian(&mut self) -> i32 {
        let low = self.random.nextWord();
        let high = self.random.nextByte();
        Self::halfGaussianOfRandomBits(low, high)
    }

    /// The half-Gaussian integer of the 72 random bits `low + 2^64 high`: the count of the
    /// table values above them, compared in three limbs of 24 bits.
    fn halfGaussianOfRandomBits(low: u64, high: u32) -> i32 {
        let v0 = (low as u32) & 0xFF_FFFF;
        let v1 = ((low >> 24) as u32) & 0xFF_FFFF;
        let v2 = ((low >> 48) as u32) + (high << 16);
        // The count of the table values above the random value, with no branch.
        let mut value = 0;
        for [w2, w1, w0] in halfGaussianTable {
            let mut borrow = v0.wrapping_sub(w0) >> 31;
            borrow = v1.wrapping_sub(w1).wrapping_sub(borrow) >> 31;
            borrow = v2.wrapping_sub(w2).wrapping_sub(borrow) >> 31;
            value += borrow as i32;
        }
        value
    }

    /// True with the probability `scale * exp(-x)` for `x >= 0`, as `BerExp` does. The bytes
    /// of the comparison are drawn only while they are equal.
    fn isBernoulliExponentialTrue(&mut self, x: FloatingPoint, scale: FloatingPoint) -> bool {
        // x = s log(2) + r, with 0 <= r < log(2). A value of s above 63 saturates at 63.
        let multiple = (x * inverseOfLogarithmOf2).roundedTowardZero() as i32;
        let remainder = x - FloatingPoint::of(i64::from(multiple)) * logarithmOf2;
        let mut shift = multiple as u32;
        shift ^= (shift ^ 63) & (63u32.wrapping_sub(shift) >> 31).wrapping_neg();
        // exp(-x) = 2^-s exp(-r), scaled to 64 bits. The subtraction keeps 2^64 in range.
        let threshold = (remainder.scaledExponentialOfNegation(scale) << 1)
            .wrapping_sub(1)
            .wrapping_shr(shift);
        let mut byteShift = 64;
        loop {
            byteShift -= 8;
            let difference = self
                .random
                .nextByte()
                .wrapping_sub(((threshold >> byteShift) as u32) & 0xFF);
            if difference != 0 || byteShift == 0 {
                return difference >> 31 != 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GaussianSampler, halfGaussianTable};
    use crate::chaChaRandom::ChaChaRandom;
    use crate::floatingPoint::FloatingPoint;
    use OQSNativeAlgorithmTests::{FuzzRandom, OutputDigest};
    use OQSNativeSHA3::SHAKE256;

    /// The sampler of the known answers: the stream SHAKE256("sampler") and the minimum
    /// standard deviation of Falcon-512.
    fn sampler() -> GaussianSampler {
        let random = ChaChaRandom::seeded(&mut SHAKE256::absorbOnce(b"sampler"));
        GaussianSampler::new(random, FloatingPoint::fromBits(4_608_433_670_533_905_013))
    }

    #[test]
    fn samplesAreTheSamplesOfTheCCode() {
        // Known answers of `sampler` of the C library: 300 samples at six centers and four
        // standard deviations, the first eight and a weighted sum.
        let centers = [0.0, 0.5, -3.25, 117.75, -2047.4, 1e-9];
        let inverseSigmas = [0.55, 0.6, 0.7, 0.8];
        let mut sampler = sampler();
        let mut samples = Vec::new();
        let mut total = 0i64;
        for round in 0..50 {
            for (index, center) in centers.iter().enumerate() {
                let inverseSigma = inverseSigmas[(round + index) % 4];
                let sample = sampler.sample(
                    FloatingPoint::fromBits(f64::to_bits(*center)),
                    FloatingPoint::fromBits(f64::to_bits(inverseSigma)),
                );
                samples.push(sample);
                total += i64::from(sample) * (samples.len() % 7 + 1) as i64;
            }
        }
        assert_eq!(&samples[..8], &[0, 1, -4, 118, -2048, 0, 1, 2]);
        assert_eq!(total, -390545);
        // The half-Gaussian of the same generator, after the samples.
        let halves: Vec<i32> = (0..1000).map(|_| sampler.halfGaussian()).collect();
        assert_eq!(&halves[..10], &[0, 1, 2, 0, 2, 1, 2, 3, 0, 0]);
        let weighted: i64 = halves
            .iter()
            .enumerate()
            .map(|(index, value)| i64::from(*value) * (index % 5 + 1) as i64)
            .sum();
        assert_eq!(weighted, 3493);
    }

    #[test]
    fn halfGaussianIsTheCountOfTheTableValuesAboveTheRandomBits() {
        // `gaussian0_sampler` compares 72 random bits with each table value in three limbs of
        // 24 bits. The values next to each table value, and next to the borrows between its
        // limbs, give the count of the definition.
        let table: Vec<u128> = halfGaussianTable
            .iter()
            .map(|[w2, w1, w0]| (u128::from(*w2) << 48) + (u128::from(*w1) << 24) + u128::from(*w0))
            .collect();
        let limit = 1u128 << 72;
        let mut values = vec![0, limit - 1];
        for value in &table {
            for (difference, isAdded) in [
                (0, true),
                (1, true),
                (1, false),
                (1 << 24, true),
                (1 << 24, false),
                ((1 << 24) - 1, false),
                (1 << 48, true),
                (1 << 48, false),
                ((1 << 48) - 1, false),
            ] {
                let shifted = if isAdded {
                    value.checked_add(difference)
                } else {
                    value.checked_sub(difference)
                };
                values.extend(shifted.filter(|shifted| *shifted < limit));
            }
        }
        let mut random = FuzzRandom::seeded(0x4741_5553_5349_414E);
        values.extend((0..1000).map(|_| {
            (u128::from(random.nextWord()) + (u128::from(random.nextWord() & 0xFF) << 64)) % limit
        }));
        for value in values {
            let expected = table.iter().filter(|entry| value < **entry).count() as i32;
            let (low, high) = (value as u64, (value >> 64) as u32);
            assert_eq!(
                GaussianSampler::halfGaussianOfRandomBits(low, high),
                expected,
                "{value:#x}"
            );
        }
    }

    #[test]
    fn bernoulliTrialIsBerExpOfTheCCodeAlsoWhereTheShiftSaturates() {
        // Known answer of `BerExp` of `sign.c` for the generator of SHAKE256("BerExp"): 32
        // trials for each x and scale, with x up to 1000, so that the shift s of
        // exp(-x) = 2^-s exp(-r) reaches its limit of 63 from x = 64 log(2) on, and then the
        // next 16 bytes of the generator.
        let xs = [
            0.0, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 40.0, 44.0, 44.4, 45.0, 50.0, 60.0,
            87.0, 100.0, 200.0, 1000.0,
        ];
        let random = ChaChaRandom::seeded(&mut SHAKE256::absorbOnce(b"BerExp"));
        let mut sampler = GaussianSampler::new(random, FloatingPoint::one);
        let emulated = |value: f64| FloatingPoint::fromBits(value.to_bits());
        let mut output = Vec::new();
        for scale in [1.0, 0.7] {
            for x in xs {
                for _ in 0..32 {
                    let isTrue = sampler.isBernoulliExponentialTrue(emulated(x), emulated(scale));
                    output.push(u8::from(isTrue));
                }
            }
        }
        output.extend((0..16).map(|_| sampler.random.nextByte() as u8));
        assert_eq!(
            OutputDigest::of(&output),
            "5461d66c6a0cc7a2563c3b85fa9493a80c960709bb1a70202ec38b1caa9eaad4"
        );
    }
}
