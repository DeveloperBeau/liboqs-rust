use OQSNativeSHA3::{SHAKE128, SHAKE256};

/// The modulus `q` of ML-KEM.
pub(crate) const modulus: u16 = 3329;

/// The number of coefficients of a polynomial.
pub(crate) const coefficientCount: usize = 256;

/// The powers `17^BitRev7(i)` of the primitive 256th root of unity, for the NTT of FIPS 203,
/// Algorithms 9 and 10.
const zetas: [u16; 128] = rootPowers(false);

/// The powers `17^(2 BitRev7(i) + 1)`, the `gamma` values of FIPS 203, Algorithm 11.
const gammas: [u16; 128] = rootPowers(true);

/// The inverse of 128 modulo `q`, the scale of the inverse NTT.
const inverseOf128: u16 = 3303;

/// The two 12-bit values of three bytes, the first in the low bits: the reading of
/// `ByteDecode_12` and of `SampleNTT` in FIPS 203.
fn twelveBitPair(triple: &[u8]) -> [u16; 2] {
    [
        u16::from(triple[0]) | (u16::from(triple[1] & 0x0F) << 8),
        u16::from(triple[1] >> 4) | (u16::from(triple[2]) << 4),
    ]
}

/// The powers of 17 that the NTT uses, at the bit-reversed 7-bit exponents.
const fn rootPowers(isGamma: bool) -> [u16; 128] {
    let mut powers = [0u16; 128];
    let mut index = 0;
    while index < 128 {
        let mut reversed = 0u32;
        let mut bit = 0;
        while bit < 7 {
            reversed = (reversed << 1) | ((index as u32 >> bit) & 1);
            bit += 1;
        }
        let exponent = if isGamma { 2 * reversed + 1 } else { reversed };
        let mut power = 1u32;
        let mut step = 0;
        while step < exponent {
            power = power * 17 % modulus as u32;
            step += 1;
        }
        powers[index] = power as u16;
        index += 1;
    }
    powers
}

/// Reduces a value below `2 q` to its canonical value below `q`, with no branch.
pub(crate) fn subtractModulusOnce(value: u16) -> u16 {
    let reduced = value.wrapping_sub(modulus);
    // The top bit of the difference is set exactly when the value was below `q`.
    let keepMask = 0u16.wrapping_sub(reduced >> 15);
    reduced.wrapping_add(modulus & keepMask)
}

/// Reduces a value below `2^32` modulo `q` with a Barrett reduction.
pub(crate) fn reduced(value: u32) -> u16 {
    // floor(2^32 / q). The estimate of the quotient is low by at most one, so the remainder
    // is below 2 q.
    let quotient = ((u64::from(value) * 1_290_167) >> 32) as u32;
    subtractModulusOnce((value - quotient * u32::from(modulus)) as u16)
}

/// The product of two canonical values modulo `q`.
pub(crate) fn product(left: u16, right: u16) -> u16 {
    reduced(u32::from(left) * u32::from(right))
}

/// The sum of two canonical values modulo `q`.
pub(crate) fn sum(left: u16, right: u16) -> u16 {
    subtractModulusOnce(left + right)
}

/// The difference of two canonical values modulo `q`.
pub(crate) fn difference(left: u16, right: u16) -> u16 {
    subtractModulusOnce(left + modulus - right)
}

/// A polynomial of ML-KEM: 256 coefficients modulo `q`, each kept canonical below `q`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Polynomial {
    pub(crate) coefficients: [u16; coefficientCount],
}

impl Polynomial {
    /// The zero polynomial.
    pub(crate) const zero: Polynomial = Polynomial {
        coefficients: [0; coefficientCount],
    };

    /// The NTT of FIPS 203, Algorithm 9, in place.
    pub(crate) fn transform(&mut self) {
        let mut zetaIndex = 1;
        let mut length = 128;
        while length >= 2 {
            for start in (0..coefficientCount).step_by(2 * length) {
                let zeta = zetas[zetaIndex];
                zetaIndex += 1;
                for index in start..start + length {
                    let twiddled = product(zeta, self.coefficients[index + length]);
                    self.coefficients[index + length] =
                        difference(self.coefficients[index], twiddled);
                    self.coefficients[index] = sum(self.coefficients[index], twiddled);
                }
            }
            length /= 2;
        }
    }

    /// The inverse NTT of FIPS 203, Algorithm 10, in place.
    pub(crate) fn inverseTransform(&mut self) {
        let mut zetaIndex = 127;
        let mut length = 2;
        while length <= 128 {
            for start in (0..coefficientCount).step_by(2 * length) {
                let zeta = zetas[zetaIndex];
                zetaIndex -= 1;
                for index in start..start + length {
                    let low = self.coefficients[index];
                    let high = self.coefficients[index + length];
                    self.coefficients[index] = sum(low, high);
                    self.coefficients[index + length] = product(zeta, difference(high, low));
                }
            }
            length *= 2;
        }
        for coefficient in self.coefficients.iter_mut() {
            *coefficient = product(*coefficient, inverseOf128);
        }
    }

    /// The product of two polynomials in the NTT domain, FIPS 203, Algorithm 11.
    pub(crate) fn transformedProduct(&self, other: &Polynomial) -> Polynomial {
        let mut result = Polynomial::zero;
        for (index, gamma) in gammas.iter().enumerate() {
            let (a0, a1) = (
                self.coefficients[2 * index],
                self.coefficients[2 * index + 1],
            );
            let (b0, b1) = (
                other.coefficients[2 * index],
                other.coefficients[2 * index + 1],
            );
            // FIPS 203, Algorithm 12.
            result.coefficients[2 * index] = sum(product(a0, b0), product(product(a1, b1), *gamma));
            result.coefficients[2 * index + 1] = sum(product(a0, b1), product(a1, b0));
        }
        result
    }

    /// The sum of two polynomials.
    pub(crate) fn plus(&self, other: &Polynomial) -> Polynomial {
        let mut result = *self;
        for (coefficient, addend) in result.coefficients.iter_mut().zip(other.coefficients) {
            *coefficient = sum(*coefficient, addend);
        }
        result
    }

    /// The difference of two polynomials.
    pub(crate) fn minus(&self, other: &Polynomial) -> Polynomial {
        let mut result = *self;
        for (coefficient, subtrahend) in result.coefficients.iter_mut().zip(other.coefficients) {
            *coefficient = difference(*coefficient, subtrahend);
        }
        result
    }

    /// The `ByteEncode_d` of FIPS 203, Algorithm 5, of the compressed or canonical
    /// coefficients: `d` bits of each coefficient, from the low bit, packed from the low bit of
    /// each byte.
    pub(crate) fn encoded(&self, bitsPerCoefficient: u32, output: &mut [u8]) {
        debug_assert_eq!(output.len(), 32 * bitsPerCoefficient as usize);
        output.fill(0);
        let mut bitPosition = 0usize;
        for coefficient in self.coefficients {
            for bit in 0..bitsPerCoefficient {
                let value = ((coefficient >> bit) & 1) as u8;
                output[bitPosition / 8] |= value << (bitPosition % 8);
                bitPosition += 1;
            }
        }
    }

    /// The `ByteDecode_d` of FIPS 203, Algorithm 6. Each coefficient takes `d` bits. With
    /// `d = 12` the value is reduced modulo `q`, and below 12 it is a value below `2^d`.
    pub(crate) fn decoded(bitsPerCoefficient: u32, input: &[u8]) -> Polynomial {
        debug_assert_eq!(input.len(), 32 * bitsPerCoefficient as usize);
        let mut polynomial = Polynomial::zero;
        let mut bitPosition = 0usize;
        for coefficient in polynomial.coefficients.iter_mut() {
            let mut value = 0u16;
            for bit in 0..bitsPerCoefficient {
                let inputBit = u16::from((input[bitPosition / 8] >> (bitPosition % 8)) & 1);
                value |= inputBit << bit;
                bitPosition += 1;
            }
            *coefficient = if bitsPerCoefficient == 12 {
                reduced(u32::from(value))
            } else {
                value
            };
        }
        polynomial
    }

    /// True when the 12-bit encoding of the bytes holds only canonical values, the modulus
    /// check of FIPS 203, Section 7.2.
    pub(crate) fn isCanonicalEncoding(input: &[u8]) -> bool {
        input
            .chunks_exact(3)
            .all(|triple| twelveBitPair(triple).iter().all(|value| *value < modulus))
    }

    /// The `Compress_d` of FIPS 203, Section 4.2.1, of each coefficient:
    /// `round(2^d / q * x) mod 2^d`.
    pub(crate) fn compressed(&self, bitsPerCoefficient: u32) -> Polynomial {
        let mut result = *self;
        let mask = (1u32 << bitsPerCoefficient) - 1;
        for coefficient in result.coefficients.iter_mut() {
            // Ties cannot occur, because q is odd, so the floor of x plus a half is the
            // floor of (2^d x + (q - 1) / 2) / q.
            let scaled = (u32::from(*coefficient) << bitsPerCoefficient) + 1664;
            *coefficient = ((scaled / u32::from(modulus)) & mask) as u16;
        }
        result
    }

    /// The `Decompress_d` of FIPS 203, Section 4.2.1, of each coefficient:
    /// `round(q / 2^d * y)`.
    pub(crate) fn decompressed(&self, bitsPerCoefficient: u32) -> Polynomial {
        let mut result = *self;
        for coefficient in result.coefficients.iter_mut() {
            let scaled = u32::from(*coefficient) * u32::from(modulus);
            *coefficient =
                ((scaled + (1 << (bitsPerCoefficient - 1))) >> bitsPerCoefficient) as u16;
        }
        result
    }

    /// The `SampleNTT` of FIPS 203, Algorithm 7: rejection sampling of 12-bit values below `q`
    /// from SHAKE128 of a 32-byte seed and two index bytes.
    pub(crate) fn sampledUniform(seed: &[u8; 32], first: u8, second: u8) -> Polynomial {
        let mut sponge = SHAKE128::new();
        sponge.absorb(seed);
        sponge.absorb(&[first, second]);
        let mut reader = sponge.finalize();
        let mut polynomial = Polynomial::zero;
        let mut count = 0;
        let mut block = [0u8; 168];
        while count < coefficientCount {
            reader.squeeze(&mut block);
            for triple in block.chunks_exact(3) {
                for candidate in twelveBitPair(triple) {
                    if candidate < modulus && count < coefficientCount {
                        polynomial.coefficients[count] = candidate;
                        count += 1;
                    }
                }
            }
        }
        polynomial
    }

    /// The `SamplePolyCBD_eta` of FIPS 203, Algorithm 8, of the bytes
    /// `PRF_eta(seed, nonce) = SHAKE256(seed || nonce, 64 eta)`.
    pub(crate) fn sampledCenteredBinomial(eta: usize, seed: &[u8; 32], nonce: u8) -> Polynomial {
        let mut bytes = [0u8; 192];
        let bytes = &mut bytes[..64 * eta];
        let mut sponge = SHAKE256::new();
        sponge.absorb(seed);
        sponge.absorb(&[nonce]);
        sponge.finalize().squeeze(bytes);
        let bitAt = |position: usize| u16::from((bytes[position / 8] >> (position % 8)) & 1);
        let mut polynomial = Polynomial::zero;
        for (index, coefficient) in polynomial.coefficients.iter_mut().enumerate() {
            let mut positive = 0u16;
            let mut negative = 0u16;
            for bit in 0..eta {
                positive += bitAt(2 * index * eta + bit);
                negative += bitAt(2 * index * eta + eta + bit);
            }
            *coefficient = difference(positive, negative);
        }
        polynomial
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Polynomial, coefficientCount, difference, gammas, modulus, product, reduced,
        subtractModulusOnce, sum, twelveBitPair, zetas,
    };

    /// A polynomial from a simple seeded sequence, the same for each test run.
    fn polynomialFrom(seed: u32) -> Polynomial {
        let mut state = seed;
        let mut polynomial = Polynomial::zero;
        for coefficient in polynomial.coefficients.iter_mut() {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            *coefficient = ((state >> 8) % u32::from(modulus)) as u16;
        }
        polynomial
    }

    /// The product of two polynomials modulo `X^256 + 1`, by the schoolbook method.
    fn schoolbookProduct(left: &Polynomial, right: &Polynomial) -> Polynomial {
        let mut wide = [0i64; 2 * coefficientCount];
        for (leftIndex, leftValue) in left.coefficients.iter().enumerate() {
            for (rightIndex, rightValue) in right.coefficients.iter().enumerate() {
                wide[leftIndex + rightIndex] += i64::from(*leftValue) * i64::from(*rightValue);
            }
        }
        let mut result = Polynomial::zero;
        for index in 0..coefficientCount {
            let value =
                (wide[index] - wide[index + coefficientCount]).rem_euclid(i64::from(modulus));
            result.coefficients[index] = value as u16;
        }
        result
    }

    #[test]
    fn rootPowersMatchTheTablesOfFIPS203() {
        // FIPS 203, Appendix A.
        assert_eq!(&zetas[..8], &[1, 1729, 2580, 3289, 2642, 630, 1897, 848]);
        assert_eq!(zetas[127], 2154);
        assert_eq!(&gammas[..4], &[17, 3312, 2761, 568]);
        assert_eq!(gammas[127], 1175);
    }

    #[test]
    fn reductionsAreExactForEveryValueOfTheirRange() {
        for value in 0..2 * modulus {
            assert_eq!(subtractModulusOnce(value), value % modulus, "{value}");
        }
        for value in (0..=u32::MAX)
            .step_by(65_521)
            .chain([u32::MAX, 0, 3328, 3329])
        {
            assert_eq!(
                u32::from(reduced(value)),
                value % u32::from(modulus),
                "{value}"
            );
        }
        for left in (0..modulus).step_by(7) {
            for right in (0..modulus).step_by(11) {
                let expected = (u32::from(left) * u32::from(right)) % u32::from(modulus);
                assert_eq!(u32::from(product(left, right)), expected);
                assert_eq!(sum(left, right), (left + right) % modulus);
                assert_eq!(difference(left, right), (left + modulus - right) % modulus);
            }
        }
    }

    #[test]
    fn transformedProductEqualsTheSchoolbookProduct() {
        for seed in 0..8 {
            let left = polynomialFrom(seed);
            let right = polynomialFrom(seed + 100);
            let mut leftTransform = left;
            let mut rightTransform = right;
            leftTransform.transform();
            rightTransform.transform();
            let mut result = leftTransform.transformedProduct(&rightTransform);
            result.inverseTransform();
            assert_eq!(result, schoolbookProduct(&left, &right), "seed {seed}");
        }
    }

    #[test]
    fn inverseTransformUndoesTheTransform() {
        for seed in 0..8 {
            let original = polynomialFrom(seed);
            let mut polynomial = original;
            polynomial.transform();
            assert_ne!(polynomial, original);
            polynomial.inverseTransform();
            assert_eq!(polynomial, original);
        }
    }

    #[test]
    fn additionAndSubtractionWorkCoefficientByCoefficient() {
        let left = polynomialFrom(1);
        let right = polynomialFrom(2);
        let total = left.plus(&right);
        for index in 0..coefficientCount {
            assert_eq!(
                total.coefficients[index],
                (left.coefficients[index] + right.coefficients[index]) % modulus
            );
        }
        assert_eq!(total.minus(&right), left);
    }

    #[test]
    fn encodingPacksTheLowBitsFirstAndDecodingReadsThemBack() {
        let mut polynomial = Polynomial::zero;
        polynomial.coefficients[0] = 0b1011;
        polynomial.coefficients[1] = 0b0110;
        polynomial.coefficients[255] = 0b1111;
        let mut bytes = [0u8; 128];
        polynomial.encoded(4, &mut bytes);
        assert_eq!(bytes[0], 0b0110_1011);
        assert_eq!(bytes[127], 0b1111_0000);
        assert!(bytes[1..127].iter().all(|byte| *byte == 0));
        assert_eq!(Polynomial::decoded(4, &bytes), polynomial);
        for bits in [1, 4, 5, 10, 11, 12] {
            let mut value = polynomialFrom(bits);
            if bits < 12 {
                for coefficient in value.coefficients.iter_mut() {
                    *coefficient &= (1 << bits) - 1;
                }
            }
            let mut encoded = vec![0u8; 32 * bits as usize];
            value.encoded(bits, &mut encoded);
            assert_eq!(Polynomial::decoded(bits, &encoded), value, "{bits} bits");
        }
    }

    #[test]
    fn twelveBitPairReadsTheLowValueFirst() {
        assert_eq!(twelveBitPair(&[0xAB, 0xCD, 0xEF]), [0xDAB, 0xEFC]);
    }

    #[test]
    fn decodingOfTwelveBitsReducesModuloQAndTheCheckSeesIt() {
        // The value 4095 in both 12-bit places of the first three bytes.
        let mut bytes = [0u8; 384];
        bytes[..3].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
        let decoded = Polynomial::decoded(12, &bytes);
        assert_eq!(&decoded.coefficients[..3], &[4095 - 3329, 4095 - 3329, 0]);
        assert!(!Polynomial::isCanonicalEncoding(&bytes));
        // 3328 in the first place and 3329 in the second.
        bytes[..3].copy_from_slice(&[0x00, 0x1D, 0xD0]);
        assert!(!Polynomial::isCanonicalEncoding(&bytes));
        bytes[..3].copy_from_slice(&[0x00, 0x0D, 0xD0]);
        assert!(Polynomial::isCanonicalEncoding(&bytes));
        bytes[..3].copy_from_slice(&[0x01, 0x0D, 0xD0]);
        assert!(!Polynomial::isCanonicalEncoding(&bytes));
        bytes[..3].copy_from_slice(&[0x00, 0x0D, 0xCF]);
        assert!(Polynomial::isCanonicalEncoding(&bytes));
    }

    #[test]
    fn compressionRoundsToTheNearestValueForEveryCoefficient() {
        for bits in [1u32, 4, 5, 10, 11] {
            for value in 0..modulus {
                let mut polynomial = Polynomial::zero;
                polynomial.coefficients[0] = value;
                let compressed = polynomial.compressed(bits).coefficients[0];
                // The exact rational rounding, with a tie impossible because q is odd.
                let exact = ((f64::from(value) * f64::from(1u32 << bits)) / f64::from(modulus)
                    + 0.5)
                    .floor() as u32
                    % (1 << bits);
                assert_eq!(u32::from(compressed), exact, "{bits} bits, {value}");
            }
            for value in 0..(1u16 << bits) {
                let mut polynomial = Polynomial::zero;
                polynomial.coefficients[0] = value;
                let decompressed = polynomial.decompressed(bits).coefficients[0];
                let exact = ((f64::from(value) * f64::from(modulus)) / f64::from(1u32 << bits)
                    + 0.5)
                    .floor() as u16;
                assert_eq!(decompressed, exact, "{bits} bits, {value}");
            }
        }
    }

    #[test]
    fn uniformSamplingGivesCanonicalValuesThatDependOnTheIndexBytes() {
        let seed = [7u8; 32];
        let first = Polynomial::sampledUniform(&seed, 0, 1);
        assert!(first.coefficients.iter().all(|value| *value < modulus));
        assert_ne!(first, Polynomial::sampledUniform(&seed, 1, 0));
        assert_eq!(first, Polynomial::sampledUniform(&seed, 0, 1));
    }

    #[test]
    fn centeredBinomialValuesStayWithinEta() {
        for eta in [2usize, 3] {
            let sample = Polynomial::sampledCenteredBinomial(eta, &[3u8; 32], 5);
            for value in sample.coefficients {
                let centered = if value > modulus / 2 {
                    i32::from(value) - i32::from(modulus)
                } else {
                    i32::from(value)
                };
                assert!(centered.unsigned_abs() as usize <= eta, "{eta}: {centered}");
            }
            assert_ne!(
                sample,
                Polynomial::sampledCenteredBinomial(eta, &[3u8; 32], 6)
            );
        }
    }
}
