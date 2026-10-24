use crate::Parameters;
use alloc::vec;
use alloc::vec::Vec;

/// The words of each factor up to which a product uses the schoolbook method.
const schoolbookWordCount: usize = 16;

/// The exponent up to which the inversion computes a power `f^(2^k)` by repeated squaring, and
/// above which it uses the permutation of the coefficients, `K_SQR_THR` of `gf2x_inv.c`.
const squaringLimit: usize = 64;

/// The ring `GF(2)[x] / (x^r - 1)` of one parameter set.
///
/// A polynomial is a list of little-endian 64-bit words, coefficient `i` in bit `i % 64` of
/// word `i / 64`, as the C code reads the bytes of `r_t` on a little-endian processor. A reduced
/// polynomial has no coefficient at `r` or above. An input from a key or a ciphertext can carry
/// coefficients from `r` up to the end of its last byte. The product takes them as the C code
/// does: it multiplies them, adds the coefficients `r` to `2 r - 1` of the exact product to the
/// coefficients below `r`, and drops every coefficient from `2 r` up.
pub(crate) struct PolynomialRing<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> PolynomialRing<'parameters> {
    /// Makes the ring of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        PolynomialRing { parameters }
    }

    /// The polynomial of little-endian bytes, at most the bytes of one polynomial.
    pub(crate) fn polynomial(&self, bytes: &[u8]) -> Vec<u64> {
        debug_assert!(bytes.len() <= self.parameters.polynomialByteCount());
        let mut words = vec![0u64; self.parameters.wordCount()];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
            let mut padded = [0u8; 8];
            padded[..chunk.len()].copy_from_slice(chunk);
            *word = u64::from_le_bytes(padded);
        }
        words
    }

    /// The bytes of a polynomial, `R_BYTES` of the C code.
    pub(crate) fn bytes(&self, polynomial: &[u64]) -> Vec<u8> {
        polynomial
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .take(self.parameters.polynomialByteCount())
            .collect()
    }

    /// The reduced product of two polynomials, `gf2x_mod_mul` of the C code.
    pub(crate) fn product(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        let wordCount = self.parameters.wordCount();
        let mut wide = vec![0u64; 2 * wordCount];
        let mut scratch = vec![0u64; scratchLength(wordCount)];
        karatsubaProduct(&mut wide, left, right, &mut scratch);
        self.reduced(&wide)
    }

    /// The inverse of a reduced polynomial, `gf2x_mod_inv` of the C code: the power
    /// `a^(2^(r - 1) - 2)` by Algorithm 2 of Drucker, Gueron and Kostic, "Fast polynomial
    /// inversion for post quantum QC-MDPC cryptography".
    pub(crate) fn inverse(&self, value: &[u64]) -> Vec<u64> {
        let parameters = self.parameters;
        let mut first = value.to_vec();
        let mut total = value.to_vec();
        for step in 1..parameters.firstPowerExponents.len() {
            let power = self.power(
                &first,
                parameters.firstPowerExponents[step - 1],
                parameters.firstPowerInverses[step - 1],
            );
            first = self.product(&power, &first);
            let exponent = parameters.secondPowerExponents[step];
            if exponent != 0 {
                let power = self.power(&first, exponent, parameters.secondPowerInverses[step]);
                total = self.product(&power, &total);
            }
        }
        self.squared(&total)
    }

    /// The power `value^(2^exponent)`, by repeated squaring up to the limit of the C code and by
    /// the permutation of the coefficients above it.
    fn power(&self, value: &[u64], exponent: usize, inverse: usize) -> Vec<u64> {
        if exponent <= squaringLimit {
            let mut result = value.to_vec();
            for _ in 0..exponent {
                result = self.squared(&result);
            }
            result
        } else {
            self.permutedPower(value, inverse)
        }
    }

    /// The reduced square of a polynomial, `gf2x_sqr_port` and then `gf2x_red_port`.
    fn squared(&self, value: &[u64]) -> Vec<u64> {
        let mut wide = vec![0u64; 2 * self.parameters.wordCount()];
        for (index, word) in value.iter().enumerate() {
            let square = carrylessProduct(*word, *word);
            wide[2 * index] = square as u64;
            wide[2 * index + 1] = (square >> 64) as u64;
        }
        self.reduced(&wide)
    }

    /// The power `value^(2^k)` from `inverse = 2^-k mod r`, `k_sqr_port` of the C code.
    /// Coefficient `i` of the result is coefficient `inverse * i mod r` of the value, by
    /// Observation 1 of the paper of the inversion.
    fn permutedPower(&self, value: &[u64], inverse: usize) -> Vec<u64> {
        let blockBits = self.parameters.blockBits;
        let mut result = vec![0u64; self.parameters.wordCount()];
        for index in 0..8 * self.parameters.polynomialByteCount() {
            let position = inverse * index % blockBits;
            let bit = (value[position / 64] >> (position % 64)) & 1;
            // Each index sets its own bit, so the sum adds each bit once.
            result[index / 64] += bit << (index % 64);
        }
        let last = result.len() - 1;
        result[last] &= self.parameters.lastWordMask();
        result
    }

    /// The reduction of a product of `2 R_QWORDS` words modulo `x^r - 1`, `gf2x_red_port`:
    /// the coefficients `r` to `2 r - 1` are added to the coefficients below `r`.
    fn reduced(&self, wide: &[u64]) -> Vec<u64> {
        let wordCount = self.parameters.wordCount();
        let lead = self.parameters.lastWordBits();
        let trail = 64 - lead;
        let mut result: Vec<u64> = (0..wordCount)
            .map(|index| {
                // The two parts of the shifted word hold different bits, so their sum is exact.
                let high =
                    (wide[index + wordCount] << trail) + (wide[index + wordCount - 1] >> lead);
                wide[index] ^ high
            })
            .collect();
        result[wordCount - 1] &= self.parameters.lastWordMask();
        result
    }
}

/// The mask of the bit positions of a double word whose residue modulo 5 is `residue`.
const fn residueClassMask(residue: u32) -> u128 {
    let mut mask = 0u128;
    let mut position = residue;
    while position < 128 {
        mask |= 1 << position;
        position += 5;
    }
    mask
}

/// The masks of the five residue classes of the bit positions modulo 5.
const residueClassMasks: [u128; 5] = [
    residueClassMask(0),
    residueClassMask(1),
    residueClassMask(2),
    residueClassMask(3),
    residueClassMask(4),
];

/// The carry-less product of two words: the product of two polynomials over GF(2) of degree
/// below 64, which `gf2x_mul_base_port` of the C code computes with a table of multiples.
///
/// The product splits each factor into the five classes of its bit positions modulo 5 and
/// multiplies the classes as integers. A column of an integer product of two classes sums at
/// most 13 bits, so its carries stay below the next column of the same class, and the low bit
/// of each column is the sum modulo 2. The product uses no branch and no table, so no memory
/// access depends on a factor.
pub(crate) fn carrylessProduct(left: u64, right: u64) -> u128 {
    // The low 64 bits of each mask are the class of the positions of a word.
    let [x0, x1, x2, x3, x4] = residueClassMasks.map(|mask| left & mask as u64);
    let [y0, y1, y2, y3, y4] = residueClassMasks.map(|mask| right & mask as u64);
    // The product of two 64-bit values fits in 128 bits, so it never wraps.
    let product = |a: u64, b: u64| u128::from(a).wrapping_mul(u128::from(b));
    // Class c of the result gathers the products of the classes i and j with i + j = c mod 5.
    let z0 =
        product(x0, y0) ^ product(x1, y4) ^ product(x2, y3) ^ product(x3, y2) ^ product(x4, y1);
    let z1 =
        product(x0, y1) ^ product(x1, y0) ^ product(x2, y4) ^ product(x3, y3) ^ product(x4, y2);
    let z2 =
        product(x0, y2) ^ product(x1, y1) ^ product(x2, y0) ^ product(x3, y4) ^ product(x4, y3);
    let z3 =
        product(x0, y3) ^ product(x1, y2) ^ product(x2, y1) ^ product(x3, y0) ^ product(x4, y4);
    let z4 =
        product(x0, y4) ^ product(x1, y3) ^ product(x2, y2) ^ product(x3, y1) ^ product(x4, y0);
    // The classes hold different bits, so the sum adds each bit once.
    (z0 & residueClassMasks[0])
        + (z1 & residueClassMasks[1])
        + (z2 & residueClassMasks[2])
        + (z3 & residueClassMasks[3])
        + (z4 & residueClassMasks[4])
}

/// The words of scratch space that `karatsubaProduct` needs for factors of `wordCount` words.
fn scratchLength(wordCount: usize) -> usize {
    if wordCount <= schoolbookWordCount {
        return 0;
    }
    let highCount = wordCount - wordCount / 2;
    4 * highCount + scratchLength(highCount)
}

/// Writes the exact product of two polynomials of the same number of words into twice that
/// number of words, by the method of Karatsuba down to a schoolbook product of a few words.
fn karatsubaProduct(output: &mut [u64], left: &[u64], right: &[u64], scratch: &mut [u64]) {
    let wordCount = left.len();
    debug_assert_eq!(right.len(), wordCount);
    debug_assert_eq!(output.len(), 2 * wordCount);
    if wordCount <= schoolbookWordCount {
        output.fill(0);
        for (leftIndex, leftWord) in left.iter().enumerate() {
            for (rightIndex, rightWord) in right.iter().enumerate() {
                let wide = carrylessProduct(*leftWord, *rightWord);
                output[leftIndex + rightIndex] ^= wide as u64;
                output[leftIndex + rightIndex + 1] ^= (wide >> 64) as u64;
            }
        }
        return;
    }
    let lowCount = wordCount / 2;
    let highCount = wordCount - lowCount;
    let (leftLow, leftHigh) = left.split_at(lowCount);
    let (rightLow, rightHigh) = right.split_at(lowCount);
    let (sums, rest) = scratch.split_at_mut(2 * highCount);
    let (leftSum, rightSum) = sums.split_at_mut(highCount);
    let (middle, deeper) = rest.split_at_mut(2 * highCount);
    leftSum.copy_from_slice(leftHigh);
    rightSum.copy_from_slice(rightHigh);
    for (sum, low) in leftSum.iter_mut().zip(leftLow) {
        *sum ^= low;
    }
    for (sum, low) in rightSum.iter_mut().zip(rightLow) {
        *sum ^= low;
    }
    let (lowProduct, highProduct) = output.split_at_mut(2 * lowCount);
    karatsubaProduct(lowProduct, leftLow, rightLow, deeper);
    karatsubaProduct(highProduct, leftHigh, rightHigh, deeper);
    karatsubaProduct(middle, leftSum, rightSum, deeper);
    // The middle term is the product of the sums minus the low and the high product.
    for (word, low) in middle.iter_mut().zip(lowProduct.iter()) {
        *word ^= low;
    }
    for (word, high) in middle.iter_mut().zip(highProduct.iter()) {
        *word ^= high;
    }
    for (word, term) in output[lowCount..].iter_mut().zip(middle.iter()) {
        *word ^= term;
    }
}

#[cfg(test)]
mod tests {
    use super::{PolynomialRing, carrylessProduct, karatsubaProduct, scratchLength};
    use crate::parameters::{Parameters, bikeL1, bikeL3, bikeL5};
    use crate::sampler::Sampler;
    use crate::testSupport::{SeededWords, digest, seededPolynomial};

    const parameterSets: [&Parameters; 3] = [&bikeL1, &bikeL3, &bikeL5];

    /// The carry-less product by its definition: the sum of the copies of one factor, shifted
    /// by the position of each set bit of the other.
    fn bitSerialProduct(left: u64, right: u64) -> u128 {
        (0..64)
            .filter(|bit| left >> bit & 1 == 1)
            .fold(0u128, |sum, bit| sum ^ (u128::from(right) << bit))
    }

    /// The exact product of two polynomials of words by the schoolbook method.
    fn schoolbookProduct(left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut output = vec![0u64; left.len() + right.len()];
        for (leftIndex, leftWord) in left.iter().enumerate() {
            for (rightIndex, rightWord) in right.iter().enumerate() {
                let wide = bitSerialProduct(*leftWord, *rightWord);
                output[leftIndex + rightIndex] ^= wide as u64;
                output[leftIndex + rightIndex + 1] ^= (wide >> 64) as u64;
            }
        }
        output
    }

    fn bitAt(words: &[u64], position: usize) -> u64 {
        words[position / 64] >> (position % 64) & 1
    }

    #[test]
    fn carrylessProductGivesTheBaseProductsOfTheCCode() {
        // `gf2x_mul_base_port` of liboqs 0.16.0: the factors, the low word and the high word.
        let expected: [(u64, u64, u64, u64); 5] = [
            (
                u64::MAX,
                u64::MAX,
                0x5555_5555_5555_5555,
                0x5555_5555_5555_5555,
            ),
            (1 << 63, 1 << 63, 0, 0x4000_0000_0000_0000),
            (
                0x0123_4567_89AB_CDEF,
                0xFEDC_BA98_7654_3210,
                0x40A0_7898_28C8_10F0,
                0x00E0_38D8_6888_50B0,
            ),
            (1, 0xDEAD_BEEF_CAFE_F00D, 0xDEAD_BEEF_CAFE_F00D, 0),
            (
                0xE000_0000_0000_0007,
                0xE000_0000_0000_0007,
                0x15,
                0x5400_0000_0000_0000,
            ),
        ];
        for (left, right, low, high) in expected {
            let product = carrylessProduct(left, right);
            assert_eq!(
                (product as u64, (product >> 64) as u64),
                (low, high),
                "{left:#x} {right:#x}"
            );
        }
    }

    #[test]
    fn carrylessProductEqualsTheBitSerialProduct() {
        let mut words = SeededWords::new(0xC1);
        for _ in 0..20_000 {
            let (left, right) = (words.next(), words.next());
            assert_eq!(
                carrylessProduct(left, right),
                bitSerialProduct(left, right),
                "{left:#x} {right:#x}"
            );
        }
        // Dense factors give each column of each class its largest count of terms.
        let dense = [
            u64::MAX,
            u64::MAX - 1,
            u64::MAX >> 1,
            0x8421_0842_1084_2108,
            1,
            0,
        ];
        for left in dense {
            for right in dense {
                assert_eq!(carrylessProduct(left, right), bitSerialProduct(left, right));
            }
        }
    }

    #[test]
    fn karatsubaProductEqualsTheSchoolbookProductForEverySplit() {
        let mut words = SeededWords::new(0xC2);
        for wordCount in (1..=70).chain([129, 193, 386]) {
            let left = words.words(wordCount);
            let right = words.words(wordCount);
            let mut output = vec![0u64; 2 * wordCount];
            let mut scratch = vec![0u64; scratchLength(wordCount)];
            karatsubaProduct(&mut output, &left, &right, &mut scratch);
            assert_eq!(
                output,
                schoolbookProduct(&left, &right),
                "{wordCount} words"
            );
        }
    }

    #[test]
    fn productGivesTheProductsOfTheCCode() {
        // The SHA3-256 of the bytes of `gf2x_mod_mul` of liboqs 0.16.0 for the seeded reduced
        // polynomials of the seeds 1 and 2.
        let expected = [
            "ce08c04ba3714a5b7121e12beca9ccf6ec073be0197b96d192fda2c9cfb8fcdd",
            "5d423c81c7c2dbd9ae0e4488a8b5a6124250b64f68f0ebe0fa8a2d93fe327f7c",
            "84847963fd087bf3114cc010d8503806dc7096f63074134f0484fcd89272d7ca",
        ];
        for (parameters, expected) in parameterSets.into_iter().zip(expected) {
            let ring = PolynomialRing::new(parameters);
            let product = ring.product(
                &seededPolynomial(parameters, 1, true),
                &seededPolynomial(parameters, 2, true),
            );
            assert_eq!(
                digest(&ring.bytes(&product)),
                expected,
                "{}",
                parameters.description.name
            );
            assert_eq!(product[product.len() - 1] & !parameters.lastWordMask(), 0);
        }
    }

    #[test]
    fn productOfFactorsWithCoefficientsFromRUpDropsTheExactProductFromTwoR() {
        // `gf2x_mod_mul` of liboqs 0.16.0 for the seeded polynomials of the seeds 3 and 4 with
        // every bit of their last byte set, as a key or a ciphertext can give them.
        let expected = [
            "69b3e85d84843a173bae48d8ccef103f39456d5a42354470d0ad4b5fe48ca558",
            "46acc1af0469d8bc0c5a5bd7157c5fa82b33105c4aafbf7e0a4d1ee276e815ee",
            "74eca67a1bea3540b3b8ce2c27c80aa43d068c3f9e3d2e01efd9c388102a5089",
        ];
        for (parameters, expected) in parameterSets.into_iter().zip(expected) {
            let ring = PolynomialRing::new(parameters);
            let lastByte = parameters.polynomialByteCount() - 1;
            let withFullLastByte = |seed: u64| {
                let mut bytes = ring.bytes(&seededPolynomial(parameters, seed, false));
                bytes[lastByte] = 0xFF;
                ring.polynomial(&bytes)
            };
            let left = withFullLastByte(3);
            let right = withFullLastByte(4);
            let product = ring.product(&left, &right);
            assert_eq!(digest(&ring.bytes(&product)), expected);
            // Coefficient i is the sum of coefficients i and i + r of the exact product, which
            // has coefficients from 2 r up that the reduction drops.
            let exact = schoolbookProduct(&left, &right);
            let r = parameters.blockBits;
            assert!((2 * r..exact.len() * 64).any(|position| bitAt(&exact, position) == 1));
            for position in 0..r {
                assert_eq!(
                    bitAt(&product, position),
                    bitAt(&exact, position) ^ bitAt(&exact, position + r),
                    "{} coefficient {position}",
                    parameters.description.name
                );
            }
        }
    }

    #[test]
    fn squareIsTheProductOfAPolynomialWithItself() {
        for parameters in parameterSets {
            let ring = PolynomialRing::new(parameters);
            let value = seededPolynomial(parameters, 7, true);
            assert_eq!(ring.squared(&value), ring.product(&value, &value));
        }
    }

    #[test]
    fn permutedPowerGivesThePowerOfTheCCodeAndOfRepeatedSquaring() {
        // `k_sqr_port` of liboqs 0.16.0 with `l = 2^-128 mod r` for the seeded reduced
        // polynomial of the seed 5.
        let expected = [
            (
                1838,
                "f44b46aee83a94da3e66bc090a42cdd9e33942f2a993bbbb38aea7df6cdedaf7",
            ),
            (
                1258,
                "a2cdfaf8e40a930558683f6b4a9554d520a60cdb002a6f981c8b5302da5139fe",
            ),
            (
                6618,
                "e9b1d111c9dfb178a7bb317c75169029d20c7e992141470dc6d230beaf609c64",
            ),
        ];
        for (parameters, (inverse, expected)) in parameterSets.into_iter().zip(expected) {
            let ring = PolynomialRing::new(parameters);
            assert_eq!(parameters.firstPowerInverses[7], inverse);
            let value = seededPolynomial(parameters, 5, true);
            let power = ring.permutedPower(&value, inverse);
            assert_eq!(digest(&ring.bytes(&power)), expected);
            let squared = (0..128).fold(value.clone(), |result, _| ring.squared(&result));
            assert_eq!(power, squared);
            assert_eq!(ring.power(&value, 128, inverse), power);
            assert_eq!(
                ring.power(&value, 3, 0),
                ring.squared(&ring.squared(&ring.squared(&value)))
            );
        }
    }

    #[test]
    fn inverseGivesTheInverseOfTheCCodeAndUndoesTheProduct() {
        // `gf2x_mod_inv` of liboqs 0.16.0 for the block h0 of the secret key seed of 0x11 bytes.
        let expected = [
            "7b358419c7a462ff9d59c63eeda73d7521f1a2577d42f68ac9d0070bea12c00e",
            "b0e4e228dd0dd54401399aa7d321ac9a48d4236e6d96887d4e8a3b375f1724f4",
            "2b900ce06f760dc9eb50f756fa5b28a83aad54d1460e2363dab801c87221b114",
        ];
        for (parameters, expected) in parameterSets.into_iter().zip(expected) {
            let ring = PolynomialRing::new(parameters);
            let (blocks, _) = Sampler::new(parameters).secretBlocks(&[0x11; 32]);
            let inverse = ring.inverse(&blocks[0]);
            assert_eq!(digest(&ring.bytes(&inverse)), expected);
            let one = ring.product(&inverse, &blocks[0]);
            assert_eq!(one[0], 1);
            assert!(one[1..].iter().all(|word| *word == 0));
        }
    }

    #[test]
    fn bytesAndPolynomialsAreLittleEndian() {
        let ring = PolynomialRing::new(&bikeL1);
        let mut bytes = vec![0u8; 1541];
        bytes[0] = 0x01;
        bytes[8] = 0x80;
        bytes[1540] = 0x07;
        let polynomial = ring.polynomial(&bytes);
        assert_eq!(polynomial.len(), 193);
        assert_eq!((polynomial[0], polynomial[1]), (1, 0x80));
        assert_eq!(polynomial[192], 0x07 << 32);
        assert!(polynomial[2..192].iter().all(|word| *word == 0));
        assert_eq!(ring.bytes(&polynomial), bytes);
        // Fewer bytes give zero coefficients after them.
        assert_eq!(ring.polynomial(&[0xAB, 0xCD])[0], 0xCDAB);
    }
}
