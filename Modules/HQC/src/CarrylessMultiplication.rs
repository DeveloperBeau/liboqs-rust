use alloc::vec::Vec;

/// The product of two binary polynomials of the same number of 64-bit words, without reduction,
/// `karatsuba_mul` of `gf2x.c` in the reference code.
///
/// The split follows the C code: half the words below, the rest above, and three products of
/// half the size, down to 16 words. There the C code multiplies bit by bit with masks, and this
/// port multiplies whole words with integer products of bits four places apart, which gives the
/// same exact product faster. Neither form has a branch or a table index that depends on the
/// values.
pub(crate) struct CarrylessMultiplication;

/// The number of words at and below which the product uses the schoolbook method,
/// `KARATSUBA_THRESHOLD`.
const schoolbookLimit: usize = 16;

/// The masks of the bits whose positions are 0, 1, 2 and 3 modulo 4.
const holeMasks: [u64; 4] = [
    0x1111_1111_1111_1111,
    0x2222_2222_2222_2222,
    0x4444_4444_4444_4444,
    0x8888_8888_8888_8888,
];

impl CarrylessMultiplication {
    /// The product of two polynomials of `n` words each, in `2 n` words.
    pub(crate) fn product(left: &[u64], right: &[u64]) -> Vec<u64> {
        debug_assert_eq!(left.len(), right.len());
        let mut result = alloc::vec![0u64; 2 * left.len()];
        // Each level of the split takes `8 n` words of the scratch, and the levels together take
        // less than `16 n`, as the buffer of the C code.
        let mut scratch = alloc::vec![0u64; 16 * left.len()];
        Self::karatsubaProduct(&mut result, left, right, &mut scratch);
        result
    }

    /// The product of two polynomials of `n` words into `2 n` words of `result`.
    fn karatsubaProduct(result: &mut [u64], left: &[u64], right: &[u64], scratch: &mut [u64]) {
        let count = left.len();
        if count <= schoolbookLimit {
            Self::schoolbookProduct(result, left, right);
            return;
        }
        let lowCount = count / 2;
        let highCount = count - lowCount;
        let (lowProduct, rest) = scratch.split_at_mut(2 * count);
        let (highProduct, rest) = rest.split_at_mut(2 * count);
        let (middleProduct, rest) = rest.split_at_mut(2 * count);
        let (leftSum, rest) = rest.split_at_mut(count);
        let (rightSum, childScratch) = rest.split_at_mut(count);
        Self::karatsubaProduct(
            &mut lowProduct[..2 * lowCount],
            &left[..lowCount],
            &right[..lowCount],
            childScratch,
        );
        Self::karatsubaProduct(
            &mut highProduct[..2 * highCount],
            &left[lowCount..],
            &right[lowCount..],
            childScratch,
        );
        // The sums of the halves, with the shorter low half padded with zero.
        for index in 0..highCount {
            let (lowLeft, lowRight) = if index < lowCount {
                (left[index], right[index])
            } else {
                (0, 0)
            };
            leftSum[index] = lowLeft ^ left[lowCount + index];
            rightSum[index] = lowRight ^ right[lowCount + index];
        }
        Self::karatsubaProduct(
            &mut middleProduct[..2 * highCount],
            &leftSum[..highCount],
            &rightSum[..highCount],
            childScratch,
        );
        result.fill(0);
        for (target, value) in result.iter_mut().zip(&lowProduct[..2 * lowCount]) {
            *target ^= value;
        }
        for (target, value) in result[2 * lowCount..]
            .iter_mut()
            .zip(&highProduct[..2 * highCount])
        {
            *target ^= value;
        }
        for index in 0..2 * highCount {
            let low = if index < 2 * lowCount {
                lowProduct[index]
            } else {
                0
            };
            result[lowCount + index] ^= middleProduct[index] ^ low ^ highProduct[index];
        }
    }

    /// The product of two polynomials of `n` words by the schoolbook method, `schoolbook_mul`.
    fn schoolbookProduct(result: &mut [u64], left: &[u64], right: &[u64]) {
        result.fill(0);
        for (leftIndex, leftWord) in left.iter().enumerate() {
            for (rightIndex, rightWord) in right.iter().enumerate() {
                let (low, high) = Self::wordProduct(*leftWord, *rightWord);
                result[leftIndex + rightIndex] ^= low;
                result[leftIndex + rightIndex + 1] ^= high;
            }
        }
    }

    /// The 128-bit carry-less product of two words, as its low word and its high word.
    ///
    /// The high word is the low word of the product of the bit reversals, reversed and shifted
    /// by one, because the product of two reversals is the reversal of the product.
    pub(crate) fn wordProduct(left: u64, right: u64) -> (u64, u64) {
        let low = Self::lowWord(left, right);
        let reversed = Self::lowWord(left.reverse_bits(), right.reverse_bits());
        (low, reversed.reverse_bits() >> 1)
    }

    /// The low 64 bits of the carry-less product of two words.
    ///
    /// Each factor splits into four parts with the bits of one position modulo 4. An integer
    /// product of two parts adds at most 16 bits into each position of its class, so the sum
    /// never reaches the next bit of the class below bit 64, and its lowest bit is the sum
    /// modulo 2. The other classes of the product hold carries and are masked away.
    fn lowWord(left: u64, right: u64) -> u64 {
        let [left0, left1, left2, left3] = holeMasks.map(|mask| left & mask);
        let [right0, right1, right2, right3] = holeMasks.map(|mask| right & mask);
        let product = |first: u64, second: u64| first.wrapping_mul(second);
        let class0 = product(left0, right0)
            ^ product(left1, right3)
            ^ product(left2, right2)
            ^ product(left3, right1);
        let class1 = product(left0, right1)
            ^ product(left1, right0)
            ^ product(left2, right3)
            ^ product(left3, right2);
        let class2 = product(left0, right2)
            ^ product(left1, right1)
            ^ product(left2, right0)
            ^ product(left3, right3);
        let class3 = product(left0, right3)
            ^ product(left1, right2)
            ^ product(left2, right1)
            ^ product(left3, right0);
        (class0 & holeMasks[0])
            + (class1 & holeMasks[1])
            + (class2 & holeMasks[2])
            + (class3 & holeMasks[3])
    }
}

#[cfg(test)]
mod tests {
    use super::CarrylessMultiplication;
    use OQSNativeAlgorithmTests::FuzzRandom;

    /// The carry-less product of two words by the definition, bit by bit.
    fn bitwiseProduct(left: u64, right: u64) -> u128 {
        (0..64)
            .filter(|bit| (right >> bit) & 1 == 1)
            .fold(0u128, |total, bit| total ^ (u128::from(left) << bit))
    }

    /// The product of two word arrays by the definition.
    fn definitionProduct(left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; 2 * left.len()];
        for (leftIndex, leftWord) in left.iter().enumerate() {
            for (rightIndex, rightWord) in right.iter().enumerate() {
                let product = bitwiseProduct(*leftWord, *rightWord);
                result[leftIndex + rightIndex] ^= product as u64;
                result[leftIndex + rightIndex + 1] ^= (product >> 64) as u64;
            }
        }
        result
    }

    /// Seeded words.
    fn words(seed: u64, count: usize) -> Vec<u64> {
        let mut random = FuzzRandom::seeded(seed);
        (0..count).map(|_| random.nextWord()).collect()
    }

    #[test]
    fn wordProductIsTheCarrylessProductForEveryPairOfSingleBitsAndRandomWords() {
        let check = |left: u64, right: u64| {
            let (low, high) = CarrylessMultiplication::wordProduct(left, right);
            let expected = bitwiseProduct(left, right);
            assert_eq!(
                (low, high),
                (expected as u64, (expected >> 64) as u64),
                "{left:#x} * {right:#x}"
            );
        };
        for leftBit in 0..64 {
            for rightBit in 0..64 {
                check(1 << leftBit, 1 << rightBit);
            }
        }
        // All ones fills every position of a class with 16 bits, the most that the parts hold.
        check(u64::MAX, u64::MAX);
        check(u64::MAX, 0x8000_0000_0000_0001);
        let values = words(1, 2000);
        for pair in values.chunks_exact(2) {
            check(pair[0], pair[1]);
        }
        assert_eq!(CarrylessMultiplication::wordProduct(0b11, 0b11), (0b101, 0));
    }

    #[test]
    fn productEqualsTheDefinitionAtEverySplitSize() {
        // Up to the limit the product is the schoolbook product, above it each odd and even size
        // splits in its own way, and the sizes of the parameter sets split several times.
        for count in (1..=40).chain([65, 129, 277]) {
            let left = words(count as u64, count);
            let right = words(1000 + count as u64, count);
            assert_eq!(
                CarrylessMultiplication::product(&left, &right),
                definitionProduct(&left, &right),
                "{count} words"
            );
        }
        let ones = vec![u64::MAX; 33];
        assert_eq!(
            CarrylessMultiplication::product(&ones, &ones),
            definitionProduct(&ones, &ones)
        );
    }
}
