/// The sorting network of djbsort, `int32_sort.h` and `uint64_sort.h` of the C code: a fixed
/// sequence of exchanges that depends only on the length, with no branch on a value.
pub(crate) struct SortingNetwork;

impl SortingNetwork {
    /// Sorts signed 32-bit values in increasing order, `int32_sort`.
    pub(crate) fn sortIntegers(values: &mut [i32]) {
        Self::sort(values, Self::exchangedIntegers);
    }

    /// Sorts 64-bit values in increasing order, `uint64_sort`. The exchange compares by the
    /// sign of the difference, as the C code does, so the order is the order of the values
    /// below `2^63`, the only values that the key generation sorts.
    pub(crate) fn sortWords(values: &mut [u64]) {
        Self::sort(values, Self::exchangedWords);
    }

    /// The smaller and the larger of two signed values, `int32_MINMAX`.
    fn exchangedIntegers(left: i32, right: i32) -> (i32, i32) {
        let differentBits = right ^ left;
        let mut difference = right.wrapping_sub(left);
        difference ^= differentBits & (difference ^ right);
        let swap = (difference >> 31) & differentBits;
        (left ^ swap, right ^ swap)
    }

    /// The pair of two 64-bit values in the order of `uint64_MINMAX`.
    fn exchangedWords(left: u64, right: u64) -> (u64, u64) {
        let swap = (right.wrapping_sub(left) >> 63).wrapping_neg() & (left ^ right);
        (left ^ swap, right ^ swap)
    }

    /// The network of djbsort with an exchange of two values.
    fn sort<Value: Copy>(values: &mut [Value], exchanged: impl Fn(Value, Value) -> (Value, Value)) {
        let count = values.len();
        if count < 2 {
            return;
        }
        let mut top = 1;
        while top < count - top {
            top += top;
        }
        let mut stride = top;
        while stride > 0 {
            for index in 0..count - stride {
                if index & stride == 0 {
                    (values[index], values[index + stride]) =
                        exchanged(values[index], values[index + stride]);
                }
            }
            let mut index = 0;
            let mut outer = top;
            while outer > stride {
                while index < count - outer {
                    if index & stride == 0 {
                        let mut carried = values[index + stride];
                        let mut inner = outer;
                        while inner > stride {
                            (carried, values[index + inner]) =
                                exchanged(carried, values[index + inner]);
                            inner >>= 1;
                        }
                        values[index + stride] = carried;
                    }
                    index += 1;
                }
                outer >>= 1;
            }
            stride >>= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SortingNetwork;
    use OQSNativeAlgorithmTests::FuzzRandom;

    #[test]
    fn integersComeOutInTheOrderOfTheStandardSort() {
        let mut words = FuzzRandom::seeded(0x5052_5453);
        for length in [0usize, 1, 2, 3, 7, 64, 100, 4096, 8192] {
            let mut values: Vec<i32> = (0..length).map(|_| words.nextWord() as i32).collect();
            // The extremes and repeated values, whose differences overflow 32 bits.
            if length >= 8 {
                values[0] = i32::MIN;
                values[1] = i32::MAX;
                values[2] = -1;
                values[3] = values[4];
            }
            let mut expected = values.clone();
            expected.sort_unstable();
            SortingNetwork::sortIntegers(&mut values);
            assert_eq!(values, expected, "{length} values");
        }
    }

    #[test]
    fn wordsBelowTwoToThe63ComeOutInTheOrderOfTheStandardSort() {
        let mut words = FuzzRandom::seeded(0x5357_4F52);
        for length in [0usize, 1, 2, 5, 4096, 8192] {
            let mut values: Vec<u64> = (0..length).map(|_| words.nextWord() >> 1).collect();
            let mut expected = values.clone();
            expected.sort_unstable();
            SortingNetwork::sortWords(&mut values);
            assert_eq!(values, expected, "{length} values");
        }
    }

    #[test]
    fn wordsThatDifferByTwoToThe63KeepTheOrderOfTheSignOfTheDifference() {
        // `uint64_MINMAX` swaps when the top bit of `b - a` is set. For 2^63 and 1 the
        // difference 1 - 2^63 has the top bit set, so the values swap, and for 0 and 2^63 the
        // difference 2^63 has it set too.
        let mut values = [1u64 << 63, 1];
        SortingNetwork::sortWords(&mut values);
        assert_eq!(values, [1, 1 << 63]);
        let mut values = [0u64, 1 << 63];
        SortingNetwork::sortWords(&mut values);
        assert_eq!(values, [1 << 63, 0]);
    }
}
