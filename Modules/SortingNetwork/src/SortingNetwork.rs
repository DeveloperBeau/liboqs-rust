/// The constant-time sort of djbsort in liboqs: `crypto_sort_int32` of the NTRU-HPS code of
/// PQClean, from `crypto_sort/int32/x86` of SUPERCOP, `crypto_sort_int32` and
/// `crypto_sort_uint32` of `sntrup761.c`, from `crypto_sort/int32/portable4` of SUPERCOP, and
/// `int32_sort` and `uint64_sort` of the Classic McEliece code of PQClean.
///
/// The network of comparisons depends only on the number of values, and each comparison
/// exchanges the two values with a mask, so the time does not depend on the values. The
/// result is the values in ascending order, except for the words of `sortWords` that differ
/// by `2^63` or more.
pub struct SortingNetwork;

/// The bit that `crypto_sort_uint32` flips, so that the signed order of the flipped values is
/// the unsigned order of the values.
const topBit: u32 = 0x8000_0000;

impl SortingNetwork {
    /// Sorts signed values in ascending order, `crypto_sort_int32`.
    pub fn sort(values: &mut [i32]) {
        Self::sortWith(values, Self::ordered);
    }

    /// Sorts unsigned values in ascending order, `crypto_sort_uint32`: the signed sort of the
    /// values with the top bit flipped.
    pub fn sortUnsigned(values: &mut [u32]) {
        Self::sortWith(values, Self::orderedUnsigned);
    }

    /// Sorts 64-bit words, `uint64_sort` of the Classic McEliece code.
    ///
    /// The exchange `uint64_MINMAX` swaps two words when the top bit of their difference is
    /// set. Two words that differ by less than `2^63` come out in ascending order. Two words
    /// that differ by `2^63` or more follow the same rule, so the larger word can come first,
    /// as in the C code. The key generation of Classic McEliece sorts only words below `2^63`.
    pub fn sortWords(values: &mut [u64]) {
        Self::sortWith(values, Self::orderedWords);
    }

    /// The smaller and the larger of two signed values with no branch, `int32_MINMAX` of
    /// PQClean and `crypto_int32_minmax` of `sntrup761.c`.
    fn ordered(first: i32, second: i32) -> (i32, i32) {
        let differentBits = second ^ first;
        // The difference has the sign of `second - first`, also when the subtraction
        // overflows 32 bits: then the two values have different signs, and the sign of
        // `second` decides.
        let mut difference = (i64::from(second) - i64::from(first)) as i32;
        difference ^= differentBits & (difference ^ second);
        let swapMask = (difference >> 31) & differentBits;
        (first ^ swapMask, second ^ swapMask)
    }

    /// The smaller and the larger of two unsigned values with no branch: the signed order of
    /// the values with the top bit flipped.
    fn orderedUnsigned(first: u32, second: u32) -> (u32, u32) {
        let (low, high) = Self::ordered((first ^ topBit) as i32, (second ^ topBit) as i32);
        ((low as u32) ^ topBit, (high as u32) ^ topBit)
    }

    /// Two words in the order of `uint64_MINMAX`, with no branch: swapped when the top bit of
    /// `second - first` modulo `2^64` is set.
    fn orderedWords(first: u64, second: u64) -> (u64, u64) {
        let swapMask = (second.wrapping_sub(first) >> 63).wrapping_neg() & (first ^ second);
        (first ^ swapMask, second ^ swapMask)
    }

    /// Orders the values at two places of a list.
    fn order<Value: Copy>(
        values: &mut [Value],
        lowPlace: usize,
        highPlace: usize,
        ordered: &impl Fn(Value, Value) -> (Value, Value),
    ) {
        let (low, high) = ordered(values[lowPlace], values[highPlace]);
        values[lowPlace] = low;
        values[highPlace] = high;
    }

    /// The value at a place after the comparisons with the places `place + r` for `r` from
    /// `q` down to above `p`, the inner loop of the merge steps.
    fn merge<Value: Copy>(
        values: &mut [Value],
        place: usize,
        p: usize,
        q: usize,
        ordered: &impl Fn(Value, Value) -> (Value, Value),
    ) {
        let mut value = values[place + p];
        let mut r = q;
        while r > p {
            let (low, high) = ordered(value, values[place + r]);
            value = low;
            values[place + r] = high;
            r >>= 1;
        }
        values[place + p] = value;
    }

    /// The network of `crypto_sort_int32` with the comparison of a value type.
    fn sortWith<Value: Copy>(
        values: &mut [Value],
        ordered: impl Fn(Value, Value) -> (Value, Value),
    ) {
        let n = values.len();
        if n < 2 {
            return;
        }
        let mut top = 1;
        while top < n - top {
            top += top;
        }
        let mut p = top;
        while p >= 1 {
            let mut i = 0;
            while i + 2 * p <= n {
                for j in i..i + p {
                    Self::order(values, j, j + p, &ordered);
                }
                i += 2 * p;
            }
            for j in i..n - p {
                Self::order(values, j, j + p, &ordered);
            }
            let mut i = 0;
            let mut j = 0;
            let mut q = top;
            'merge: while q > p {
                if j != i {
                    loop {
                        if j == n - q {
                            // The `goto done` of the C code: the next value of q.
                            q >>= 1;
                            continue 'merge;
                        }
                        Self::merge(values, j, p, q, &ordered);
                        j += 1;
                        if j == i + p {
                            i += 2 * p;
                            break;
                        }
                    }
                }
                while i + p <= n - q {
                    for place in i..i + p {
                        Self::merge(values, place, p, q, &ordered);
                    }
                    i += 2 * p;
                }
                j = i;
                while j < n - q {
                    Self::merge(values, j, p, q, &ordered);
                    j += 1;
                }
                q >>= 1;
            }
            p >>= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SortingNetwork;

    /// Values of a length that spread over the whole 32-bit range: the multiplicative hash of
    /// Knuth, a source times 2654435761 modulo `2^32`, with the length mixed into the source.
    /// Each third value repeats an earlier one.
    fn spreadValues(length: usize) -> Vec<u32> {
        (0..length)
            .map(|index| {
                let source = if index % 3 == 2 { index / 3 } else { index };
                (source as u32 ^ length as u32).wrapping_mul(2_654_435_761)
            })
            .collect()
    }

    /// Words of a length below `2^63` that spread over that range: a source times the 64-bit
    /// golden ratio `0x9E3779B97F4A7C15` modulo `2^64`, with the length mixed into the source,
    /// and the top bit cleared. Each third word repeats an earlier one.
    fn spreadWords(length: usize) -> Vec<u64> {
        (0..length)
            .map(|index| {
                let source = if index % 3 == 2 { index / 3 } else { index };
                (source as u64 ^ length as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 1
            })
            .collect()
    }

    /// The lengths of the tests: every short length, the lengths of NTRU and sntrup761, and the
    /// lengths `2^w` of Classic McEliece up to the 8192 elements of GF(2^13).
    fn testLengths() -> impl Iterator<Item = usize> {
        (0..70)
            .chain([286, 508, 676, 760, 761, 820, 1228])
            .chain([128, 256, 512, 1024, 2048, 4096, 8192])
    }

    /// The input of the C program of the known answers.
    const cInput: [i32; 24] = [
        5,
        -3,
        i32::MAX,
        i32::MIN,
        0,
        7,
        -1,
        7,
        1,
        i32::MIN,
        42,
        -42,
        1_000_000,
        -1_000_000,
        2_147_483_646,
        -2_147_483_647,
        3,
        3,
        0,
        65_536,
        -65_536,
        123_456_789,
        -123_456_789,
        2,
    ];

    #[test]
    fn orderedGivesTheSmallerValueFirstAlsoAcrossTheSignBoundary() {
        for (first, second) in [
            (5, 3),
            (3, 5),
            (-1, 1),
            (i32::MIN, i32::MAX),
            (i32::MAX, i32::MIN),
            (7, 7),
            (-7, i32::MIN),
        ] {
            assert_eq!(
                SortingNetwork::ordered(first, second),
                (first.min(second), first.max(second)),
                "{first}, {second}"
            );
        }
        for (first, second) in [
            (5u32, 3u32),
            (0x8000_0000, 0x7FFF_FFFF),
            (0x7FFF_FFFF, 0x8000_0000),
            (u32::MAX, 0),
            (0, u32::MAX),
            (9, 9),
        ] {
            assert_eq!(
                SortingNetwork::orderedUnsigned(first, second),
                (first.min(second), first.max(second)),
                "{first}, {second}"
            );
        }
    }

    #[test]
    fn orderedWordsSwapsTwoWordsWhenTheTopBitOfTheirDifferenceIsSet() {
        // `uint64_MINMAX` of the Classic McEliece code of liboqs 0.16.0 on each pair. Below a
        // distance of 2^63 the order is ascending. From 2^63 up, the larger word can stay
        // first or move first.
        for (pair, expected) in [
            ((5, 3), (3, 5)),
            ((3, 5), (3, 5)),
            ((7, 7), (7, 7)),
            ((1 << 63, 1), (1, 1 << 63)),
            ((0, 1 << 63), (1 << 63, 0)),
            ((1 << 63, 0), (0, 1 << 63)),
            ((1, (1 << 63) + 1), ((1 << 63) + 1, 1)),
            ((0, u64::MAX), (u64::MAX, 0)),
            ((u64::MAX, 0), (u64::MAX, 0)),
        ] {
            assert_eq!(
                SortingNetwork::orderedWords(pair.0, pair.1),
                expected,
                "{pair:x?}"
            );
        }
    }

    #[test]
    fn sortGivesTheSignedValuesInAscendingOrderForEveryLength() {
        for length in testLengths() {
            let mut values: Vec<i32> = spreadValues(length)
                .iter()
                .map(|value| *value as i32)
                .collect();
            let mut expected = values.clone();
            expected.sort_unstable();
            SortingNetwork::sort(&mut values);
            assert_eq!(values, expected, "{length} values");
        }
    }

    #[test]
    fn sortUnsignedGivesTheUnsignedValuesInAscendingOrderForEveryLength() {
        for length in testLengths() {
            let mut values = spreadValues(length);
            let mut expected = values.clone();
            expected.sort_unstable();
            SortingNetwork::sortUnsigned(&mut values);
            assert_eq!(values, expected, "{length} values");
        }
    }

    #[test]
    fn sortWordsGivesTheWordsBelowTwoToThe63InAscendingOrderForEveryLength() {
        for length in testLengths() {
            let mut values = spreadWords(length);
            let mut expected = values.clone();
            expected.sort_unstable();
            SortingNetwork::sortWords(&mut values);
            assert_eq!(values, expected, "{length} words");
        }
    }

    #[test]
    fn eachSortKeepsRepeatedValuesAndTheExtremes() {
        let mut values = vec![3, i32::MIN, 3, -3, i32::MAX, 0, i32::MIN, 3];
        SortingNetwork::sort(&mut values);
        assert_eq!(values, vec![i32::MIN, i32::MIN, -3, 0, 3, 3, 3, i32::MAX]);
        let mut values = vec![u32::MAX, 0, 0x8000_0000, 0x7FFF_FFFF, 1, u32::MAX];
        SortingNetwork::sortUnsigned(&mut values);
        assert_eq!(
            values,
            vec![0, 1, 0x7FFF_FFFF, 0x8000_0000, u32::MAX, u32::MAX]
        );
        let mut words = vec![u64::MAX >> 1, 0, 5, 1 << 62, 5, 0, u64::MAX >> 1];
        SortingNetwork::sortWords(&mut words);
        assert_eq!(
            words,
            vec![0, 0, 5, 5, 1 << 62, u64::MAX >> 1, u64::MAX >> 1]
        );
    }

    #[test]
    fn eachSortGivesTheOrderOfItsCFunctions() {
        // crypto_sort_int32 of the NTRU-HPS-2048-509 and NTRU-HPS-4096-1229 code,
        // crypto_sort_int32 and crypto_sort_uint32 of sntrup761.c, and int32_sort of the Classic
        // McEliece code, of liboqs 0.16.0 on the same 24 values. The four signed sorts gave the
        // same order.
        let mut signed = cInput;
        SortingNetwork::sort(&mut signed);
        assert_eq!(
            signed,
            [
                i32::MIN,
                i32::MIN,
                -2_147_483_647,
                -123_456_789,
                -1_000_000,
                -65_536,
                -42,
                -3,
                -1,
                0,
                0,
                1,
                2,
                3,
                3,
                5,
                7,
                7,
                42,
                65_536,
                1_000_000,
                123_456_789,
                2_147_483_646,
                i32::MAX,
            ]
        );
        let mut unsigned = cInput.map(|value| value as u32);
        SortingNetwork::sortUnsigned(&mut unsigned);
        assert_eq!(
            unsigned,
            [
                0,
                0,
                1,
                2,
                3,
                3,
                5,
                7,
                7,
                42,
                65_536,
                1_000_000,
                123_456_789,
                2_147_483_646,
                2_147_483_647,
                2_147_483_648,
                2_147_483_648,
                2_147_483_649,
                4_171_510_507,
                4_293_967_296,
                4_294_901_760,
                4_294_967_254,
                4_294_967_293,
                u32::MAX,
            ]
        );
    }

    #[test]
    fn sortWordsGivesTheOrderOfUint64SortOfTheCCode() {
        // uint64_sort of the Classic McEliece code of liboqs 0.16.0, the same in its ten
        // folders, on 24 words below and from 2^63, with pairs that differ by 2^63. The words
        // from 2^63 up break the ascending order, as `uint64_MINMAX` does.
        let mut words: [u64; 24] = [
            5,
            0x8000_0000_0000_0000,
            1,
            0,
            u64::MAX,
            0x7FFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0001,
            3,
            0x0123_4567_89AB_CDEF,
            0x8123_4567_89AB_CDEF,
            7,
            7,
            0xFFFF_FFFF_0000_0000,
            0x0000_0000_FFFF_FFFF,
            0x4000_0000_0000_0000,
            0xC000_0000_0000_0000,
            2,
            0x8000_0000_0000_0000,
            0x0FED_CBA9_8765_4321,
            0x8FED_CBA9_8765_4321,
            9,
            0x7FFF_FFFF_FFFF_FFFE,
            0xFFFF_FFFF_FFFF_FFFE,
            4,
        ];
        SortingNetwork::sortWords(&mut words);
        assert_eq!(
            words,
            [
                0x8FED_CBA9_8765_4321,
                0xFFFF_FFFF_0000_0000,
                0xFFFF_FFFF_FFFF_FFFE,
                0x8123_4567_89AB_CDEF,
                1,
                0,
                2,
                u64::MAX,
                7,
                3,
                4,
                5,
                0x7FFF_FFFF_FFFF_FFFE,
                9,
                0x0000_0000_FFFF_FFFF,
                7,
                0x0123_4567_89AB_CDEF,
                0x4000_0000_0000_0000,
                0x8000_0000_0000_0000,
                0x7FFF_FFFF_FFFF_FFFF,
                0x8000_0000_0000_0001,
                0x8000_0000_0000_0000,
                0xC000_0000_0000_0000,
                0x0FED_CBA9_8765_4321,
            ]
        );
    }
}
