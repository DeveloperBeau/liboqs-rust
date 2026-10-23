/// The constant-time sort of 32-bit values of liboqs: `crypto_sort_int32` of the NTRU-HPS code
/// of PQClean, from `crypto_sort/int32/x86` of SUPERCOP, and `crypto_sort_int32` and
/// `crypto_sort_uint32` of `sntrup761.c`, from `crypto_sort/int32/portable4` of SUPERCOP.
///
/// The network of comparisons depends only on the number of values, and each comparison
/// exchanges the two values with a mask, so the time does not depend on the values. The
/// result is the values in ascending order.
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

    /// The lengths of the tests: every short length, and the lengths of NTRU and sntrup761.
    fn testLengths() -> impl Iterator<Item = usize> {
        (0..70).chain([286, 508, 676, 760, 761, 820, 1228])
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
    }

    #[test]
    fn eachSortGivesTheOrderOfItsCFunctions() {
        // crypto_sort_int32 of the NTRU-HPS-2048-509 and NTRU-HPS-4096-1229 code, and
        // crypto_sort_int32 and crypto_sort_uint32 of sntrup761.c, of liboqs 0.16.0 on the same
        // 24 values. The three signed sorts gave the same order.
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
}
