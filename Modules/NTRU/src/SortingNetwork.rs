/// The constant-time sort of 32-bit signed values of `crypto_sort_int32.c`, from
/// `crypto_sort/int32/x86` of SUPERCOP.
///
/// The network of comparisons depends only on the number of values, and each comparison
/// exchanges the two values with a mask, so the time does not depend on the values. The
/// result is the values in ascending order.
pub(crate) struct SortingNetwork;

impl SortingNetwork {
    /// The smaller and the larger of two values with no branch, `int32_MINMAX`.
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

    /// Orders the values at two places of a list.
    fn order(values: &mut [i32], lowPlace: usize, highPlace: usize) {
        let (low, high) = Self::ordered(values[lowPlace], values[highPlace]);
        values[lowPlace] = low;
        values[highPlace] = high;
    }

    /// The value at a place after the comparisons with the places `place + r` for `r` from
    /// `q` down to above `p`, the inner loop of the merge steps.
    fn merged(values: &mut [i32], place: usize, p: usize, q: usize) {
        let mut value = values[place + p];
        let mut r = q;
        while r > p {
            let (low, high) = Self::ordered(value, values[place + r]);
            value = low;
            values[place + r] = high;
            r >>= 1;
        }
        values[place + p] = value;
    }

    /// Sorts the values in ascending order, `crypto_sort_int32`.
    pub(crate) fn sort(values: &mut [i32]) {
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
                    Self::order(values, j, j + p);
                }
                i += 2 * p;
            }
            for j in i..n - p {
                Self::order(values, j, j + p);
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
                        Self::merged(values, j, p, q);
                        j += 1;
                        if j == i + p {
                            i += 2 * p;
                            break;
                        }
                    }
                }
                while i + p <= n - q {
                    for place in i..i + p {
                        Self::merged(values, place, p, q);
                    }
                    i += 2 * p;
                }
                j = i;
                while j < n - q {
                    Self::merged(values, j, p, q);
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
    use crate::testInputs::{cAnswer, digest, sequence};

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
    }

    #[test]
    fn sortGivesTheValuesInAscendingOrderForEveryLength() {
        for length in (0..70).chain([508, 676, 760, 761, 820, 1228]) {
            let words = sequence(2 * length, length as u32);
            let mut values: Vec<i32> = words
                .chunks_exact(2)
                .map(|pair| ((u32::from(pair[0]) << 16) + u32::from(pair[1])) as i32)
                .collect();
            let mut expected = values.clone();
            expected.sort_unstable();
            SortingNetwork::sort(&mut values);
            assert_eq!(values, expected, "{length} values");
        }
    }

    #[test]
    fn sortKeepsRepeatedValuesAndTheExtremes() {
        let mut values = vec![3, i32::MIN, 3, -3, i32::MAX, 0, i32::MIN, 3];
        SortingNetwork::sort(&mut values);
        assert_eq!(values, vec![i32::MIN, i32::MIN, -3, 0, 3, 3, 3, i32::MAX]);
    }

    #[test]
    fn sortGivesTheOrderOfCryptoSortInt32() {
        // crypto_sort_int32 of liboqs 0.16.0 on 1228 values from the same sequence.
        let words = sequence(2 * 1228, 20);
        let mut values: Vec<i32> = words
            .chunks_exact(2)
            .map(|pair| ((u32::from(pair[0]) << 16) + u32::from(pair[1])) as i32)
            .collect();
        SortingNetwork::sort(&mut values);
        let bytes: Vec<u8> = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        assert_eq!(digest(&bytes), cAnswer("sort", "values"));
    }
}
