/// The constant-time sort of `sntrup761.c`, `crypto_sort_int32` from
/// `crypto_sort/int32/portable4` of SUPERCOP and `crypto_sort_uint32` on top of it.
///
/// The network of comparisons depends only on the number of values, and each comparison
/// exchanges the two values with a mask, so the time does not depend on the values. The
/// result is the values in ascending order.
pub(crate) struct SortingNetwork;

impl SortingNetwork {
    /// The smaller and the larger of two values with no branch, `crypto_int32_minmax`.
    fn ordered(first: i32, second: i32) -> (i32, i32) {
        let differentBits = i64::from(second ^ first);
        // The difference has the sign of `second - first`, also when the two values have
        // different signs: then the sign of `second` decides.
        let mut difference = i64::from(second) - i64::from(first);
        difference ^= differentBits & (difference ^ i64::from(second));
        let swapMask = ((difference as i32) >> 31) & (differentBits as i32);
        (first ^ swapMask, second ^ swapMask)
    }

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

    /// Sorts signed values in ascending order, `crypto_sort_int32`.
    pub(crate) fn sortSigned(values: &mut [i32]) {
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

    /// Sorts unsigned values in ascending order, `crypto_sort_uint32`: the signed sort of the
    /// values with the top bit flipped.
    pub(crate) fn sort(values: &mut [u32]) {
        let mut signed: alloc::vec::Vec<i32> = values
            .iter()
            .map(|value| (value ^ 0x8000_0000) as i32)
            .collect();
        Self::sortSigned(&mut signed);
        for (value, sorted) in values.iter_mut().zip(signed) {
            *value = (sorted as u32) ^ 0x8000_0000;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SortingNetwork;
    use crate::testInputs::sequence;

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
    fn sortGivesTheUnsignedValuesInAscendingOrderForEveryLength() {
        for length in (0..70).chain([286, 761]) {
            let words = sequence(2 * length, 7 + length as u32);
            let mut values: Vec<u32> = words
                .chunks_exact(2)
                .map(|pair| (u32::from(pair[0]) << 16) + u32::from(pair[1]))
                .collect();
            let mut expected = values.clone();
            expected.sort_unstable();
            SortingNetwork::sort(&mut values);
            assert_eq!(values, expected, "{length} values");
        }
        let mut extremes = vec![u32::MAX, 0, 0x8000_0000, 0x7FFF_FFFF, 1, u32::MAX];
        SortingNetwork::sort(&mut extremes);
        assert_eq!(
            extremes,
            vec![0, 1, 0x7FFF_FFFF, 0x8000_0000, u32::MAX, u32::MAX]
        );
    }
}
