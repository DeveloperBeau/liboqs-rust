/// The comparison and the selection of decapsulation with no branch on secret data,
/// `ct_verify` and `ct_select` of liboqs `util.c`.
pub(crate) struct ConstantTime;

impl ConstantTime {
    /// The selector of two lists of values: 0 when they are equal and -1 when they differ, as
    /// `ct_verify` gives it.
    pub(crate) fn mismatchSelector(left: &[u16], right: &[u16]) -> i8 {
        let differences = left
            .iter()
            .zip(right)
            .fold(0u16, |accumulated, (left, right)| {
                accumulated | (left ^ right)
            });
        // Each negation is of a value below 2^15, and one of them is negative exactly when a
        // bit of the differences is set. The arithmetic shift spreads the sign bit.
        let negative =
            ((differences >> 1) as i16).wrapping_neg() | ((differences & 1) as i16).wrapping_neg();
        (negative >> 15) as i8
    }

    /// Writes the first input to the output for the selector 0, and the second input for the
    /// selector -1, as `ct_select` does.
    pub(crate) fn select(first: &[u8], second: &[u8], selector: i8, output: &mut [u8]) {
        // The selector is a mask, and the optimizer must not turn it back into a branch.
        let mask = core::hint::black_box(selector) as u8;
        for ((target, first), second) in output.iter_mut().zip(first).zip(second) {
            // The two masks have no bit in common, so the sum has no carry.
            *target = (!mask & first) + (mask & second);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ConstantTime;

    #[test]
    fn equalListsGiveZeroAndEachDifferenceGivesMinusOne() {
        // `ct_verify` of liboqs 0.16.0 gives -1 for each of these differences in one value.
        let zero = [0u16; 16];
        assert_eq!(ConstantTime::mismatchSelector(&zero, &zero), 0);
        for difference in [0x0001u16, 0x0002, 0x4000, 0x8000, 0xFFFF, 0x0101] {
            let mut other = zero;
            other[5] = difference;
            assert_eq!(
                ConstantTime::mismatchSelector(&zero, &other),
                -1,
                "{difference:#06x}"
            );
            assert_eq!(ConstantTime::mismatchSelector(&other, &zero), -1);
        }
        let same: Vec<u16> = (0..640).map(|value| value * 51).collect();
        assert_eq!(ConstantTime::mismatchSelector(&same, &same.clone()), 0);
    }

    #[test]
    fn twoEqualDifferencesInTwoValuesStillDiffer() {
        // An exclusive or of the two differences would cancel them.
        let zero = [0u16; 16];
        let mut other = zero;
        other[5] = 0x0040;
        other[9] = 0x0040;
        assert_eq!(ConstantTime::mismatchSelector(&zero, &other), -1);
        let mut changed = [7u16, 7, 7, 7];
        changed[0] ^= 0x8001;
        changed[3] ^= 0x8001;
        assert_eq!(ConstantTime::mismatchSelector(&[7u16; 4], &changed), -1);
    }

    #[test]
    fn selectionTakesTheFirstInputForZeroAndTheSecondForMinusOne() {
        let first = [0x00u8, 0x5A, 0xFF, 0x81];
        let second = [0xFFu8, 0xA5, 0x01, 0x7E];
        let mut output = [0x33u8; 4];
        ConstantTime::select(&first, &second, 0, &mut output);
        assert_eq!(output, first);
        ConstantTime::select(&first, &second, -1, &mut output);
        assert_eq!(output, second);
    }
}
