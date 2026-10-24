use alloc::vec;
use alloc::vec::Vec;

/// The counters of the unsatisfied parity checks of the positions of one block, in bit slices,
/// `upc_t` of the C code: word `i` of slice `j` holds bit `j` of the counters of the positions
/// `64 i` to `64 i + 63`.
pub(crate) struct ParityCheckCounters {
    slices: Vec<u64>,
    wordCount: usize,
    sliceCount: usize,
}

impl ParityCheckCounters {
    /// Makes counters with the value zero.
    pub(crate) fn zeroed(sliceCount: usize, wordCount: usize) -> Self {
        ParityCheckCounters {
            slices: vec![0u64; sliceCount * wordCount],
            wordCount,
            sliceCount,
        }
    }

    /// Sets every counter to zero.
    pub(crate) fn clear(&mut self) {
        self.slices.fill(0);
    }

    /// Adds one bit of each position to its counter through the first slices, as a chain of
    /// half adders, `bit_sliced_adder_port` of the C code. The addend holds the carries of the
    /// last slice afterwards, as in the C code.
    pub(crate) fn add(&mut self, addend: &mut [u64], sliceCount: usize) {
        for slice in self
            .slices
            .chunks_exact_mut(self.wordCount)
            .take(sliceCount)
        {
            for (counter, bit) in slice.iter_mut().zip(addend.iter_mut()) {
                let carry = *counter & *bit;
                *counter ^= *bit;
                *bit = carry;
            }
        }
    }

    /// Subtracts a value from every counter modulo `2^sliceCount`, as a chain of full
    /// subtractors, `bit_slice_full_subtract_port` of the C code. The top slice then holds the
    /// sign of each difference.
    pub(crate) fn subtract(&mut self, value: u8) {
        let mut borrows = vec![0u64; self.wordCount];
        let mut remaining = value;
        for slice in self.slices.chunks_exact_mut(self.wordCount) {
            let subtrahend = 0u64.wrapping_sub(u64::from(remaining & 1));
            remaining >>= 1;
            for (counter, borrow) in slice.iter_mut().zip(borrows.iter_mut()) {
                let minuend = *counter;
                // The two terms of the borrow hold different bits, so their sum is exact.
                let nextBorrow =
                    (!minuend & subtrahend & !*borrow) + ((!minuend | subtrahend) & *borrow);
                *counter = minuend ^ subtrahend ^ *borrow;
                *borrow = nextBorrow;
            }
        }
    }

    /// The top slice: bit `j` of the counter of each position for `j = sliceCount - 1`.
    pub(crate) fn topSlice(&self) -> &[u64] {
        &self.slices[(self.sliceCount - 1) * self.wordCount..]
    }
}

#[cfg(test)]
mod tests {
    use super::ParityCheckCounters;
    use crate::testSupport::SeededWords;

    /// The counter of one position, read from its bit in each slice.
    fn counterAt(counters: &ParityCheckCounters, position: usize) -> u64 {
        counters
            .slices
            .chunks_exact(counters.wordCount)
            .enumerate()
            .map(|(slice, words)| (words[position / 64] >> (position % 64) & 1) << slice)
            .sum()
    }

    #[test]
    fn additionsCountTheOnesOfEachPosition() {
        let wordCount = 3;
        let mut counters = ParityCheckCounters::zeroed(8, wordCount);
        let mut expected = [0u64; 192];
        let mut words = SeededWords::new(0xCC);
        for addition in 1..=71usize {
            let mut addend = words.words(wordCount);
            for (position, count) in expected.iter_mut().enumerate() {
                *count += addend[position / 64] >> (position % 64) & 1;
            }
            // The decoder adds through the bit length of the number of additions so far.
            let sliceCount = (usize::BITS - addition.leading_zeros()) as usize;
            counters.add(&mut addend, sliceCount);
        }
        for (position, count) in expected.iter().enumerate() {
            assert_eq!(
                counterAt(&counters, position),
                *count,
                "position {position}"
            );
        }
    }

    #[test]
    fn theAddendHoldsTheCarriesOfTheLastSlice() {
        let mut counters = ParityCheckCounters::zeroed(2, 1);
        // The counters 0, 1, 2 and 3 at the positions 0 to 3.
        counters.add(&mut [0b1110], 2);
        counters.add(&mut [0b1100], 2);
        counters.add(&mut [0b1000], 2);
        let mut addend = [0b1111];
        counters.add(&mut addend, 2);
        // The counters are now 1, 2, 3 and 0 modulo 4, and only position 3 carries out.
        assert_eq!(
            (0..4)
                .map(|position| counterAt(&counters, position))
                .collect::<Vec<_>>(),
            [1, 2, 3, 0]
        );
        assert_eq!(addend, [0b1000]);
        // An addition through one slice leaves the carries of the first slice: the counter 1
        // of position 0 carries, and the counter 2 of position 1 does not.
        let mut addend = [0b0011];
        counters.add(&mut addend, 1);
        assert_eq!(addend, [0b0001]);
        assert_eq!(counterAt(&counters, 0), 0);
        assert_eq!(counterAt(&counters, 1), 3);
    }

    #[test]
    fn subtractionGivesTheDifferenceModuloTheSliceCountWithItsSignInTheTopSlice() {
        for sliceCount in [8usize, 9] {
            let modulus = 1u64 << sliceCount;
            let mut counters = ParityCheckCounters::zeroed(sliceCount, 2);
            // The counters 0 to 127 at the positions 0 to 127.
            for value in 0..128u64 {
                for slice in 0..sliceCount {
                    let bit = value >> slice & 1;
                    counters.slices[slice * 2 + (value as usize) / 64] |= bit << (value % 64);
                }
            }
            for threshold in [0u8, 1, 36, 70, 145, 182, 255] {
                let mut subtracted = ParityCheckCounters {
                    slices: counters.slices.clone(),
                    wordCount: 2,
                    sliceCount,
                };
                subtracted.subtract(threshold);
                for value in 0..128u64 {
                    let difference = (value + modulus - u64::from(threshold) % modulus) % modulus;
                    assert_eq!(
                        counterAt(&subtracted, value as usize),
                        difference,
                        "{value} - {threshold} with {sliceCount} slices"
                    );
                    let sign = subtracted.topSlice()[(value as usize) / 64] >> (value % 64) & 1;
                    assert_eq!(sign, difference >> (sliceCount - 1));
                }
            }
        }
    }

    #[test]
    fn clearSetsEveryCounterToZero() {
        let mut counters = ParityCheckCounters::zeroed(3, 2);
        counters.add(&mut [u64::MAX, 5], 3);
        assert!(counters.slices.iter().any(|word| *word != 0));
        counters.clear();
        assert!(counters.slices.iter().all(|word| *word == 0));
        assert_eq!(counters.topSlice().len(), 2);
    }
}
