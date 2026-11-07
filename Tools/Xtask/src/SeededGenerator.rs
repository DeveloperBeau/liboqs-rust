/// A small deterministic generator for test inputs (SplitMix64).
///
/// Every test that uses it prints its seed, so a failure can run again with the same input.
pub struct SeededGenerator {
    state: u64,
}

impl SeededGenerator {
    /// Makes a generator that starts at a seed.
    pub fn new(seed: u64) -> Self {
        println!("seed: {seed}");
        SeededGenerator { state: seed }
    }

    /// Returns the next 64 random bits.
    pub fn nextValue(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    /// Returns a value in the range from zero to one less than a bound.
    pub fn nextIndex(&mut self, bound: usize) -> usize {
        (self.nextValue() % bound as u64) as usize
    }

    /// Returns one element of a list.
    pub fn element<'list, Element>(&mut self, list: &'list [Element]) -> &'list Element {
        &list[self.nextIndex(list.len())]
    }
}
