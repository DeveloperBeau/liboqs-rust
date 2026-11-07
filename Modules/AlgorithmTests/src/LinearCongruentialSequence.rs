/// The seeded sequence of the C programs that give the known answers of the unit tests of the
/// families.
///
/// The state takes `state * 1103515245 + 12345` modulo `2^32`, the constants of the example
/// `rand` of the C standard. A C program and a Rust test that start at the same seed make the
/// same inputs, so the test can compare its output with the digest that the C program printed.
pub struct LinearCongruentialSequence {
    state: u32,
}

impl LinearCongruentialSequence {
    /// Starts the sequence at a seed.
    pub fn new(seed: u32) -> Self {
        LinearCongruentialSequence { state: seed }
    }

    /// Advances the state and returns the new state.
    pub fn nextState(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::LinearCongruentialSequence;

    #[test]
    fn statesFollowTheConstantsOfTheExampleRandOfTheCStandard() {
        // 1 * 1103515245 + 12345 = 1103527590, and each later state is reduced modulo 2^32.
        let mut sequence = LinearCongruentialSequence::new(1);
        let states: Vec<u32> = (0..3).map(|_| sequence.nextState()).collect();
        assert_eq!(states, vec![1_103_527_590, 2_524_885_223, 662_824_084]);
        let mut fromZero = LinearCongruentialSequence::new(0);
        assert_eq!(fromZero.nextState(), 12_345);
        assert_eq!(fromZero.nextState(), 3_554_416_254);
    }
}
