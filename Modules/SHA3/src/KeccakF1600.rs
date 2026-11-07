/// The Keccak-f[1600] permutation of FIPS 202, on a state of 25 lanes of 64 bits.
///
/// Lane `x + 5 * y` holds the lane at column `x` and row `y`. A byte at offset `i` of the
/// state is byte `i % 8` of lane `i / 8`, in little-endian order.
pub struct KeccakF1600;

/// The round constants of the iota step, one for each of the 24 rounds.
const roundConstants: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// The rotation amounts of the rho step, in the order in which the pi step visits the lanes.
const rotationAmounts: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// The lane that the pi step moves into next, starting from lane 1.
const piLanes: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

impl KeccakF1600 {
    /// Applies the 24 rounds of the permutation to a state.
    pub fn permute(state: &mut [u64; 25]) {
        for roundConstant in roundConstants {
            // Theta: each lane takes the parity of two neighbouring columns.
            let mut columnParity = [0u64; 5];
            for (index, lane) in state.iter().enumerate() {
                columnParity[index % 5] ^= lane;
            }
            let mut columnEffect = [0u64; 5];
            for (column, effect) in columnEffect.iter_mut().enumerate() {
                *effect =
                    columnParity[(column + 4) % 5] ^ columnParity[(column + 1) % 5].rotate_left(1);
            }
            for (index, lane) in state.iter_mut().enumerate() {
                *lane ^= columnEffect[index % 5];
            }
            // Rho and pi: each lane rotates and moves to its new place.
            let mut carried = state[1];
            for (target, amount) in piLanes.iter().zip(rotationAmounts) {
                let moved = state[*target];
                state[*target] = carried.rotate_left(amount);
                carried = moved;
            }
            // Chi: the only non-linear step, within each row.
            for row in state.chunks_exact_mut(5) {
                let original = [row[0], row[1], row[2], row[3], row[4]];
                for (column, lane) in row.iter_mut().enumerate() {
                    *lane = original[column]
                        ^ (!original[(column + 1) % 5] & original[(column + 2) % 5]);
                }
            }
            // Iota: the round constant breaks the symmetry of the rounds.
            state[0] ^= roundConstant;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KeccakF1600;

    /// The state after one permutation of the zero state, from the Keccak team's
    /// `KeccakF-1600-IntermediateValues.txt`.
    #[test]
    fn permutationOfTheZeroStateGivesTheReferenceState() {
        let mut state = [0u64; 25];
        KeccakF1600::permute(&mut state);
        assert_eq!(state[0], 0xF1258F7940E1DDE7);
        assert_eq!(state[1], 0x84D5CCF933C0478A);
        assert_eq!(state[2], 0xD598261EA65AA9EE);
        assert_eq!(state[24], 0xEAF1FF7B5CECA249);
        KeccakF1600::permute(&mut state);
        assert_eq!(state[0], 0x2D5C954DF96ECB3C);
        assert_eq!(state[24], 0x20D06CD26A8FBF5C);
    }
}
