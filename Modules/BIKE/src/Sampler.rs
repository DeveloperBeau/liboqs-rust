use crate::Parameters;
use crate::pseudorandomFunction::PseudorandomFunction;
use alloc::vec;
use alloc::vec::Vec;

/// The samplers of BIKE of one parameter set, `sampling.c` and `sampling_portable.c` of the C
/// code: the secret blocks of a key pair and the error vector of a message.
///
/// Each sampler draws its positions from the pseudorandom function of a seed with the variant of
/// the method of Fisher and Yates of the C code, so the same seed gives the same positions.
pub(crate) struct Sampler<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> Sampler<'parameters> {
    /// Makes the samplers of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Sampler { parameters }
    }

    /// `count` different positions below `bound`, `sample_indices_fisher_yates` of the C code.
    ///
    /// The last position comes first. Position `i` takes 4 bytes of the function as a
    /// little-endian value `v` and is `i + (v * (bound - i)) / 2^32`, or `i` itself when a later
    /// position already has that value. Each later position is above `i`, so the positions are
    /// different. The search for a repeated value has no branch.
    pub(crate) fn positions(
        count: usize,
        bound: u32,
        function: &mut PseudorandomFunction,
    ) -> Vec<u32> {
        let mut positions = vec![0u32; count];
        for index in (0..count).rev() {
            let mut bytes = [0u8; 4];
            function.fill(&mut bytes);
            let scaled = u64::from(u32::from_le_bytes(bytes)) * u64::from(bound - index as u32);
            let candidate = index as u32 + (scaled >> 32) as u32;
            let isRepeated = positions[index + 1..]
                .iter()
                .fold(0u32, |found, later| found | u32::from(candidate == *later));
            // The index when the candidate repeats a later position, and else the candidate.
            let repeatedMask = 0u32.wrapping_sub(isRepeated);
            positions[index] = candidate ^ (repeatedMask & (candidate ^ index as u32));
        }
        positions
    }

    /// The polynomial whose coefficients at the positions minus a first position are one,
    /// `secure_set_bits_port` of the C code, without a branch on a position.
    ///
    /// A position below the first position is negative as a 32-bit integer, so its word number
    /// matches no word, as in the C code. The positions must be different.
    pub(crate) fn polynomialOfPositions(&self, positions: &[u32], firstPosition: u32) -> Vec<u64> {
        let locations: Vec<(u32, u64)> = positions
            .iter()
            .map(|position| {
                let offset = position.wrapping_sub(firstPosition) as i32;
                ((offset >> 6) as u32, 1u64 << (offset & 63))
            })
            .collect();
        let mut words = vec![0u64; self.parameters.wordCount()];
        for (index, word) in words.iter_mut().enumerate() {
            for (wordIndex, bit) in &locations {
                let matchMask = 0u64.wrapping_sub(u64::from(*wordIndex == index as u32));
                // The positions are different, so the sum adds each bit once.
                *word += bit & matchMask;
            }
        }
        words
    }

    /// The secret blocks `h0` and `h1` of a seed and their positions,
    /// `generate_secret_key` of the C code. Both blocks draw `d` positions below `r` from one
    /// function, `h0` first.
    pub(crate) fn secretBlocks(&self, seed: &[u8; 32]) -> ([Vec<u64>; 2], [Vec<u32>; 2]) {
        let parameters = self.parameters;
        let mut function = PseudorandomFunction::new(seed);
        let blockBits = parameters.blockBits as u32;
        let firstPositions = Self::positions(parameters.blockWeight, blockBits, &mut function);
        let secondPositions = Self::positions(parameters.blockWeight, blockBits, &mut function);
        (
            [
                self.polynomialOfPositions(&firstPositions, 0),
                self.polynomialOfPositions(&secondPositions, 0),
            ],
            [firstPositions, secondPositions],
        )
    }

    /// The error vector `(e0, e1)` of a seed, the function `H` of BIKE,
    /// `generate_error_vector` of the C code. The `t` positions are below `2 r`: a position
    /// below `r` is a coefficient of `e0`, and a position `r + i` is coefficient `i` of `e1`.
    pub(crate) fn errorVector(&self, seed: &[u8; 32]) -> [Vec<u64>; 2] {
        let parameters = self.parameters;
        let mut function = PseudorandomFunction::new(seed);
        let blockBits = parameters.blockBits as u32;
        let positions = Self::positions(parameters.errorWeight, 2 * blockBits, &mut function);
        let mut error = [
            self.polynomialOfPositions(&positions, 0),
            self.polynomialOfPositions(&positions, blockBits),
        ];
        // The positions of e1 are coefficients of e0 from r up, which the C code clears.
        for block in error.iter_mut() {
            let last = block.len() - 1;
            block[last] &= parameters.lastWordMask();
        }
        error
    }
}

#[cfg(test)]
mod tests {
    use super::Sampler;
    use crate::parameters::{Parameters, bikeL1, bikeL3, bikeL5};
    use crate::polynomialRing::PolynomialRing;
    use crate::pseudorandomFunction::PseudorandomFunction;
    use crate::testSupport::digest;

    const parameterSets: [&Parameters; 3] = [&bikeL1, &bikeL3, &bikeL5];

    fn positionBytes(positions: &[u32]) -> Vec<u8> {
        positions
            .iter()
            .flat_map(|position| position.to_le_bytes())
            .collect()
    }

    fn weight(polynomial: &[u64]) -> u32 {
        polynomial.iter().map(|word| word.count_ones()).sum()
    }

    #[test]
    fn positionsAreThePositionsOfTheCSampler() {
        // `sample_indices_fisher_yates` of liboqs 0.16.0 with the bound 12 for the seed of 0x33
        // bytes. Several candidates repeat a later position, and the index replaces each one.
        let mut function = PseudorandomFunction::new(&[0x33; 32]);
        assert_eq!(
            Sampler::positions(10, 12, &mut function),
            [0, 1, 2, 3, 6, 5, 9, 7, 11, 10]
        );
        // The SHA3-256 of the 71 positions below 12323 for the seed of 0x42 bytes.
        let mut function = PseudorandomFunction::new(&[0x42; 32]);
        assert_eq!(
            digest(&positionBytes(&Sampler::positions(
                71,
                12323,
                &mut function
            ))),
            "a43bcea6f382eb295a38c4e1ec8880f017285cef1a21816c39b218e59ba6463c"
        );
    }

    #[test]
    fn positionsAreDifferentAndBelowTheBound() {
        for (count, bound) in [
            (71usize, 12323u32),
            (10, 12),
            (12, 12),
            (1, 1),
            (264, 81946),
        ] {
            for seed in 0..20u8 {
                let mut function = PseudorandomFunction::new(&[seed; 32]);
                let mut positions = Sampler::positions(count, bound, &mut function);
                assert!(positions.iter().all(|position| *position < bound));
                positions.sort_unstable();
                positions.dedup();
                assert_eq!(positions.len(), count, "{count} below {bound}, seed {seed}");
            }
        }
    }

    #[test]
    fn eachPositionTakesFourBytesOfTheFunctionFromTheLastPositionDown() {
        let seed = [7u8; 32];
        let mut stream = [0u8; 288];
        OQSNativeSHA3::SHAKE256::hash(&seed, &mut stream);
        let mut function = PseudorandomFunction::new(&seed);
        let positions = Sampler::positions(71, 12323, &mut function);
        // The last position takes the first 4 bytes as a little-endian value v and is
        // 70 + v (12323 - 70) / 2^32. No later position can repeat it.
        let first = u64::from(u32::from_le_bytes(stream[..4].try_into().expect("4 bytes")));
        assert_eq!(
            u64::from(positions[70]),
            70 + ((first * (12323 - 70)) >> 32)
        );
        // 71 positions take 284 bytes. A block of 136 bytes holds 34 requests of 4 bytes, so
        // no byte is skipped, and the next request gets bytes 284 to 287.
        let mut next = [0u8; 4];
        function.fill(&mut next);
        assert_eq!(next, stream[284..288]);
    }

    #[test]
    fn polynomialOfPositionsSetsTheCoefficientsAtThePositionsFromTheFirstPosition() {
        let sampler = Sampler::new(&bikeL1);
        let polynomial = sampler.polynomialOfPositions(&[0, 63, 64, 12322], 0);
        assert_eq!((polynomial[0], polynomial[1]), (1 | 1 << 63, 1));
        assert_eq!(polynomial[192], 1 << 34);
        assert_eq!(weight(&polynomial), 4);
        // From the first position r, the positions r and r + 70 are the coefficients 0 and 70,
        // and the position 5 below r matches no word.
        let polynomial = sampler.polynomialOfPositions(&[12323, 12393, 5], 12323);
        assert_eq!((polynomial[0], polynomial[1]), (1, 1 << 6));
        assert_eq!(weight(&polynomial), 2);
    }

    #[test]
    fn secretBlocksAreTheBlocksOfTheCSampler() {
        // `generate_secret_key` of liboqs 0.16.0 for the seed of 0x11 bytes: the SHA3-256 of
        // the bytes of h0 and h1, of the positions of both, and the first positions of h0.
        let expected = [
            (
                "91da3bef3df03bb53167caaeba91176d6b9157970b93a8121bad89bfd047ff65",
                "312022921a574008ca02f3808a150bab18d36a08cc6e29747d690b1164bce49c",
                [10566, 7628, 11617, 8383],
            ),
            (
                "63f1df80dc31ad6d3b22423995d48ebcb19134ef190faba21a76ff13f7f200e6",
                "14244a9e7a9b9ec4948b17cc8f157906c3d209284d37d336995904ca1fa4780c",
                [13461, 5655, 24577, 11745],
            ),
            (
                "30b2d23913b3f8b1f1ac636e9316c3b925027230b644cda1af1c86877a8a00b4",
                "6d6a99e7c4bf1dfa7d82168543f416f5de6c786a574f87f6fd07f033dc3b3fb2",
                [27141, 21516, 5918, 25116],
            ),
        ];
        for (parameters, (blocksDigest, positionsDigest, head)) in
            parameterSets.into_iter().zip(expected)
        {
            let ring = PolynomialRing::new(parameters);
            let (blocks, positions) = Sampler::new(parameters).secretBlocks(&[0x11; 32]);
            let mut bytes = ring.bytes(&blocks[0]);
            bytes.extend(ring.bytes(&blocks[1]));
            assert_eq!(digest(&bytes), blocksDigest);
            let mut allPositions = positions[0].clone();
            allPositions.extend(&positions[1]);
            assert_eq!(digest(&positionBytes(&allPositions)), positionsDigest);
            assert_eq!(positions[0][..4], head);
            for (block, blockPositions) in blocks.iter().zip(positions.iter()) {
                assert_eq!(weight(block) as usize, parameters.blockWeight);
                assert_eq!(
                    *block,
                    Sampler::new(parameters).polynomialOfPositions(blockPositions, 0)
                );
            }
        }
    }

    #[test]
    fn errorVectorIsTheErrorVectorOfTheCSampler() {
        // `generate_error_vector` of liboqs 0.16.0 for the seed of 0x22 bytes: the SHA3-256 of
        // the bytes of e0 and e1.
        let expected = [
            "746ce3bfcc57a70448a82260992b506244cdb70e9d984b0f514195e3216c0dbf",
            "55d7cc2db798b1a1c4c9d5af0467838c4a1e481965cb9babba66b32c6a355183",
            "ac174faf80d0aeee848d743aaa3f8d5318f4c8de500bd01ab5d74d6b6ecc9939",
        ];
        for (parameters, expected) in parameterSets.into_iter().zip(expected) {
            let ring = PolynomialRing::new(parameters);
            let error = Sampler::new(parameters).errorVector(&[0x22; 32]);
            let mut bytes = ring.bytes(&error[0]);
            bytes.extend(ring.bytes(&error[1]));
            assert_eq!(digest(&bytes), expected);
            assert_eq!(
                (weight(&error[0]) + weight(&error[1])) as usize,
                parameters.errorWeight
            );
            for block in &error {
                assert_eq!(block[block.len() - 1] & !parameters.lastWordMask(), 0);
            }
        }
    }

    #[test]
    fn errorVectorHasNoCoefficientFromR() {
        // A position r + i of e1 with i below 64 R_QWORDS - r also falls in the last word of
        // e0, and the sampler must clear it there, as the C code does.
        for parameters in parameterSets {
            let r = parameters.blockBits as u32;
            let lastWordEnd = 64 * parameters.wordCount() as u32;
            let mut clearedCount = 0;
            for seed in 0..=255u8 {
                let mut function = PseudorandomFunction::new(&[seed; 32]);
                let positions = Sampler::positions(parameters.errorWeight, 2 * r, &mut function);
                clearedCount += positions
                    .iter()
                    .filter(|position| (r..lastWordEnd).contains(*position))
                    .count();
                let error = Sampler::new(parameters).errorVector(&[seed; 32]);
                for block in &error {
                    assert_eq!(block[block.len() - 1] & !parameters.lastWordMask(), 0);
                }
                let total = weight(&error[0]) + weight(&error[1]);
                assert_eq!(total as usize, parameters.errorWeight, "seed {seed}");
            }
            assert!(clearedCount > 0, "{}", parameters.description.name);
        }
    }

    #[test]
    fn errorVectorSplitsThePositionsAtR() {
        // The positions of the seed below r are the coefficients of e0, and the others are the
        // coefficients of e1 after r.
        let parameters = &bikeL1;
        let mut function = PseudorandomFunction::new(&[0x22; 32]);
        let positions = Sampler::positions(134, 2 * 12323, &mut function);
        let error = Sampler::new(parameters).errorVector(&[0x22; 32]);
        for position in positions {
            let (block, coefficient) = if position < 12323 {
                (0, position as usize)
            } else {
                (1, position as usize - 12323)
            };
            assert_eq!(error[block][coefficient / 64] >> (coefficient % 64) & 1, 1);
        }
    }
}
