use crate::Parameters;
use OQSNativeDomain::RandomGenerating;
use alloc::vec;
use alloc::vec::Vec;

/// The Niederreiter encryption of the C code, `encrypt.c`: a random error vector of weight `t`
/// and its syndrome under the public key.
pub(crate) struct Encryption<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> Encryption<'parameters> {
    /// Makes the encryption of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Encryption { parameters }
    }

    /// The `t` positions of an error vector from the bytes of one random request, or `None`
    /// when the attempt fails, as `gen_e` decides.
    ///
    /// Each two bytes give a value of `m` bits. A code of full length takes the first `t`
    /// values as they are. Another code takes the first `t` values below `n` from `2 t`
    /// candidates, and the attempt fails when fewer than `t` are below `n`. In both, the
    /// attempt fails when two positions are equal.
    pub(crate) fn positions(&self, bytes: &[u8]) -> Option<Vec<u16>> {
        let parameters = self.parameters;
        let field = parameters.field();
        let weight = parameters.errorWeight;
        let values = bytes.chunks_exact(2).map(|pair| field.loaded(pair));
        let positions: Vec<u16> = if parameters.isFullLength() {
            values.collect()
        } else {
            values
                .filter(|value| usize::from(*value) < parameters.codeLength)
                .take(weight)
                .collect()
        };
        if positions.len() < weight {
            return None;
        }
        // The C code compares every pair, with no early exit.
        let mut isRepeated = false;
        for (index, position) in positions.iter().enumerate() {
            for earlier in &positions[..index] {
                isRepeated |= position == earlier;
            }
        }
        if isRepeated { None } else { Some(positions) }
    }

    /// A mask of ones when two values are equal, `same_mask` of `encrypt.c`.
    fn sameMask(left: u16, right: u16) -> u8 {
        let difference = u32::from(left ^ right).wrapping_sub(1) >> 31;
        (difference.wrapping_neg() & 0xFF) as u8
    }

    /// The error vector of `n` bits with the bits of the positions set, with a mask for each
    /// position and each byte, as the end of `gen_e` writes it.
    pub(crate) fn errorVector(&self, positions: &[u16]) -> Vec<u8> {
        let mut error = vec![0u8; self.parameters.errorVectorLength()];
        for (index, byte) in error.iter_mut().enumerate() {
            for position in positions {
                let bit = 1u8 << (position & 7);
                *byte += bit & Self::sameMask(index as u16, position >> 3);
            }
        }
        error
    }

    /// The random error vector of weight `t`, `gen_e`: one random request for each attempt,
    /// until an attempt gives `t` distinct positions.
    pub(crate) fn randomErrorVector(&self, random: &mut dyn RandomGenerating) -> Vec<u8> {
        let mut bytes = vec![0u8; self.parameters.errorRequestLength()];
        loop {
            random.fillRandomBytes(&mut bytes);
            if let Some(positions) = self.positions(&bytes) {
                return self.errorVector(&positions);
            }
        }
    }

    /// The syndrome of an error vector under a public key, `syndrome` of `encrypt.c`: for each
    /// row, the parity of the row `(I | T)` of the systematic matrix and the error vector.
    ///
    /// The rows of the 6960119 sets start inside a byte, so the C code shifts each row of the
    /// public key by the bits of the tail. The shift drops the padding bits of the last byte of
    /// the row.
    pub(crate) fn syndrome(&self, publicKey: &[u8], error: &[u8]) -> Vec<u8> {
        let parameters = self.parameters;
        let rowLength = parameters.publicKeyRowLength();
        let byteCount = parameters.errorVectorLength();
        let tail = parameters.rowTail();
        let identityLength = byteCount - rowLength;
        let mut syndrome = vec![0u8; parameters.description.ciphertextLength];
        let mut row = vec![0u8; byteCount];
        for (index, publicRow) in publicKey.chunks_exact(rowLength).enumerate() {
            row.fill(0);
            row[identityLength..].copy_from_slice(publicRow);
            if tail != 0 {
                for byte in (identityLength..byteCount).rev() {
                    row[byte] = (row[byte] << tail) + (row[byte - 1] >> (8 - tail));
                }
            }
            row[index / 8] += 1 << (index % 8);
            let mut parity = row
                .iter()
                .zip(error)
                .fold(0u8, |total, (rowByte, errorByte)| {
                    total ^ (rowByte & errorByte)
                });
            parity ^= parity >> 4;
            parity ^= parity >> 2;
            parity ^= parity >> 1;
            syndrome[index / 8] += (parity & 1) << (index % 8);
        }
        syndrome
    }
}

#[cfg(test)]
mod tests {
    use super::Encryption;
    use crate::parameters::{
        allParameters, classicMcEliece348864, classicMcEliece6960119, classicMcEliece8192128,
    };
    use OQSNativeAlgorithmTests::{FuzzRandom, OutputDigest};

    /// The bytes of 16-bit values, little-endian.
    fn valueBytes(values: &[u16]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    #[test]
    fn candidatesBelowNAreTakenInOrderAndNIsRefused() {
        let parameters = &classicMcEliece348864;
        let encryption = Encryption::new(parameters);
        let weight = parameters.errorWeight;
        // Candidates n, n - 1, then 0 to 62, then 65535: n is refused, n - 1 is taken, and the
        // last value is above the first t valid ones.
        let mut candidates = vec![3488u16, 3487];
        candidates.extend(0..63);
        candidates.resize(2 * weight, 0xFFFF);
        let positions = encryption
            .positions(&valueBytes(&candidates))
            .expect("t positions");
        let mut expected = vec![3487u16];
        expected.extend(0..63);
        assert_eq!(positions, expected);
        // The 16-bit value 0x1000 + 5 loads as 5 in GF(2^12).
        candidates[2] = 0x1005;
        candidates[7] = 0x1000 + 3487;
        assert_eq!(encryption.positions(&valueBytes(&candidates)), None);
    }

    #[test]
    fn anAttemptWithFewerThanTValidCandidatesOrARepeatedPositionFails() {
        let parameters = &classicMcEliece348864;
        let encryption = Encryption::new(parameters);
        let weight = parameters.errorWeight;
        // t - 1 valid candidates and t + 1 values from n up.
        let mut candidates: Vec<u16> = (0..weight as u16 - 1).collect();
        candidates.resize(2 * weight, 3488);
        assert_eq!(encryption.positions(&valueBytes(&candidates)), None);
        // One more valid candidate at the very end gives t positions.
        candidates[2 * weight - 1] = 3487;
        assert!(encryption.positions(&valueBytes(&candidates)).is_some());
        // A repeated position among the first t valid candidates fails, also when it is the
        // last one.
        candidates[2 * weight - 1] = 0;
        assert_eq!(encryption.positions(&valueBytes(&candidates)), None);
        // A repeated value after the first t valid ones is not read.
        let mut candidates: Vec<u16> = (0..weight as u16).collect();
        candidates.resize(2 * weight, 7);
        assert!(encryption.positions(&valueBytes(&candidates)).is_some());
    }

    #[test]
    fn aCodeOfFullLengthTakesTheFirstTValuesAsTheyAre() {
        let parameters = &classicMcEliece8192128;
        let encryption = Encryption::new(parameters);
        let weight = parameters.errorWeight;
        assert_eq!(parameters.errorRequestLength(), 2 * weight);
        let values: Vec<u16> = (0..weight as u16).map(|value| 8191 - value).collect();
        assert_eq!(
            encryption.positions(&valueBytes(&values)),
            Some(values.clone())
        );
        let mut repeated = values.clone();
        repeated[weight - 1] = repeated[0];
        assert_eq!(encryption.positions(&valueBytes(&repeated)), None);
        // The bits above 13 are dropped, so 0xE000 + 8191 repeats 8191.
        let mut masked = values;
        masked[1] = 0xE000 + 8191;
        assert_eq!(encryption.positions(&valueBytes(&masked)), None);
    }

    #[test]
    fn theErrorVectorHasTheBitsOfThePositions() {
        for parameters in allParameters.iter().step_by(2) {
            let encryption = Encryption::new(parameters);
            let positions: Vec<u16> = (0..parameters.errorWeight as u16)
                .map(|index| index * 7 % parameters.codeLength as u16)
                .collect();
            let error = encryption.errorVector(&positions);
            assert_eq!(error.len(), parameters.codeLength / 8);
            let ones: Vec<u16> = (0..parameters.codeLength as u16)
                .filter(|bit| (error[usize::from(*bit) / 8] >> (bit % 8)) & 1 == 1)
                .collect();
            let mut sorted = positions.clone();
            sorted.sort_unstable();
            assert_eq!(ones, sorted, "{}", parameters.description.name);
        }
    }

    #[test]
    fn theSyndromeOfAnIdentityPositionIsItsUnitVector() {
        // The identity part of `(I | T)`: an error at position i < m t gives the syndrome with
        // only bit i set, whatever the public key holds.
        for parameters in [&classicMcEliece348864, &classicMcEliece6960119] {
            let encryption = Encryption::new(parameters);
            let mut words = FuzzRandom::seeded(17);
            let publicKey: Vec<u8> = (0..parameters.description.publicKeyLength)
                .map(|_| words.nextWord() as u8)
                .collect();
            for position in [0usize, 9, parameters.rowCount() - 1] {
                let mut error = vec![0u8; parameters.codeLength / 8];
                error[position / 8] = 1 << (position % 8);
                let syndrome = encryption.syndrome(&publicKey, &error);
                let mut expected = vec![0u8; parameters.description.ciphertextLength];
                expected[position / 8] = 1 << (position % 8);
                assert_eq!(syndrome, expected, "{position}");
            }
        }
    }

    #[test]
    fn theSyndromeOfAPositionOfTheKeyPartIsAColumnOfTheKey() {
        // An error at position m t + j gives bit j of each row of the public key. The 6960119
        // rows have 5413 bits, so the padding bits of the last byte of a row are never read.
        for parameters in [&classicMcEliece348864, &classicMcEliece6960119] {
            let encryption = Encryption::new(parameters);
            let rowLength = parameters.publicKeyRowLength();
            let mut words = FuzzRandom::seeded(18);
            let publicKey: Vec<u8> = (0..parameters.description.publicKeyLength)
                .map(|_| words.nextWord() as u8)
                .collect();
            let columnCount = parameters.codeLength - parameters.rowCount();
            for column in [0usize, 1, columnCount - 1] {
                let position = parameters.rowCount() + column;
                let mut error = vec![0u8; parameters.codeLength / 8];
                error[position / 8] = 1 << (position % 8);
                let syndrome = encryption.syndrome(&publicKey, &error);
                for (row, publicRow) in publicKey.chunks_exact(rowLength).enumerate() {
                    assert_eq!(
                        (syndrome[row / 8] >> (row % 8)) & 1,
                        (publicRow[column / 8] >> (column % 8)) & 1,
                        "column {column}, row {row}"
                    );
                }
            }
        }
    }

    #[test]
    fn syndromesGiveTheKnownAnswersOfTheCFunction() {
        // The `OutputDigest` of the syndromes of `encrypt` of liboqs 0.16.0, with a public key
        // of SplitMix64 bytes of the seed 51 and the error vectors of `gen_e` from SplitMix64
        // bytes of the seed 52, 4 vectors for each base set. Each vector and its syndrome
        // follow each other in the hashed bytes.
        let expected = [
            "eb77d12a45ced228aa406b9c6b3826e6b245ce892c10a568dc3168630096fade",
            "eadfea377fed941c955ffed69c69ce0d963ea791fe6bbb6b2e17a84001aea1cf",
            "2ce0ee5f88c95d52c13cffe9a853fadbe4407d576357e125d6951b27136288c5",
            "8cad782c998a352b9258b2bcbd9ce39cd0b5d0e7a1ed9fd3b435c89c52582918",
            "32e1a50494f5879befe09c827d9347b862638d0ac727c995066c2f16de48ff71",
        ];
        for (parameters, syndromeDigest) in allParameters.iter().step_by(2).zip(expected) {
            let encryption = Encryption::new(parameters);
            let mut words = FuzzRandom::seeded(51);
            let publicKey: Vec<u8> = (0..parameters.description.publicKeyLength)
                .map(|_| words.nextWord() as u8)
                .collect();
            let mut random = FuzzRandom::seeded(52);
            let mut output = Vec::new();
            for _ in 0..4 {
                let error = encryption.randomErrorVector(&mut random);
                output.extend(&error);
                output.extend(encryption.syndrome(&publicKey, &error));
            }
            assert_eq!(
                OutputDigest::of(&output),
                syndromeDigest,
                "{}",
                parameters.description.name
            );
        }
    }
}
