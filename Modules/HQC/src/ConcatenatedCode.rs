use crate::Parameters;
use crate::reedMuller::ReedMuller;
use crate::reedSolomon::ReedSolomon;
use alloc::vec::Vec;

/// The concatenated code of one parameter set, `code.c` of the reference code: the Reed-Solomon
/// code outside and the duplicated Reed-Muller code inside.
pub(crate) struct ConcatenatedCode<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> ConcatenatedCode<'parameters> {
    /// Makes the code of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        ConcatenatedCode { parameters }
    }

    /// The codeword of a message of `k` bytes, in `n1 n2 / 64` words, `code_encode`.
    pub(crate) fn encoded(&self, message: &[u8]) -> Vec<u64> {
        let outer = ReedSolomon::new(self.parameters).encoded(message);
        ReedMuller::encoded(&outer, self.parameters.multiplicity())
    }

    /// The message of `k` bytes of a received word of `n1 n2 / 64` words, `code_decode`.
    pub(crate) fn decoded(&self, received: &[u64]) -> Vec<u8> {
        let outer = ReedMuller::decoded(
            received,
            self.parameters.reedSolomonLength,
            self.parameters.multiplicity(),
        );
        ReedSolomon::new(self.parameters).decoded(&outer)
    }
}

#[cfg(test)]
mod tests {
    use super::ConcatenatedCode;
    use crate::parameters::{hqc1, hqc3, hqc5};

    #[test]
    fn decodingRecoversTheMessageThroughErrorsOfBothCodes() {
        for parameters in [&hqc1, &hqc3, &hqc5] {
            let code = ConcatenatedCode::new(parameters);
            let message: Vec<u8> = (0..parameters.messageLength as u8)
                .map(|index| index.wrapping_mul(37) ^ 0xC5)
                .collect();
            let mut word = code.encoded(&message);
            assert_eq!(word.len(), parameters.codewordWordCount());
            // A few flips in every Reed-Muller block, which the inner code corrects, and every
            // bit of `delta` whole blocks, which only the outer code corrects.
            let blockWords = 2 * parameters.multiplicity();
            for (block, words) in word.chunks_exact_mut(blockWords).enumerate() {
                if block < parameters.correctionCapacity {
                    words.iter_mut().for_each(|value| *value = !*value);
                } else {
                    words[0] ^= 0x0101_0000_0000_1001;
                    words[blockWords - 1] ^= 1 << 63;
                }
            }
            assert_eq!(
                code.decoded(&word),
                message,
                "{}",
                parameters.description.name
            );
        }
    }
}
