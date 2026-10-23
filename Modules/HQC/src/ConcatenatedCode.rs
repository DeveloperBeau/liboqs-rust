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
    use crate::testInputs::receivedWord;
    use OQSNativeAlgorithmTests::{LinearCongruentialSequence, OutputDigest};

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

    #[test]
    fn decodingOfAnyWordGivesTheMessageOfTheCFunction() {
        // The digests of `code_decode` of liboqs 0.16.0 for six received words of each set, with
        // the seeds 500, 501 and 502. The thresholds of the shifts 2, 1 and 0 leave no wrong
        // byte, fewer than `delta` and more than `delta` wrong bytes for the Reed-Solomon code.
        for (seed, parameters, expected) in [
            (
                500,
                &hqc1,
                "c24bfc02dce51237feec0ab3e0d63ade7db9dd2b8bb5490009c6054cbc2e7ac9",
            ),
            (
                501,
                &hqc3,
                "9571e28ea6b96899377545adae997da5cbd6d906da10766d569e7660ebe3b029",
            ),
            (
                502,
                &hqc5,
                "f7efd03a1f0afb5bdd9a3c7f154cf97b9c9652a2b0e1caf97964651fba5fc849",
            ),
        ] {
            let code = ConcatenatedCode::new(parameters);
            let mut sequence = LinearCongruentialSequence::new(seed);
            let mut messages = Vec::new();
            for word in 0..6 {
                messages.extend(code.decoded(&receivedWord(&mut sequence, parameters, word % 3)));
            }
            assert_eq!(
                OutputDigest::of(&messages),
                expected,
                "{}, seed {seed}",
                parameters.description.name
            );
        }
    }
}
