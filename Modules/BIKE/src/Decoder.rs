use crate::Parameters;
use crate::parityCheckCounters::ParityCheckCounters;
use crate::polynomialRing::PolynomialRing;
use crate::syndrome::Syndrome;
use alloc::vec;
use alloc::vec::Vec;

/// The two blocks `(e0, e1)` of an error vector.
pub(crate) type ErrorVector = [Vec<u64>; 2];

/// The factor of the threshold, `THRESHOLD_MUL_CONST` of the C code: about `2^90 / 10^8`.
const thresholdFactor: u64 = 12_379_400_392_853_802_749;

/// The shift of the threshold after the high product, `THRESHOLD_SHR_CONST`.
const thresholdShift: u32 = 26;

/// The Black-Gray-Flip decoder of BIKE of one parameter set, `decode.c` and
/// `decode_portable.c` of the C code, with the fixed five iterations of the C code.
///
/// The decoder counts the unsatisfied parity checks of each position with bit-sliced counters,
/// flips the positions whose count reaches a threshold, and keeps the positions of the first
/// iteration as the black and the gray positions for its second and third steps. Every step
/// runs for every input, so the decoder has no branch on a secret value, and it decides as the C
/// code does for every ciphertext, also when it cannot find the error.
pub(crate) struct Decoder<'parameters> {
    parameters: &'parameters Parameters,
    ring: PolynomialRing<'parameters>,
}

/// The positions of the first step that a later step of the first iteration can flip.
#[derive(Clone, Copy)]
enum Marking {
    /// The positions whose count reached the threshold.
    black,
    /// The other positions whose count reached the threshold minus `delta`.
    gray,
}

/// The state of a run of the decoder: the error so far and the buffers of the steps.
struct DecoderRun<'parameters> {
    error: ErrorVector,
    black: ErrorVector,
    gray: ErrorVector,
    rotated: Vec<u64>,
    counters: ParityCheckCounters,
    syndrome: Syndrome<'parameters>,
}

impl<'parameters> Decoder<'parameters> {
    /// Makes the decoder of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Decoder {
            parameters,
            ring: PolynomialRing::new(parameters),
        }
    }

    /// The error vector that the decoder finds for a ciphertext under a secret key, as
    /// `decaps` of the C code hands their bytes to `decode`: the first block `c0` of the
    /// ciphertext, and the positions, the block `h0` and the public key of the secret key.
    pub(crate) fn decodedCiphertext(&self, ciphertext: &[u8], secretKey: &[u8]) -> ErrorVector {
        let parameters = self.parameters;
        let positions = [0, 1].map(|block| {
            secretKey[parameters.positionsRange(block)]
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
                .collect::<Vec<u32>>()
        });
        self.decoded(
            &self
                .ring
                .polynomial(&ciphertext[..parameters.polynomialByteCount()]),
            &self
                .ring
                .polynomial(&secretKey[parameters.secretBlockRange(0)]),
            &self
                .ring
                .polynomial(&secretKey[parameters.publicKeyRange()]),
            [&positions[0], &positions[1]],
        )
    }

    /// The error vector that the decoder finds for the first block `c0` of a ciphertext, with
    /// the secret block `h0`, the public key and the positions of `h0` and `h1`, `decode` of the
    /// C code.
    ///
    /// The inputs are the polynomials of the bytes of the ciphertext and the secret key, which
    /// can carry coefficients from `r` up. Each position can have any value, as in an invalid
    /// secret key.
    pub(crate) fn decoded(
        &self,
        ciphertextBlock: &[u64],
        secretBlock: &[u64],
        publicKey: &[u64],
        positions: [&[u32]; 2],
    ) -> ErrorVector {
        let parameters = self.parameters;
        let wordCount = parameters.wordCount();
        let zero = || [vec![0u64; wordCount], vec![0u64; wordCount]];
        let mut run = DecoderRun {
            error: zero(),
            black: zero(),
            gray: zero(),
            rotated: vec![0u64; Syndrome::rotationLength(parameters)],
            counters: ParityCheckCounters::zeroed(parameters.sliceCount(), wordCount),
            syndrome: self.syndrome(ciphertextBlock, secretBlock),
        };
        for iteration in 0..Parameters::decoderIterations {
            let threshold = self.threshold(&run.syndrome);
            self.flipAndMark(&mut run, positions, threshold);
            run.syndrome =
                self.recomputedSyndrome(ciphertextBlock, secretBlock, publicKey, &run.error);
            if iteration >= 1 {
                continue;
            }
            for marking in [Marking::black, Marking::gray] {
                self.flipMarked(&mut run, positions, marking);
                run.syndrome =
                    self.recomputedSyndrome(ciphertextBlock, secretBlock, publicKey, &run.error);
            }
        }
        run.error
    }

    /// The syndrome `c0 h0`, `compute_syndrome` of the C code.
    fn syndrome(&self, ciphertextBlock: &[u64], secretBlock: &[u64]) -> Syndrome<'parameters> {
        Syndrome::new(
            self.parameters,
            &self.ring.product(ciphertextBlock, secretBlock),
        )
    }

    /// The syndrome of the ciphertext with the error so far removed,
    /// `(c0 + e0 + e1 h) h0`, `recompute_syndrome` of the C code.
    fn recomputedSyndrome(
        &self,
        ciphertextBlock: &[u64],
        secretBlock: &[u64],
        publicKey: &[u64],
        error: &ErrorVector,
    ) -> Syndrome<'parameters> {
        let mut corrected = self.ring.product(&error[1], publicKey);
        for (word, (ciphertextWord, errorWord)) in corrected
            .iter_mut()
            .zip(ciphertextBlock.iter().zip(error[0].iter()))
        {
            *word ^= ciphertextWord ^ errorWord;
        }
        self.syndrome(&corrected, secretBlock)
    }

    /// The threshold of the first step of an iteration, `get_threshold` of the C code:
    /// `max((T0 + T1 |s|) / 10^8, minimum)` from the weight `|s|` of the syndrome, in integer
    /// arithmetic.
    fn threshold(&self, syndrome: &Syndrome<'_>) -> u8 {
        Self::thresholdOfWeight(self.parameters, syndrome.weight())
    }

    /// The threshold of a syndrome weight, as `get_threshold` computes it.
    ///
    /// The division by `10^8` is a product with `2^90 / 10^8` and a shift. The high word of the
    /// product is the one of the `MUL64HIGH` macro of the C code, which leaves out the product of
    /// the low halves, so it can be one below the exact high word. The threshold is a byte, as in
    /// the C code.
    fn thresholdOfWeight(parameters: &Parameters, weight: u64) -> u8 {
        let scaled = parameters.thresholdConstant + parameters.thresholdSlope * weight;
        let (low, high) = (scaled & 0xFFFF_FFFF, scaled >> 32);
        let (factorLow, factorHigh) = (thresholdFactor & 0xFFFF_FFFF, thresholdFactor >> 32);
        let highWord = high * factorHigh + ((high * factorLow + low * factorHigh) >> 32);
        let threshold = highWord >> thresholdShift;
        // `secure_l32_mask` of the 32-bit value: all ones when it is at least the minimum. The
        // values are far below 2^31, so the signed comparison of the C code on x86-64 and the
        // unsigned one elsewhere agree.
        let keepMask = 0u64.wrapping_sub(u64::from(
            threshold as u32 >= parameters.thresholdMinimum as u32,
        ));
        let chosen =
            (threshold & 0xFFFF_FFFF & keepMask) + (parameters.thresholdMinimum & !keepMask);
        chosen as u8
    }

    /// Counts the unsatisfied parity checks of each position of one block and subtracts a
    /// threshold, steps 1 and 2 of `find_err1` and `find_err2` of the C code. A position of the
    /// block whose count reaches the threshold has a zero in the top slice afterwards.
    fn countChecks(&self, run: &mut DecoderRun<'_>, positions: &[u32], threshold: u8) {
        run.counters.clear();
        for (index, position) in positions.iter().enumerate() {
            run.syndrome.rotateRight(*position, &mut run.rotated);
            // After `index + 1` additions a counter fits in the bit length of `index + 1`.
            run.counters
                .add(&mut run.rotated, Parameters::bitLength(index + 1));
        }
        run.counters.subtract(threshold);
    }

    /// The first step of an iteration, `find_err1` of the C code: flips each position whose
    /// count reaches the threshold, marks those positions as black, and marks as gray each
    /// other position whose count reaches the threshold minus `delta`.
    fn flipAndMark(&self, run: &mut DecoderRun<'_>, positions: [&[u32]; 2], threshold: u8) {
        let parameters = self.parameters;
        let wordCount = parameters.wordCount();
        for (block, blockPositions) in positions.into_iter().enumerate() {
            self.countChecks(run, blockPositions, threshold);
            let top = run.counters.topSlice();
            for (index, topWord) in top.iter().enumerate() {
                run.black[block][index] = !topWord;
                run.error[block][index] ^= !topWord;
            }
            run.error[block][wordCount - 1] &= parameters.lastWordMask();
            for _ in 0..Parameters::grayDelta {
                // The C code sets the first R_BYTES bytes to ones and keeps the carries in the
                // rest of the last word. Those bits count the positions from 8 R_BYTES up, which
                // never reach the error vector, so the whole word is set.
                run.rotated[..wordCount].fill(u64::MAX);
                run.counters.add(&mut run.rotated, parameters.sliceCount());
            }
            let top = run.counters.topSlice();
            for (index, topWord) in top.iter().enumerate() {
                run.gray[block][index] = !run.black[block][index] & !topWord;
            }
        }
    }

    /// The second or the third step of the first iteration, `find_err2` of the C code: flips
    /// each black or each gray position whose count reaches the majority threshold.
    fn flipMarked(&self, run: &mut DecoderRun<'_>, positions: [&[u32]; 2], marking: Marking) {
        let parameters = self.parameters;
        let wordCount = parameters.wordCount();
        for (block, blockPositions) in positions.into_iter().enumerate() {
            self.countChecks(run, blockPositions, parameters.majorityThreshold());
            let marked = match marking {
                Marking::black => &run.black[block],
                Marking::gray => &run.gray[block],
            };
            for ((errorWord, markedWord), topWord) in run.error[block]
                .iter_mut()
                .zip(marked.iter())
                .zip(run.counters.topSlice().iter())
            {
                *errorWord ^= markedWord & !topWord;
            }
            run.error[block][wordCount - 1] &= parameters.lastWordMask();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Decoder;
    use crate::BIKE;
    use crate::parameters::{Parameters, bikeL1, bikeL3, bikeL5};
    use crate::polynomialRing::PolynomialRing;
    use crate::sampler::Sampler;
    use crate::testSupport::{SeededWords, digest};
    use OQSNativeDomain::KeyEncapsulating;
    use OQSNativeKATRandom::NISTKATRandom;

    const parameterSets: [(&Parameters, &BIKE); 3] = [
        (&bikeL1, &BIKE::bikeL1),
        (&bikeL3, &BIKE::bikeL3),
        (&bikeL5, &BIKE::bikeL5),
    ];

    fn errorBytes(parameters: &Parameters, error: &super::ErrorVector) -> Vec<u8> {
        let ring = PolynomialRing::new(parameters);
        let mut bytes = ring.bytes(&error[0]);
        bytes.extend(ring.bytes(&error[1]));
        bytes
    }

    #[test]
    fn thresholdsAreTheThresholdsOfTheCCode() {
        // `get_threshold` of liboqs 0.16.0 for the syndrome weights 0, 1, 100, 1000, 2000,
        // 5000, r / 2, r - 1 and r.
        let expected = [
            [36, 36, 36, 36, 36, 48, 56, 99, 99],
            [52, 52, 52, 52, 52, 52, 80, 145, 145],
            [69, 69, 69, 69, 69, 69, 100, 182, 182],
        ];
        for ((parameters, _), expected) in parameterSets.into_iter().zip(expected) {
            let r = parameters.blockBits as u64;
            let weights = [0, 1, 100, 1000, 2000, 5000, r / 2, r - 1, r];
            let thresholds: Vec<u8> = weights
                .iter()
                .map(|weight| Decoder::thresholdOfWeight(parameters, *weight))
                .collect();
            assert_eq!(thresholds, expected, "{}", parameters.description.name);
        }
    }

    #[test]
    fn theHighWordOfTheCCodeGivesTheThresholdOfTheExactHighWordForEveryWeight() {
        // The `MUL64HIGH` macro leaves out the product of the low halves and its carry, so its
        // high word is often one below the exact one. The shift by 26 hides the difference for
        // every weight from 0 to r, so the threshold of the C code is the exact quotient.
        for (parameters, _) in parameterSets {
            for weight in 0..=parameters.blockBits as u64 {
                let scaled = parameters.thresholdConstant + parameters.thresholdSlope * weight;
                let exact = ((u128::from(scaled) * u128::from(super::thresholdFactor)) >> 64)
                    as u64
                    >> super::thresholdShift;
                let expected = exact.max(parameters.thresholdMinimum) as u8;
                assert_eq!(
                    Decoder::thresholdOfWeight(parameters, weight),
                    expected,
                    "{} weight {weight}",
                    parameters.description.name
                );
            }
        }
    }

    #[test]
    fn theThresholdRisesWithTheWeightFromItsMinimum() {
        for (parameters, _) in parameterSets {
            let mut previous = Decoder::thresholdOfWeight(parameters, 0);
            assert_eq!(u64::from(previous), parameters.thresholdMinimum);
            for weight in 1..=parameters.blockBits as u64 {
                let threshold = Decoder::thresholdOfWeight(parameters, weight);
                assert!(
                    threshold >= previous && threshold - previous <= 1,
                    "{weight}"
                );
                previous = threshold;
            }
        }
    }

    #[test]
    fn decoderFindsTheErrorOfAValidCiphertext() {
        for (parameters, _) in parameterSets {
            let ring = PolynomialRing::new(parameters);
            let sampler = Sampler::new(parameters);
            for seed in 0..3u8 {
                let (blocks, positions) = sampler.secretBlocks(&[seed; 32]);
                let publicKey = ring.product(&blocks[1], &ring.inverse(&blocks[0]));
                let error = sampler.errorVector(&[seed ^ 0x80; 32]);
                let mut ciphertextBlock = ring.product(&error[1], &publicKey);
                for (word, errorWord) in ciphertextBlock.iter_mut().zip(&error[0]) {
                    *word ^= errorWord;
                }
                let decoded = Decoder::new(parameters).decoded(
                    &ciphertextBlock,
                    &blocks[0],
                    &publicKey,
                    [&positions[0], &positions[1]],
                );
                assert_eq!(
                    decoded, error,
                    "{} seed {seed}",
                    parameters.description.name
                );
            }
        }
    }

    #[test]
    fn decoderGivesTheErrorsOfTheCDecoderForHostileInputs() {
        // `decode` of liboqs 0.16.0 with the secret key of the NIST generator seeded with the
        // bytes 0 to 47: the SHA3-256 of the bytes of e0 and e1 for a block c0 of ones, for
        // that block below r, and for the ciphertext of the generator seeded with ones under a
        // key whose positions repeat 0, r - 1, r, 64 R_QWORDS, 2^32 - 1 and
        // 64 (2 largestRotationStep) + 5.
        let expected = [
            [
                "ec69fee4d55414e1e24ab88fce73c2d702ec64a3a5ecb1765f0b4c3ad7cc70d6",
                "ec69fee4d55414e1e24ab88fce73c2d702ec64a3a5ecb1765f0b4c3ad7cc70d6",
                "28e6c384906afe92f90407baa139806bba15aff99ea69015bf0b1a85ed8eff52",
            ],
            [
                "87bd9672876893630a989823932a20f72e273b997042a007496edc727f4b4179",
                "100a1b32205386a84843d8f45b81041fc3eadb1d4de14991bcb00538d1181842",
                "628642cc2b129e82aa8024cf2369da30d23d3e532966c08faab376e51cfe110d",
            ],
            [
                "5b28b5c7fd53772600f5ee081b7cd3de26d1bf670dd2133af87ad6667ce47a2f",
                "5b28b5c7fd53772600f5ee081b7cd3de26d1bf670dd2133af87ad6667ce47a2f",
                "a68f1a39f6fec65949e3e5369ffd7b6d43948525f9636ea62bca7ff928ed4294",
            ],
        ];
        let entropy: [u8; 48] = core::array::from_fn(|index| index as u8);
        for ((parameters, mechanism), expected) in parameterSets.into_iter().zip(expected) {
            let decoder = Decoder::new(parameters);
            let keyPair = mechanism
                .generateKeyPair(&mut NISTKATRandom::new(&entropy, None))
                .expect("key pair");
            let secretKey = keyPair.secretKey.bytes();
            let byteCount = parameters.polynomialByteCount();
            let mut ones = vec![0xFFu8; byteCount + 32];
            ones[byteCount..].fill(0);
            let decodedOnes = decoder.decodedCiphertext(&ones, secretKey);
            assert_eq!(digest(&errorBytes(parameters, &decodedOnes)), expected[0]);
            ones[byteCount - 1] &= (1 << (parameters.blockBits % 8)) - 1;
            let decodedReduced = decoder.decodedCiphertext(&ones, secretKey);
            assert_eq!(
                digest(&errorBytes(parameters, &decodedReduced)),
                expected[1]
            );
            let encapsulation = mechanism
                .encapsulate(&keyPair.publicKey, &mut NISTKATRandom::new(&[1; 48], None))
                .expect("encapsulation");
            let r = parameters.blockBits as u32;
            let edges = [
                0,
                r - 1,
                r,
                64 * parameters.wordCount() as u32,
                u32::MAX,
                64 * 2 * parameters.largestRotationStep() as u32 + 5,
            ];
            let mut edgeKey = secretKey.to_vec();
            for (index, bytes) in edgeKey[..8 * parameters.blockWeight]
                .chunks_exact_mut(4)
                .enumerate()
            {
                bytes.copy_from_slice(&edges[index % edges.len()].to_le_bytes());
            }
            let decodedEdges = decoder.decodedCiphertext(&encapsulation.ciphertext, &edgeKey);
            assert_eq!(digest(&errorBytes(parameters, &decodedEdges)), expected[2]);
        }
    }

    #[test]
    fn decoderGivesTheErrorOfTheCDecoderForACiphertextBeyondItsReach() {
        // `decode` of liboqs 0.16.0 for the ciphertext of the generator seeded with ones under
        // the key of the generator seeded with the bytes 0 to 47, with the coefficients of c0
        // changed at the 40 positions `v mod r` of the words v of SplitMix64 from the seed 40.
        // The decoder cannot remove so many errors, so its output depends on each of its steps,
        // also on the gray step and on delta. The SHA3-256 of e0 and e1, and their weight.
        let expected = [
            (
                "3e7b0d31e17e4abb964f09c5d093e8a56dae7a41dcb1faa73337249e42995ff6",
                16,
            ),
            (
                "b77676a15bd8d78638e323374182df799da63834f3cbcbe68e6fe237df93fb78",
                6,
            ),
            (
                "8f2adf964e85afc3f294724c0dfae5c3a3e03d94fc4ca2867f56d713a437ca8a",
                206,
            ),
        ];
        let entropy: [u8; 48] = core::array::from_fn(|index| index as u8);
        for ((parameters, mechanism), (expectedDigest, expectedWeight)) in
            parameterSets.into_iter().zip(expected)
        {
            let keyPair = mechanism
                .generateKeyPair(&mut NISTKATRandom::new(&entropy, None))
                .expect("key pair");
            let mut ciphertext = mechanism
                .encapsulate(&keyPair.publicKey, &mut NISTKATRandom::new(&[1; 48], None))
                .expect("encapsulation")
                .ciphertext;
            let mut words = SeededWords::new(40);
            for _ in 0..40 {
                let position = (words.next() % parameters.blockBits as u64) as usize;
                ciphertext[position / 8] ^= 1 << (position % 8);
            }
            let decoded =
                Decoder::new(parameters).decodedCiphertext(&ciphertext, keyPair.secretKey.bytes());
            let bytes = errorBytes(parameters, &decoded);
            assert_eq!(digest(&bytes), expectedDigest);
            let weight: u32 = bytes.iter().map(|byte| byte.count_ones()).sum();
            assert_eq!(weight, expectedWeight, "{}", parameters.description.name);
        }
    }
}
