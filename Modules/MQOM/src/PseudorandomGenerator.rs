use crate::SeedCipher;
use crate::seedCipher::generatorTweak;
use alloc::vec;
use alloc::vec::Vec;

/// The PRG of the seeds of one salt and one repetition, as `PRG` computes it: block `b` of the
/// output of a seed is the derived seed of the cipher keyed with `TweakSalt(salt, 3, e, b)`, and
/// the last block is cut to the length of the output.
///
/// The generator keeps the cipher of each block, as the key schedule cache of `prg_cache.h`
/// keeps the key schedules across the seeds of a repetition, and it encrypts the seeds of a
/// block together. The output of a seed does not depend on the other seeds.
pub(crate) struct PseudorandomGenerator {
    ciphers: Vec<SeedCipher>,
    seedLength: usize,
    outputLength: usize,
}

impl PseudorandomGenerator {
    /// The generator of a salt, a repetition and an output length, for seeds of the length of
    /// the salt.
    pub(crate) fn new(salt: &[u8], repetition: usize, outputLength: usize) -> Self {
        let seedLength = salt.len();
        let ciphers = (0..outputLength.div_ceil(seedLength))
            .map(|block| SeedCipher::tweaked(salt, generatorTweak, repetition, block))
            .collect();
        PseudorandomGenerator {
            ciphers,
            seedLength,
            outputLength,
        }
    }

    /// Fills the outputs of seeds, one after another: `outputLength` bytes for each seed.
    pub(crate) fn fill(&self, seeds: &[u8], outputs: &mut [u8]) {
        let mut derived = vec![0u8; seeds.len()];
        for (block, cipher) in self.ciphers.iter().enumerate() {
            cipher.derive(seeds, &mut derived);
            let start = block * self.seedLength;
            let length = self.seedLength.min(self.outputLength - start);
            for (output, seedBlock) in outputs
                .chunks_exact_mut(self.outputLength)
                .zip(derived.chunks_exact(self.seedLength))
            {
                output[start..start + length].copy_from_slice(&seedBlock[..length]);
            }
        }
    }

    /// The output of one seed.
    pub(crate) fn output(&self, seed: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; self.outputLength];
        self.fill(seed, &mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::PseudorandomGenerator;
    use crate::SeedCipher;
    use crate::testInputs::{cAnswer, everySet, sequenceBytes};
    use OQSNativeAlgorithmTests::OutputDigest;

    #[test]
    fn eachBlockIsTheDerivedSeedOfItsTweakedCipherAndTheLastIsCut() {
        let salt: Vec<u8> = (1..=24).collect();
        let seeds: Vec<u8> = (0..72).map(|value| value * 3).collect();
        let generator = PseudorandomGenerator::new(&salt, 5, 60);
        let mut outputs = vec![0u8; 3 * 60];
        generator.fill(&seeds, &mut outputs);
        for (seed, output) in seeds.chunks_exact(24).zip(outputs.chunks_exact(60)) {
            let mut expected = Vec::new();
            for block in 0..3 {
                let mut derived = [0u8; 24];
                SeedCipher::tweaked(&salt, 3, 5, block).derive(seed, &mut derived);
                expected.extend_from_slice(&derived);
            }
            assert_eq!(output, &expected[..60]);
            assert_eq!(generator.output(seed), output);
        }
    }

    #[test]
    fn theOutputIsTheOutputOfTheCFunctionForEverySet() {
        // `PRG` of a seeded salt and seed, the repetition 5 and 3 λ / 8 + 7 bytes.
        for parameters in everySet() {
            let name = parameters.description.name;
            let seedLength = parameters.seedLength();
            let generator =
                PseudorandomGenerator::new(&sequenceBytes(seedLength, 4), 5, 3 * seedLength + 7);
            let output = generator.output(&sequenceBytes(seedLength, 5));
            assert_eq!(
                OutputDigest::of(&output),
                cAnswer(name, "generator"),
                "{name}"
            );
        }
    }
}
