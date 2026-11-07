use OQSNativeDomain::RandomGenerating;
use OQSNativeKATRandom::{HQCKATRandom, NISTKATRandom};
use alloc::boxed::Box;

/// The rules of `tests/test_helpers.c` that pick the random generator and the number of
/// counts of a known-answer program by algorithm name.
pub struct KnownAnswerRandom;

impl KnownAnswerRandom {
    /// The names of the algorithms whose known answers use the SHAKE256 generator.
    pub const shakeGeneratorAlgorithms: [&'static str; 3] = ["HQC-1", "HQC-3", "HQC-5"];

    /// The names of the algorithms whose `--all` run has 10 counts, not 100.
    pub const shortRunAlgorithms: [&'static str; 10] = [
        "Classic-McEliece-348864",
        "Classic-McEliece-348864f",
        "Classic-McEliece-460896",
        "Classic-McEliece-460896f",
        "Classic-McEliece-6688128",
        "Classic-McEliece-6688128f",
        "Classic-McEliece-6960119",
        "Classic-McEliece-6960119f",
        "Classic-McEliece-8192128",
        "Classic-McEliece-8192128f",
    ];

    /// The generator of an algorithm, seeded with a 48-byte entropy input: the SHAKE256
    /// generator for HQC and the NIST DRBG for every other algorithm.
    pub fn generator(algorithm: &str, entropy: &[u8; 48]) -> Box<dyn RandomGenerating> {
        if Self::shakeGeneratorAlgorithms.contains(&algorithm) {
            Box::new(HQCKATRandom::new(entropy, None))
        } else {
            Box::new(NISTKATRandom::new(entropy, None))
        }
    }

    /// The number of counts of the `--all` run of an algorithm.
    pub fn allCount(algorithm: &str) -> usize {
        if Self::shortRunAlgorithms.contains(&algorithm) {
            10
        } else {
            100
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KnownAnswerRandom;
    use OQSNativeDomain::RandomGenerating;
    use OQSNativeKATRandom::{HQCKATRandom, NISTKATRandom};

    fn firstBytes(generator: &mut dyn RandomGenerating) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        generator.fillRandomBytes(&mut bytes);
        bytes
    }

    #[test]
    fn hqcUsesTheSHAKEGeneratorAndEveryOtherNameTheNISTGenerator() {
        let entropy = [7u8; 48];
        assert_eq!(
            firstBytes(KnownAnswerRandom::generator("HQC-3", &entropy).as_mut()),
            firstBytes(&mut HQCKATRandom::new(&entropy, None))
        );
        for name in ["ML-KEM-768", "HQC-2", "hqc-1", "Falcon-512"] {
            assert_eq!(
                firstBytes(KnownAnswerRandom::generator(name, &entropy).as_mut()),
                firstBytes(&mut NISTKATRandom::new(&entropy, None)),
                "{name}"
            );
        }
    }

    #[test]
    fn onlyClassicMcElieceHasTheShortRun() {
        assert_eq!(KnownAnswerRandom::allCount("Classic-McEliece-6960119f"), 10);
        assert_eq!(KnownAnswerRandom::allCount("ML-KEM-512"), 100);
        assert_eq!(KnownAnswerRandom::allCount("Classic-McEliece"), 100);
    }
}
