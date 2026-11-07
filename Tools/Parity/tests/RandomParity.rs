//! Parity of the known-answer random generators with the C generators of liboqs, for seeded
//! entropy inputs and seeded request patterns. The output of the NIST DRBG depends on how the
//! requests split the bytes, so the patterns vary the lengths, empty requests included.

use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeDomain::RandomGenerating;
use OQSNativeKATRandom::{HQCKATRandom, NISTKATRandom};
use OQSNativeParity::{ParitySettings, VariationGenerator};

const caseCount: u64 = 1000;

/// The request lengths of one case: up to 12 requests of 0 to 300 bytes.
fn requestLengths(generator: &mut VariationGenerator) -> Vec<usize> {
    let count = 1 + generator.below(12) as usize;
    (0..count).map(|_| generator.below(301) as usize).collect()
}

fn drawn(random: &mut dyn RandomGenerating, lengths: &[usize]) -> Vec<Vec<u8>> {
    lengths
        .iter()
        .map(|length| {
            let mut bytes = vec![0u8; *length];
            random.fillRandomBytes(&mut bytes);
            bytes
        })
        .collect()
}

fn cDrawn(oracle: &mut COracle<'_>, lengths: &[usize]) -> Vec<Vec<u8>> {
    lengths
        .iter()
        .map(|length| {
            let mut bytes = vec![0u8; *length];
            oracle.fillRandomBytes(&mut bytes);
            bytes
        })
        .collect()
}

#[test]
fn nistGeneratorMatchesTheCDRBGForEveryRequestPattern() {
    let seed = ParitySettings::defaultSeed;
    let mut generator = VariationGenerator::forCase(seed, "NIST DRBG", 0);
    for case in 0..caseCount {
        let entropy = generator.entropy();
        let lengths = requestLengths(&mut generator);
        let rustBytes = drawn(&mut NISTKATRandom::new(&entropy, None), &lengths);
        let cBytes = cDrawn(&mut COracle::new(OracleRandomness::nist(entropy)), &lengths);
        assert_eq!(
            rustBytes, cBytes,
            "case {case} of seed {seed:#x}, requests {lengths:?}"
        );
    }
}

#[test]
fn hqcGeneratorMatchesTheCGeneratorOfTheKnownAnswerProgram() {
    let seed = ParitySettings::defaultSeed;
    let mut generator = VariationGenerator::forCase(seed, "HQC generator", 0);
    for case in 0..caseCount {
        let entropy = generator.entropy();
        let lengths = requestLengths(&mut generator);
        let rustBytes = drawn(&mut HQCKATRandom::new(&entropy, None), &lengths);
        let cBytes = cDrawn(
            &mut COracle::new(OracleRandomness::knownAnswer {
                algorithm: "HQC-5",
                entropy,
            }),
            &lengths,
        );
        assert_eq!(
            rustBytes, cBytes,
            "case {case} of seed {seed:#x}, requests {lengths:?}"
        );
    }
}
