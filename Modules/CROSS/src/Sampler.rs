use crate::problem::bitLength;
use crate::{BitReader, Parameters};
use OQSNativeSHA3::SHAKEReader;
use alloc::vec;
use alloc::vec::Vec;

/// The samplers of a parameter set, from `csprng_hash.h` and `csprng_hash.c`: uniform field
/// elements and exponents by rejection, and the second challenge of fixed weight.
///
/// Each sampler squeezes a buffer of a fixed number of random bits, the `BITS_*_CT_RNG` of the
/// set, and reads its candidates from it. The buffer has room for the rejections of all but a
/// vanishing share of the seeds. When it runs out, the draws give zeros, which the samplers
/// accept, as the C code does.
pub(crate) struct Sampler<'parameters> {
    parameters: &'parameters Parameters,
}

/// The accepted draws of a buffer: each draw of some bits plus an offset, kept when it is below
/// a bound.
fn accepted(buffer: &[u8], bits: u32, offset: u64, bound: u64) -> impl Iterator<Item = u64> + '_ {
    let mut reader = BitReader::new(buffer);
    core::iter::repeat_with(move || reader.draw(bits) + offset).filter(move |value| *value < bound)
}

/// The next bytes of a reader for a number of random bits, `ROUND_UP(bits, 8) / 8` of them.
fn squeezed(reader: &mut SHAKEReader, bits: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; bits.div_ceil(8)];
    reader.squeeze(&mut buffer);
    buffer
}

impl<'parameters> Sampler<'parameters> {
    /// Makes the samplers of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Sampler { parameters }
    }

    /// The uniform field elements of a buffer, of the bits of the field, below p.
    fn fieldElements(&self, buffer: &[u8], count: usize) -> Vec<u16> {
        let problem = self.parameters.problem();
        accepted(buffer, problem.fieldBits(), 0, u64::from(problem.prime()))
            .take(count)
            .map(|value| value as u16)
            .collect()
    }

    /// The uniform exponents of a buffer, of the bits of the group order, below z.
    fn exponents(&self, buffer: &[u8], count: usize) -> Vec<u8> {
        let problem = self.parameters.problem();
        accepted(
            buffer,
            problem.restrictedBits(),
            0,
            u64::from(problem.restrictedOrder()),
        )
        .take(count)
        .map(|value| value as u8)
        .collect()
    }

    /// A vector of n uniform field elements, `csprng_fp_vec`.
    pub(crate) fn fieldVector(&self, reader: &mut SHAKEReader) -> Vec<u16> {
        let code = &self.parameters.code;
        let buffer = squeezed(reader, code.fieldVectorRandomBits);
        self.fieldElements(&buffer, code.length)
    }

    /// The matrix V^T of k rows of n - k uniform field elements, row by row, `csprng_fp_mat`.
    pub(crate) fn parityMatrix(&self, reader: &mut SHAKEReader) -> Vec<u16> {
        let code = &self.parameters.code;
        let buffer = squeezed(reader, code.parityMatrixRandomBits);
        self.fieldElements(&buffer, code.dimension * (code.length - code.dimension))
    }

    /// A restricted vector of uniform exponents: n for RSDP, `csprng_fz_vec`, and the m of an
    /// element of the subgroup for RSDP(G), `csprng_fz_inf_w`.
    pub(crate) fn restrictedVector(&self, reader: &mut SHAKEReader) -> Vec<u8> {
        let buffer = squeezed(reader, self.parameters.code.restrictedVectorRandomBits);
        self.exponents(&buffer, self.parameters.restrictedExponentCount())
    }

    /// The matrix W of the subgroup of RSDP(G), m rows of n - m uniform exponents, row by row,
    /// `csprng_fz_mat`.
    pub(crate) fn subgroupMatrix(&self, reader: &mut SHAKEReader) -> Vec<u8> {
        let code = &self.parameters.code;
        let buffer = squeezed(reader, code.subgroupMatrixRandomBits);
        self.exponents(
            &buffer,
            code.subgroupDimension * (code.length - code.subgroupDimension),
        )
    }

    /// The first challenge of the digest of a message, its commitments and its salt: t field
    /// elements from 1 to p - 1, `csprng_fp_vec_chall_1`. A candidate draws the bits of p - 2,
    /// and 1 is added to it.
    pub(crate) fn firstChallenge(&self, digest: &[u8]) -> Vec<u16> {
        let parameters = self.parameters;
        let problem = parameters.problem();
        let mut reader = parameters
            .hashFunction()
            .reader(&[digest], parameters.firstChallengeDomain());
        let buffer = squeezed(&mut reader, parameters.firstChallengeRandomBits);
        accepted(
            &buffer,
            problem.challengeBits(),
            1,
            u64::from(problem.prime()),
        )
        .take(parameters.roundCount)
        .map(|value| value as u16)
        .collect()
    }

    /// The second challenge of a digest: t bits of which w are ones, by the shuffle of
    /// Fisher and Yates, `expand_digest_to_fixed_weight`. Round i reveals its seed when bit i
    /// is one, and publishes its response when it is zero.
    pub(crate) fn secondChallenge(&self, digest: &[u8]) -> Vec<u8> {
        let parameters = self.parameters;
        let mut reader = parameters
            .hashFunction()
            .reader(&[digest], parameters.secondChallengeDomain());
        let buffer = squeezed(&mut reader, parameters.secondChallengeRandomBits);
        self.shuffled(&buffer)
    }

    /// The shuffle of the second challenge with the candidates of a buffer: w ones and then
    /// t - w zeros, where step i swaps place i with a place from i to t - 1.
    fn shuffled(&self, buffer: &[u8]) -> Vec<u8> {
        let roundCount = self.parameters.roundCount;
        let mut challenge = vec![1u8; self.parameters.challengeWeight];
        challenge.resize(roundCount, 0);
        let mut bits = BitReader::new(buffer);
        let mut current = 0;
        while current < roundCount {
            // A candidate of the bits of t - 1 - current, refused when it passes that value.
            let candidate = bits.draw(bitLength(roundCount - 1 - current)) as usize;
            if candidate < roundCount - current {
                challenge.swap(current, current + candidate);
                current += 1;
            }
        }
        challenge
    }
}

#[cfg(test)]
mod tests {
    use super::{Sampler, accepted};
    use crate::Packing;
    use crate::parameters::{
        allSets, crossRSDP128Balanced, crossRSDP128Fast, crossRSDPG128Balanced,
    };
    use crate::testInputs::SeededSequence;
    use OQSNativeAlgorithmTests::OutputDigest;
    use OQSNativeSHA3::SHAKE128;

    /// A buffer of packed values of some bits, with zeros after them to fill a length.
    fn buffer(values: &[u32], bits: u32, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        Packing::pack(values.iter().copied(), bits, &mut bytes);
        bytes
    }

    #[test]
    fn rejectionKeepsOnlyTheDrawsBelowTheBound() {
        // 7 bits: 127 is the second form of zero and is refused, 126 is kept.
        let bytes = buffer(&[5, 127, 126, 127, 127, 0, 9], 7, 16);
        let kept: Vec<u64> = accepted(&bytes, 7, 0, 127).take(4).collect();
        assert_eq!(kept, vec![5, 126, 0, 9]);
        // 9 bits: 509, 510 and 511 are refused, 508 is kept.
        let bytes = buffer(&[509, 508, 510, 511, 1], 9, 16);
        let kept: Vec<u64> = accepted(&bytes, 9, 0, 509).take(2).collect();
        assert_eq!(kept, vec![508, 1]);
        // 3 bits: 7 is the second form of zero of the exponents and is refused.
        let bytes = buffer(&[7, 6, 7, 0], 3, 8);
        let kept: Vec<u64> = accepted(&bytes, 3, 0, 7).take(2).collect();
        assert_eq!(kept, vec![6, 0]);
    }

    #[test]
    fn theFirstChallengeAddsOneToEachDrawBeforeTheBound() {
        // A draw of 125 gives 126, which is kept, and draws of 126 and 127 give 127 and 128,
        // which are refused. A draw of 0 gives 1, so the challenge is never zero.
        let bytes = buffer(&[125, 126, 127, 0], 7, 16);
        let kept: Vec<u64> = accepted(&bytes, 7, 1, 127).take(2).collect();
        assert_eq!(kept, vec![126, 1]);
    }

    #[test]
    fn aUsedUpBufferGivesTheZerosThatTheCSamplerAccepts() {
        // 141 bytes of ones for n = 127 elements of 7 bits: 161 draws of 127 are refused, the
        // last bit of the buffer gives 1, and the empty window gives zeros.
        let bytes = vec![0xFF; 141];
        let kept: Vec<u64> = accepted(&bytes, 7, 0, 127).take(127).collect();
        let mut expected = vec![0u64; 127];
        expected[0] = 1;
        assert_eq!(kept, expected);
    }

    #[test]
    fn eachSamplerDrawsTheValuesOfItsKindAndCount() {
        for parameters in allSets {
            let sampler = Sampler::new(parameters);
            let code = &parameters.code;
            let problem = parameters.problem();
            let prime = problem.prime() as u16;
            let order = problem.restrictedOrder() as u8;
            let mut reader = SHAKE128::absorbOnce(b"samplers");
            let vector = sampler.fieldVector(&mut reader);
            assert_eq!(vector.len(), code.length);
            assert!(vector.iter().all(|value| *value < prime));
            let matrix = sampler.parityMatrix(&mut reader);
            assert_eq!(
                matrix.len(),
                code.dimension * (code.length - code.dimension)
            );
            assert!(matrix.iter().all(|value| *value < prime));
            let restricted = sampler.restrictedVector(&mut reader);
            assert_eq!(restricted.len(), parameters.restrictedExponentCount());
            assert!(restricted.iter().all(|value| *value < order));
            if code.subgroupDimension > 0 {
                let subgroup = sampler.subgroupMatrix(&mut reader);
                assert_eq!(
                    subgroup.len(),
                    code.subgroupDimension * (code.length - code.subgroupDimension)
                );
                assert!(subgroup.iter().all(|value| *value < order));
            }
            let challenge = sampler.firstChallenge(b"digest");
            assert_eq!(challenge.len(), parameters.roundCount);
            assert!(challenge.iter().all(|value| *value >= 1 && *value < prime));
        }
    }

    #[test]
    fn theSecondChallengeIsTheShuffleOfTheCCode() {
        // `expand_digest_to_fixed_weight` of each set of the oracle library, on the digest of
        // the bytes of seed 3, as SHAKE128 of the t challenge bytes.
        let expected = [
            "c171585171ba3b4d840af037fb4e7507f8152f7cd524424ec82f69f2e21ef895",
            "6da4282348cbe296ac96eeeb1e2c0b002a4d5bd8b02e8e40a1e1a2ad79995008",
            "3e125198583763e369fd727dc29fea8e5e60b2899a5d6c8be00f3fe76a289835",
            "fb286f0ddb7b59459a70cc6f9a26cc8979ebf8c709bd638126333fa84d6fac9a",
            "22e5a75fb3d770617da3b5f54608541ce379cc199fe01ed04007c163fef00b3b",
            "56b059e865e97e0b35aaaf20bd12a2cef395dfb7f1b298e2ddbd54adbb1d802f",
            "753a1c73f8847564d1aa7d924703c0d84e0b1910dfce5b9d1822ba3cd0221686",
            "62b3cd69c12317babdc3a5f02378e60ae4f15d8af5239bc50cd8ffa942a16fa6",
            "345580197bd62d3cf926c4605c76800d07f5b62ae793550f35d77f87b61b1fcc",
            "a9018cf304c78690afe82da288c5b86003e44def0a98bc380bdfde3231aa02ea",
            "5ec3ec809936a9d6f9f9f41ee86d9f1a84e6ab51416b1af6f68497ed47369112",
            "def02dc75ab3fd2ef71681091e761252320b1045f7eebd8340c1a578bc0dd2a4",
            "84681191bdbcb9a9a7e7a2d133f323256c66bbc9a35f71945f79e0b8fc44d60c",
            "98b3b86d87ac70a462e69a7e49b9bed8f30767eb3a963ff53200dba24d5ab4d9",
            "24bcdc9d5539dfe670a013dd034de50e0a3c6424846c60710e3e844662c7b164",
            "1c9a03eccf79aca5e31edb99bff7fd1260247091677f0940f7988af4eb6ff92b",
            "d7ba34cdf655ff6b468982a9098dcac382831be78d5f9939be7ff9d7e7072c18",
            "ee9bdf098bf637d38faca88060d32fac4ea6cc6519eb0655da308509e699edd9",
        ];
        for (parameters, digest) in allSets.iter().zip(expected) {
            let challengeDigest = SeededSequence::new(3).bytes(parameters.digestLength());
            let challenge = Sampler::new(parameters).secondChallenge(&challengeDigest);
            assert_eq!(
                OutputDigest::of(&challenge),
                digest,
                "{}",
                parameters.description.name
            );
            let ones = challenge.iter().filter(|bit| **bit == 1).count();
            assert_eq!(ones, parameters.challengeWeight);
            assert!(challenge.iter().all(|bit| *bit <= 1));
        }
    }

    #[test]
    fn theShuffleRefusesACandidatePastTheLastPlace() {
        // cross-rsdp-128-fast has t = 157 and w = 82. The first candidate has 8 bits: 157 is
        // one past the last place and is refused, 156 swaps place 0 with the last place, and
        // the zeros after it keep every other place.
        let parameters = &crossRSDP128Fast;
        let mut bytes = vec![0u8; 64];
        bytes[0] = 157;
        bytes[1] = 156;
        let challenge = Sampler::new(parameters).shuffled(&bytes);
        let mut expected = vec![1u8; 82];
        expected.resize(157, 0);
        expected.swap(0, 156);
        assert_eq!(challenge, expected);
        // Zeros alone keep the ones first.
        let challenge = Sampler::new(&crossRSDPG128Balanced).shuffled(&[0u8; 64]);
        assert_eq!(&challenge[..220], &[1; 220]);
        assert_eq!(&challenge[220..], &[0; 36]);
    }

    #[test]
    fn theLastPlaceOfTheShuffleTakesOnlyACandidateOfZero() {
        // The candidate of the last step has 1 bit, and a candidate of 1 is refused. The
        // candidates before it are zeros, so their bits end where the last step starts: the sum
        // of the bit lengths of t - 1 down to 1.
        let parameters = &crossRSDP128Balanced;
        let lastStart: u32 = (1..parameters.roundCount)
            .map(crate::problem::bitLength)
            .sum();
        assert_eq!(lastStart, 1793);
        let mut bytes = vec![0u8; 597];
        bytes[lastStart as usize / 8] |= 1 << (lastStart % 8);
        let challenge = Sampler::new(parameters).shuffled(&bytes);
        let mut expected = vec![1u8; 215];
        expected.resize(256, 0);
        assert_eq!(challenge, expected);
    }
}
