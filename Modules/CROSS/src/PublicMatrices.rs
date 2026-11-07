use crate::{Parameters, Problem, Sampler};
use alloc::vec::Vec;

/// The matrices of a public seed, `expand_pk`: the part V^T of the parity-check matrix, and for
/// RSDP(G) the part W of the generator matrix of the subgroup.
///
/// One SHAKE stream of the seed, with the domain separator `3 T + 2`, gives W first and then
/// V^T, each from its own buffer of random bits.
pub(crate) struct PublicMatrices {
    /// V^T: k rows of n - k field elements.
    pub(crate) parityCheck: Vec<u16>,
    /// W: m rows of n - m exponents for RSDP(G), and empty for RSDP.
    pub(crate) subgroup: Vec<u8>,
}

impl PublicMatrices {
    /// The matrices of a public seed of 2 lambda / 8 bytes.
    pub(crate) fn expanded(parameters: &Parameters, publicSeed: &[u8]) -> Self {
        let sampler = Sampler::new(parameters);
        let mut reader = parameters
            .hashFunction()
            .reader(&[publicSeed], parameters.publicSeedDomain());
        let subgroup = match parameters.problem() {
            Problem::rsdp => Vec::new(),
            Problem::rsdpg => sampler.subgroupMatrix(&mut reader),
        };
        let parityCheck = sampler.parityMatrix(&mut reader);
        PublicMatrices {
            parityCheck,
            subgroup,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PublicMatrices;
    use crate::Sampler;
    use crate::parameters::{crossRSDP128Fast, crossRSDPG256Small};

    #[test]
    fn theSubgroupMatrixComesBeforeTheParityCheckMatrixInOneStream() {
        let parameters = &crossRSDPG256Small;
        let seed = [9u8; 64];
        let matrices = PublicMatrices::expanded(parameters, &seed);
        let sampler = Sampler::new(parameters);
        let mut reader = parameters
            .hashFunction()
            .reader(&[&seed], parameters.publicSeedDomain());
        assert_eq!(matrices.subgroup, sampler.subgroupMatrix(&mut reader));
        assert_eq!(matrices.parityCheck, sampler.parityMatrix(&mut reader));
        // RSDP has no subgroup, and its parity-check matrix starts the stream.
        let parameters = &crossRSDP128Fast;
        let matrices = PublicMatrices::expanded(parameters, &seed[..32]);
        assert!(matrices.subgroup.is_empty());
        let mut reader = parameters
            .hashFunction()
            .reader(&[&seed[..32]], parameters.publicSeedDomain());
        assert_eq!(
            matrices.parityCheck,
            Sampler::new(parameters).parityMatrix(&mut reader)
        );
    }
}
