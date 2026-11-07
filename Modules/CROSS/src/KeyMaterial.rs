use crate::{
    FieldArithmetic, Packing, Parameters, Problem, PublicMatrices, RestrictedArithmetic, Sampler,
};
use alloc::vec::Vec;

/// The key material of a secret seed, as `CROSS_keygen` and `expand_sk` expand it: the seed of
/// the matrices, the matrices, and the secret restricted vector e.
///
/// SHAKE of the secret seed with the domain separator `3 T + 1` gives the seed of e and then
/// the seed of the matrices. SHAKE of the seed of e with `3 T + 3` gives e for RSDP. For
/// RSDP(G) it gives the information word e_G of e, and e is the element of the subgroup of e_G.
pub(crate) struct KeyMaterial {
    /// The seed of the matrices, the first part of the public key.
    pub(crate) publicSeed: Vec<u8>,
    /// The matrices of the public seed.
    pub(crate) matrices: PublicMatrices,
    /// The secret restricted vector e of n exponents, normalized.
    pub(crate) secretVector: Vec<u8>,
    /// The information word e_G of m exponents of RSDP(G), and empty for RSDP.
    pub(crate) secretWord: Vec<u8>,
}

impl KeyMaterial {
    /// The key material of a secret seed of 2 lambda / 8 bytes.
    pub(crate) fn expanded(parameters: &Parameters, secretSeed: &[u8]) -> Self {
        let hash = parameters.hashFunction();
        let digestLength = parameters.digestLength();
        let mut seeds = alloc::vec![0u8; 2 * digestLength];
        hash.reader(&[secretSeed], parameters.secretSeedDomain())
            .squeeze(&mut seeds);
        let (errorSeed, publicSeed) = seeds.split_at(digestLength);
        let matrices = PublicMatrices::expanded(parameters, publicSeed);
        let mut reader = hash.reader(&[errorSeed], parameters.errorSeedDomain());
        let sampled = Sampler::new(parameters).restrictedVector(&mut reader);
        let (secretVector, secretWord) = match parameters.problem() {
            Problem::rsdp => (sampled, Vec::new()),
            Problem::rsdpg => {
                let arithmetic = RestrictedArithmetic::new(parameters);
                let mut element = arithmetic.subgroupElement(&sampled, &matrices.subgroup);
                arithmetic.normalize(&mut element);
                (element, sampled)
            }
        };
        KeyMaterial {
            publicSeed: publicSeed.to_vec(),
            matrices,
            secretVector,
            secretWord,
        }
    }

    /// The public key, `pk_t`: the seed of the matrices and the packed syndrome `s = e H^T`,
    /// normalized.
    pub(crate) fn publicKey(&self, parameters: &Parameters) -> Vec<u8> {
        let arithmetic = FieldArithmetic::new(parameters);
        let mut syndrome =
            arithmetic.restrictedSyndrome(&self.secretVector, &self.matrices.parityCheck);
        arithmetic.normalize(&mut syndrome);
        let mut publicKey = alloc::vec![0u8; parameters.publicKeyLength()];
        let (seedPart, syndromePart) = publicKey.split_at_mut(self.publicSeed.len());
        seedPart.copy_from_slice(&self.publicSeed);
        Packing::pack(
            syndrome.iter().map(|value| u32::from(*value)),
            parameters.problem().fieldBits(),
            syndromePart,
        );
        publicKey
    }
}

#[cfg(test)]
mod tests {
    use super::KeyMaterial;
    use crate::parameters::allSets;

    #[test]
    fn theSecretVectorIsARestrictedVectorOfTheSubgroup() {
        for parameters in allSets {
            let key = KeyMaterial::expanded(parameters, &vec![3u8; parameters.digestLength()]);
            let order = parameters.problem().restrictedOrder();
            assert_eq!(key.secretVector.len(), parameters.code.length);
            assert!(
                key.secretVector
                    .iter()
                    .all(|exponent| u32::from(*exponent) < order)
            );
            assert_eq!(key.secretWord.len(), parameters.code.subgroupDimension);
            assert_eq!(key.publicSeed.len(), parameters.digestLength());
            // The information word is the systematic part of the element of the subgroup.
            let width = parameters.code.length - parameters.code.subgroupDimension;
            if !key.secretWord.is_empty() {
                assert_eq!(&key.secretVector[width..], &key.secretWord[..]);
            }
            let publicKey = key.publicKey(parameters);
            assert_eq!(publicKey.len(), parameters.description.publicKeyLength);
            assert_eq!(&publicKey[..parameters.digestLength()], &key.publicSeed[..]);
        }
    }
}
