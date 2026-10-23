use crate::{
    FieldArithmetic, HashFunction, KeyMaterial, MerkleTree, Packing, Parameters, Problem,
    RestrictedArithmetic, Sampler, SeedTree,
};
use alloc::vec;
use alloc::vec::Vec;

/// The signature of `CROSS_sign` of one parameter set, with the root seed and the salt that the
/// signature draws as arguments.
///
/// Each of the t rounds commits to a masked copy of the secret vector. The commitments, the
/// message and the salt give the first challenge, a field element for each round, and the
/// responses y of the rounds then give the second challenge, t bits of weight w. A round with
/// bit one reveals its seed through the seed path, and a round with bit zero publishes y, its
/// restricted vector and its second commitment.
pub(crate) struct Signer<'parameters> {
    parameters: &'parameters Parameters,
    /// True when the signer normalizes each restricted vector before it publishes it, as
    /// `fz_dz_norm_n` and `fz_dz_norm_m` do. Only the signer of the tests of the group check
    /// leaves the second form of zero in its published vectors.
    normalizesPublishedVectors: bool,
}

/// The part of a message that the C code hashes. `xof_shake_update` takes the length as an
/// `unsigned int`, so the hash of a message of 2^32 bytes or more stops at its length modulo
/// 2^32.
fn hashedLength(length: usize) -> usize {
    length as u32 as usize
}

impl<'parameters> Signer<'parameters> {
    /// Makes the signer of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Signer {
            parameters,
            normalizesPublishedVectors: true,
        }
    }

    /// Makes a signer that publishes each restricted vector without its normalization, so that
    /// each zero of a published vector is the second form z. The first commitments hash the
    /// vectors as the signature holds them, so only the group check refuses its signatures.
    #[cfg(test)]
    pub(crate) fn keepingTheSecondFormOfZero(parameters: &'parameters Parameters) -> Self {
        Signer {
            parameters,
            normalizesPublishedVectors: false,
        }
    }

    /// The signature of a message under a secret key of the right length, with a root seed of
    /// lambda / 8 bytes and a salt of 2 lambda / 8 bytes.
    pub(crate) fn signature(
        &self,
        message: &[u8],
        secretKey: &[u8],
        rootSeed: &[u8],
        salt: &[u8],
    ) -> Vec<u8> {
        let parameters = self.parameters;
        let hash = parameters.hashFunction();
        let digestLength = parameters.digestLength();
        let roundCount = parameters.roundCount;
        let length = parameters.code.length;
        let field = FieldArithmetic::new(parameters);
        let restricted = RestrictedArithmetic::new(parameters);
        let sampler = Sampler::new(parameters);
        let key = KeyMaterial::expanded(parameters, secretKey);
        let seeds = SeedTree::generated(parameters, rootSeed, salt);

        let syndromeLength = parameters.syndromeLength();
        let restrictedLength = parameters.restrictedVectorLength();
        let fieldBits = parameters.problem().fieldBits();
        let restrictedBits = parameters.problem().restrictedBits();
        // The input of a first commitment: the syndrome, the restricted vector and the salt.
        let mut commitmentInput = vec![0u8; syndromeLength + restrictedLength + digestLength];
        commitmentInput[syndromeLength + restrictedLength..].copy_from_slice(salt);
        let mut errorVectors = Vec::with_capacity(roundCount * length);
        let mut masks = Vec::with_capacity(roundCount * length);
        let mut packedRestricted = vec![0u8; roundCount * restrictedLength];
        let mut firstCommitments = vec![0u8; roundCount * digestLength];
        let mut secondCommitments = vec![0u8; roundCount * digestLength];
        for round in 0..roundCount {
            let roundSeed = seeds.roundSeed(round);
            let domain = parameters.roundDomain(round);
            let mut reader = hash.reader(&[roundSeed, salt], domain);
            // The restricted vector e' of the round, the difference v = e - e' before its
            // normalization, and the vector that the round publishes: v for RSDP, and the word
            // v_G = e_G - e'_G of the subgroup for RSDP(G).
            let sampled = sampler.restrictedVector(&mut reader);
            let (errorVector, difference, published) = match parameters.problem() {
                Problem::rsdp => {
                    let difference = restricted.difference(&key.secretVector, &sampled);
                    let mut published = difference.clone();
                    if self.normalizesPublishedVectors {
                        restricted.normalize(&mut published);
                    }
                    (sampled, difference, published)
                }
                Problem::rsdpg => {
                    let mut word = restricted.difference(&key.secretWord, &sampled);
                    if self.normalizesPublishedVectors {
                        restricted.normalize(&mut word);
                    }
                    let mut element = restricted.subgroupElement(&sampled, &key.matrices.subgroup);
                    restricted.normalize(&mut element);
                    let difference = restricted.difference(&key.secretVector, &element);
                    (element, difference, word)
                }
            };
            let values = field.restrictedValues(&difference);
            let mask = sampler.fieldVector(&mut reader);
            // The commitment syndrome (g^v * u') H^T of the round.
            let product = field.pointwiseProduct(&values, &mask);
            let mut syndrome = field.syndrome(&product, &key.matrices.parityCheck);
            field.normalize(&mut syndrome);
            Packing::pack(
                syndrome.iter().map(|value| u32::from(*value)),
                fieldBits,
                &mut commitmentInput[..syndromeLength],
            );
            let restrictedPart =
                &mut packedRestricted[round * restrictedLength..(round + 1) * restrictedLength];
            Packing::pack(
                published.iter().map(|value| u32::from(*value)),
                restrictedBits,
                restrictedPart,
            );
            commitmentInput[syndromeLength..syndromeLength + restrictedLength]
                .copy_from_slice(restrictedPart);
            let commitmentDomain = HashFunction::hashDomain + domain;
            hash.digest(
                &[&commitmentInput],
                commitmentDomain,
                &mut firstCommitments[round * digestLength..(round + 1) * digestLength],
            );
            hash.digest(
                &[roundSeed, salt],
                commitmentDomain,
                &mut secondCommitments[round * digestLength..(round + 1) * digestLength],
            );
            errorVectors.extend_from_slice(&errorVector);
            masks.extend_from_slice(&mask);
        }

        let mut signature = vec![0u8; parameters.signatureLength()];
        signature[parameters.saltRange()].copy_from_slice(salt);
        let tree = MerkleTree::built(parameters, &firstCommitments);
        let commitmentDigest = Self::commitmentDigest(parameters, &tree.root(), &secondCommitments);
        signature[parameters.commitmentDigestRange()].copy_from_slice(&commitmentDigest);
        let firstChallengeDigest =
            Self::firstChallengeDigest(parameters, message, &commitmentDigest, salt);
        let firstChallenge = sampler.firstChallenge(&firstChallengeDigest);

        // The responses y = u' + c g^e' of the rounds, packed for the second challenge.
        let fieldVectorLength = parameters.fieldVectorLength();
        let mut responses = vec![0u8; roundCount * fieldVectorLength + digestLength];
        for (round, packed) in responses
            .chunks_exact_mut(fieldVectorLength)
            .take(roundCount)
            .enumerate()
        {
            let roundVectors = round * length..(round + 1) * length;
            let mut response = field.scaledSum(
                &errorVectors[roundVectors.clone()],
                firstChallenge[round],
                &masks[roundVectors],
            );
            field.normalize(&mut response);
            Packing::pack(
                response.iter().map(|value| u32::from(*value)),
                fieldBits,
                packed,
            );
        }
        responses[roundCount * fieldVectorLength..].copy_from_slice(&firstChallengeDigest);
        let secondChallengeRange = parameters.secondChallengeDigestRange();
        hash.digest(
            &[&responses],
            HashFunction::hashDomain,
            &mut signature[secondChallengeRange.clone()],
        );
        let secondChallenge = sampler.secondChallenge(&signature[secondChallengeRange]);

        tree.writeProof(&secondChallenge, &mut signature[parameters.proofRange()]);
        seeds.writePath(&secondChallenge, &mut signature[parameters.pathRange()]);
        let responseLength = parameters.responseLength();
        let commitmentResponses = parameters.commitmentResponsesRange().start;
        let responseStart = parameters.responsesRange().start;
        let hiddenRounds = (0..roundCount).filter(|round| secondChallenge[*round] == 0);
        for (index, round) in hiddenRounds.enumerate() {
            let response = responseStart + index * responseLength;
            signature[response..response + fieldVectorLength].copy_from_slice(
                &responses[round * fieldVectorLength..(round + 1) * fieldVectorLength],
            );
            signature[response + fieldVectorLength..response + responseLength].copy_from_slice(
                &packedRestricted[round * restrictedLength..(round + 1) * restrictedLength],
            );
            let commitment = commitmentResponses + index * digestLength;
            signature[commitment..commitment + digestLength].copy_from_slice(
                &secondCommitments[round * digestLength..(round + 1) * digestLength],
            );
        }
        signature
    }

    /// The digest of the commitments, `digest_cmt`: the hash of the Merkle root and of the hash
    /// of the second commitments of all rounds.
    pub(crate) fn commitmentDigest(
        parameters: &Parameters,
        root: &[u8],
        secondCommitments: &[u8],
    ) -> Vec<u8> {
        let hash = parameters.hashFunction();
        let digestLength = parameters.digestLength();
        let mut pair = vec![0u8; 2 * digestLength];
        pair[..digestLength].copy_from_slice(root);
        hash.digest(
            &[secondCommitments],
            HashFunction::hashDomain,
            &mut pair[digestLength..],
        );
        let mut digest = vec![0u8; digestLength];
        hash.digest(&[&pair], HashFunction::hashDomain, &mut digest);
        digest
    }

    /// The digest of the first challenge, `digest_chall_1`: the hash of the hash of the message,
    /// the digest of the commitments and the salt.
    pub(crate) fn firstChallengeDigest(
        parameters: &Parameters,
        message: &[u8],
        commitmentDigest: &[u8],
        salt: &[u8],
    ) -> Vec<u8> {
        let hash = parameters.hashFunction();
        let digestLength = parameters.digestLength();
        let mut input = vec![0u8; 3 * digestLength];
        hash.digest(
            &[&message[..hashedLength(message.len())]],
            HashFunction::hashDomain,
            &mut input[..digestLength],
        );
        input[digestLength..2 * digestLength].copy_from_slice(commitmentDigest);
        input[2 * digestLength..].copy_from_slice(salt);
        let mut digest = vec![0u8; digestLength];
        hash.digest(&[&input], HashFunction::hashDomain, &mut digest);
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::hashedLength;

    #[test]
    fn theHashedLengthIsTheLengthModulo2To32() {
        assert_eq!(hashedLength(0), 0);
        assert_eq!(hashedLength(9280), 9280);
        assert_eq!(hashedLength(u32::MAX as usize), u32::MAX as usize);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(hashedLength((1 << 32) + 5), 5);
            assert_eq!(hashedLength(1 << 32), 0);
        }
    }
}
