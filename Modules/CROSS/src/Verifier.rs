use crate::{
    FieldArithmetic, HashFunction, MerkleTree, Packing, Parameters, Problem, PublicMatrices,
    RestrictedArithmetic, Sampler, SeedTree, Signer,
};
use alloc::vec;
use alloc::vec::Vec;

/// The verification of `CROSS_verify` of one parameter set.
///
/// The verifier recomputes the response y of each round that reveals its seed, and the first
/// commitment of each round that publishes its response. The signature is valid when the
/// digest of the commitments and the digest of the second challenge come out as in the
/// signature, every published restricted vector lies in the restricted group, and every padding
/// bit of the public key, of the responses, of the seed path and of the Merkle proof is zero.
pub(crate) struct Verifier<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> Verifier<'parameters> {
    /// Makes the verifier of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        Verifier { parameters }
    }

    /// True when a signature of a message is valid for a public key. A signature or a public
    /// key of a wrong length is not valid.
    pub(crate) fn isValidSignature(
        &self,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> bool {
        let parameters = self.parameters;
        if signature.len() != parameters.signatureLength()
            || publicKey.len() != parameters.publicKeyLength()
        {
            return false;
        }
        let hash = parameters.hashFunction();
        let digestLength = parameters.digestLength();
        let roundCount = parameters.roundCount;
        let problem = parameters.problem();
        let field = FieldArithmetic::new(parameters);
        let restricted = RestrictedArithmetic::new(parameters);
        let sampler = Sampler::new(parameters);
        let fieldBits = problem.fieldBits();
        let restrictedBits = problem.restrictedBits();

        let (publicSeed, packedSyndrome) = publicKey.split_at(digestLength);
        let matrices = PublicMatrices::expanded(parameters, publicSeed);
        let (syndromeValues, isKeyPaddingZero) = Packing::unpacked(
            packedSyndrome,
            parameters.code.length - parameters.code.dimension,
            fieldBits,
        );
        let publicSyndrome: Vec<u16> = syndromeValues.iter().map(|value| *value as u16).collect();
        let salt = &signature[parameters.saltRange()];
        let commitmentDigest = &signature[parameters.commitmentDigestRange()];
        let secondChallengeDigest = &signature[parameters.secondChallengeDigestRange()];
        let firstChallengeDigest =
            Signer::firstChallengeDigest(parameters, message, commitmentDigest, salt);
        let firstChallenge = sampler.firstChallenge(&firstChallengeDigest);
        let secondChallenge = sampler.secondChallenge(secondChallengeDigest);
        let (seeds, isPathPaddingZero) = SeedTree::rebuilt(
            parameters,
            &secondChallenge,
            &signature[parameters.pathRange()],
            salt,
        );

        let syndromeLength = parameters.syndromeLength();
        let restrictedLength = parameters.restrictedVectorLength();
        let fieldVectorLength = parameters.fieldVectorLength();
        let responseLength = parameters.responseLength();
        let mut commitmentInput = vec![0u8; syndromeLength + restrictedLength + digestLength];
        commitmentInput[syndromeLength + restrictedLength..].copy_from_slice(salt);
        let mut firstCommitments = vec![0u8; roundCount * digestLength];
        let mut secondCommitments = vec![0u8; roundCount * digestLength];
        let mut responses = vec![0u8; roundCount * fieldVectorLength + digestLength];
        let mut isInGroup = true;
        let mut isResponsePaddingZero = true;
        let mut published = signature[parameters.responsesRange()].chunks_exact(responseLength);
        let mut publishedCommitments =
            signature[parameters.commitmentResponsesRange()].chunks_exact(digestLength);
        for round in 0..roundCount {
            let domain = parameters.roundDomain(round);
            let commitmentDomain = HashFunction::hashDomain + domain;
            let commitments = round * digestLength..(round + 1) * digestLength;
            let response = if secondChallenge[round] == 1 {
                // The round reveals its seed: its second commitment and its response y.
                let roundSeed = seeds.roundSeed(round);
                hash.digest(
                    &[roundSeed, salt],
                    commitmentDomain,
                    &mut secondCommitments[commitments],
                );
                let mut reader = hash.reader(&[roundSeed, salt], domain);
                let sampled = sampler.restrictedVector(&mut reader);
                let errorVector = match problem {
                    Problem::rsdp => sampled,
                    Problem::rsdpg => {
                        let mut element = restricted.subgroupElement(&sampled, &matrices.subgroup);
                        restricted.normalize(&mut element);
                        element
                    }
                };
                let mask = sampler.fieldVector(&mut reader);
                let mut response = field.scaledSum(&errorVector, firstChallenge[round], &mask);
                field.normalize(&mut response);
                response
            } else {
                // The round publishes y, its restricted vector and its second commitment. The
                // packed restricted vector enters the first commitment as the signature holds it.
                // The second challenge has t - w zeros, one for each response.
                let packed = published.next().expect("t - w responses");
                let commitment = publishedCommitments.next().expect("t - w commitments");
                let (packedResponse, packedRestricted) = packed.split_at(fieldVectorLength);
                let (responseValues, isResponseZero) =
                    Packing::unpacked(packedResponse, parameters.code.length, fieldBits);
                let (restrictedValues, isRestrictedZero) = Packing::unpacked(
                    packedRestricted,
                    parameters.restrictedExponentCount(),
                    restrictedBits,
                );
                isResponsePaddingZero &= isResponseZero && isRestrictedZero;
                commitmentInput[syndromeLength..syndromeLength + restrictedLength]
                    .copy_from_slice(packedRestricted);
                let exponents: Vec<u8> =
                    restrictedValues.iter().map(|value| *value as u8).collect();
                isInGroup &= restricted.isInRestrictedGroup(&exponents);
                let difference = match problem {
                    Problem::rsdp => exponents,
                    Problem::rsdpg => restricted.subgroupElement(&exponents, &matrices.subgroup),
                };
                secondCommitments[commitments.clone()].copy_from_slice(commitment);
                let response: Vec<u16> = responseValues.iter().map(|value| *value as u16).collect();
                // The commitment syndrome (g^v * y) H^T - c s of the round.
                let product =
                    field.pointwiseProduct(&field.restrictedValues(&difference), &response);
                let mut syndrome = field.syndrome(&product, &matrices.parityCheck);
                field.normalize(&mut syndrome);
                let mut syndrome =
                    field.syndromeDifference(&syndrome, firstChallenge[round], &publicSyndrome);
                field.normalize(&mut syndrome);
                Packing::pack(
                    syndrome.iter().map(|value| u32::from(*value)),
                    fieldBits,
                    &mut commitmentInput[..syndromeLength],
                );
                hash.digest(
                    &[&commitmentInput],
                    commitmentDomain,
                    &mut firstCommitments[commitments],
                );
                response
            };
            Packing::pack(
                response.iter().map(|value| u32::from(*value)),
                fieldBits,
                &mut responses[round * fieldVectorLength..(round + 1) * fieldVectorLength],
            );
        }

        let (root, isProofPaddingZero) = MerkleTree::recomputedRoot(
            parameters,
            &firstCommitments,
            &signature[parameters.proofRange()],
            &secondChallenge,
        );
        let recomputedCommitmentDigest =
            Signer::commitmentDigest(parameters, &root, &secondCommitments);
        responses[roundCount * fieldVectorLength..].copy_from_slice(&firstChallengeDigest);
        let mut recomputedChallengeDigest = vec![0u8; digestLength];
        hash.digest(
            &[&responses],
            HashFunction::hashDomain,
            &mut recomputedChallengeDigest,
        );
        isInGroup
            && recomputedCommitmentDigest == commitmentDigest
            && recomputedChallengeDigest == secondChallengeDigest
            && isProofPaddingZero
            && isPathPaddingZero
            && isKeyPaddingZero
            && isResponsePaddingZero
    }
}

#[cfg(test)]
mod tests {
    use super::Verifier;
    use crate::parameters::{Parameters, allSets};
    use crate::{KeyMaterial, Packing, Problem, Signer};

    const message: &[u8] = b"the quick brown fox";

    /// A public key and a signature of the message, from a secret key, a root seed and a salt of
    /// chosen bytes.
    fn signed(parameters: &Parameters) -> (Vec<u8>, Vec<u8>) {
        let secretKey = vec![0x11; parameters.digestLength()];
        let publicKey = KeyMaterial::expanded(parameters, &secretKey).publicKey(parameters);
        let rootSeed = vec![0x22; parameters.seedLength()];
        let salt = vec![0x33; parameters.digestLength()];
        let signature = Signer::new(parameters).signature(message, &secretKey, &rootSeed, &salt);
        (publicKey, signature)
    }

    fn isValid(parameters: &Parameters, signature: &[u8], publicKey: &[u8]) -> bool {
        Verifier::new(parameters).isValidSignature(signature, message, publicKey)
    }

    /// The number of bits that the values of a packed vector use in its last byte.
    fn usedBitsOfLastByte(count: usize, bits: u32, length: usize) -> usize {
        count * bits as usize - 8 * (length - 1)
    }

    #[test]
    fn aChangeInEachFieldOfASignatureIsRefused() {
        for parameters in allSets {
            let name = parameters.description.name;
            let (publicKey, signature) = signed(parameters);
            assert!(isValid(parameters, &signature, &publicKey), "{name}");
            let responses = parameters.responsesRange().start;
            let positions = [
                parameters.saltRange().start,
                parameters.commitmentDigestRange().start,
                parameters.secondChallengeDigestRange().end - 1,
                parameters.pathRange().start,
                parameters.proofRange().start,
                parameters.commitmentResponsesRange().start,
                responses,
                responses + parameters.fieldVectorLength(),
                signature.len() - 1,
            ];
            for position in positions {
                let mut changed = signature.clone();
                changed[position] ^= 0x01;
                assert!(
                    !isValid(parameters, &changed, &publicKey),
                    "{name}: byte {position}"
                );
            }
        }
    }

    #[test]
    fn aPaddingBitOfAResponseIsRefusedThoughItsValuesStay() {
        for parameters in allSets {
            let name = parameters.description.name;
            let (publicKey, signature) = signed(parameters);
            let fieldBits = parameters.problem().fieldBits();
            let length = parameters.fieldVectorLength();
            let used = usedBitsOfLastByte(parameters.code.length, fieldBits, length);
            assert!(used < 8, "{name} has padding bits after y");
            let last = parameters.responsesRange().start + length - 1;
            let mut changed = signature.clone();
            changed[last] |= 1 << used;
            let start = last + 1 - length;
            let original =
                Packing::unpacked(&signature[start..=last], parameters.code.length, fieldBits);
            let padded =
                Packing::unpacked(&changed[start..=last], parameters.code.length, fieldBits);
            assert_eq!((original.0.clone(), original.1), (padded.0, true), "{name}");
            assert!(!padded.1, "{name}");
            assert!(!isValid(parameters, &changed, &publicKey), "{name}");
        }
    }

    #[test]
    fn aPaddingBitOfThePublicKeyIsRefusedThoughItsSyndromeStays() {
        for parameters in allSets {
            let name = parameters.description.name;
            let (publicKey, signature) = signed(parameters);
            let count = parameters.code.length - parameters.code.dimension;
            let fieldBits = parameters.problem().fieldBits();
            let used = usedBitsOfLastByte(count, fieldBits, parameters.syndromeLength());
            assert!(used < 8, "{name} has padding bits after the syndrome");
            let mut changed = publicKey.clone();
            let last = changed.len() - 1;
            changed[last] |= 0x80;
            let syndrome = &publicKey[parameters.digestLength()..];
            let changedSyndrome = &changed[parameters.digestLength()..];
            assert_eq!(
                Packing::unpacked(syndrome, count, fieldBits).0,
                Packing::unpacked(changedSyndrome, count, fieldBits).0
            );
            assert!(isValid(parameters, &signature, &publicKey), "{name}");
            assert!(!isValid(parameters, &signature, &changed), "{name}");
        }
    }

    #[test]
    fn aPaddingBitOfARestrictedVectorChangesTheCommitment() {
        // The 3-bit check of RSDP accepts any padding, but the first commitment hashes the bytes
        // of the signature, so the root changes. RSDP(G) with m = 25 also refuses the padding bit
        // in its 7-bit check. With m = 40 and m = 48 the vector has no padding.
        let mut checked = 0;
        for parameters in allSets {
            let name = parameters.description.name;
            let count = parameters.restrictedExponentCount();
            let bits = parameters.problem().restrictedBits();
            let length = parameters.restrictedVectorLength();
            let used = usedBitsOfLastByte(count, bits, length);
            if used == 8 {
                continue;
            }
            let (publicKey, signature) = signed(parameters);
            let start = parameters.responsesRange().start + parameters.fieldVectorLength();
            let mut changed = signature.clone();
            changed[start + length - 1] |= 0x80;
            let (values, isAccepted) =
                Packing::unpacked(&changed[start..start + length], count, bits);
            assert_eq!(
                values,
                Packing::unpacked(&signature[start..start + length], count, bits).0
            );
            assert_eq!(isAccepted, parameters.problem() == Problem::rsdp, "{name}");
            assert!(!isValid(parameters, &changed, &publicKey), "{name}");
            checked += 1;
        }
        assert_eq!(checked, 12);
    }

    /// The number of slots of a part of a signature up to its last slot that is not zero.
    fn usedSlots(part: &[u8], slotLength: usize) -> usize {
        part.chunks_exact(slotLength)
            .rposition(|slot| slot.iter().any(|byte| *byte != 0))
            .map_or(0, |last| last + 1)
    }

    #[test]
    fn aByteInTheRoomAfterThePathOrTheProofIsRefused() {
        for parameters in allSets {
            let name = parameters.description.name;
            let (publicKey, signature) = signed(parameters);
            for (range, slotLength) in [
                (parameters.pathRange(), parameters.seedLength()),
                (parameters.proofRange(), parameters.digestLength()),
            ] {
                let used = usedSlots(&signature[range.clone()], slotLength);
                if !parameters.tradeoff.usesTrees() {
                    // A fast set fills its path and its proof.
                    assert_eq!(used, parameters.challengeWeight, "{name}");
                    continue;
                }
                assert!(
                    used < parameters.storedNodeCount,
                    "{name} has room after its nodes"
                );
                for position in [range.start + used * slotLength, range.end - 1] {
                    let mut changed = signature.clone();
                    changed[position] = 0x01;
                    assert!(
                        !isValid(parameters, &changed, &publicKey),
                        "{name}: byte {position}"
                    );
                }
            }
        }
    }
}
