use crate::{HashFunction, Parameters};
use alloc::vec;
use alloc::vec::Vec;

/// The commitments of the rounds of a signature, from `merkle.c`.
///
/// The balanced and the small sets hash the first commitments of the rounds into a Merkle tree
/// of the shape of `TreeLayout`. A signature holds the proof: the fewest nodes from which a
/// verifier, who recomputes the commitments of the rounds that publish a response, gets the
/// root. The fast sets hash the commitments in 4 quarters and then the 4 digests, and a
/// signature lists the commitment of each round that reveals its seed.
pub(crate) struct MerkleTree<'parameters> {
    parameters: &'parameters Parameters,
    /// The digests of the nodes of the tree, or the commitments of the rounds of a fast set.
    nodes: Vec<u8>,
}

impl<'parameters> MerkleTree<'parameters> {
    /// The tree of the commitments of the rounds, `tree_root` without its copy of the root.
    pub(crate) fn built(parameters: &'parameters Parameters, commitments: &[u8]) -> Self {
        if !parameters.tradeoff.usesTrees() {
            return MerkleTree {
                parameters,
                nodes: commitments.to_vec(),
            };
        }
        let digestLength = parameters.digestLength();
        let layout = &parameters.treeLayout;
        let mut nodes = Self::leafNodes(parameters, commitments);
        let hash = parameters.hashFunction();
        for level in (1..=layout.depth).rev() {
            for pair in (0..layout.nodeCountOfLevel(level) / 2).rev() {
                let node = layout.levelStart(level) + 2 * pair;
                let parent = layout.parent(node, level);
                let (parents, children) = nodes.split_at_mut(node * digestLength);
                hash.digest(
                    &[&children[..2 * digestLength]],
                    HashFunction::hashDomain,
                    &mut parents[parent * digestLength..(parent + 1) * digestLength],
                );
            }
        }
        MerkleTree { parameters, nodes }
    }

    /// The nodes of a tree with the commitments of the rounds on its leaves, `place_cmt_on_leaves`,
    /// and zeros elsewhere.
    fn leafNodes(parameters: &Parameters, commitments: &[u8]) -> Vec<u8> {
        let digestLength = parameters.digestLength();
        let layout = &parameters.treeLayout;
        let mut nodes = vec![0u8; layout.nodeCount() * digestLength];
        for (leaf, commitment) in layout
            .leafNodes()
            .zip(commitments.chunks_exact(digestLength))
        {
            nodes[leaf * digestLength..(leaf + 1) * digestLength].copy_from_slice(commitment);
        }
        nodes
    }

    /// The root, the first digest of the pair that the digest of the commitments hashes.
    pub(crate) fn root(&self) -> Vec<u8> {
        let digestLength = self.parameters.digestLength();
        if self.parameters.tradeoff.usesTrees() {
            self.nodes[..digestLength].to_vec()
        } else {
            Self::quarterRoot(self.parameters, &self.nodes)
        }
    }

    /// The root of the commitments of a fast set, `tree_root` of `NO_TREES`: the hash of the
    /// digests of the 4 quarters of the commitments. The first `t mod 4` quarters have one
    /// commitment more.
    fn quarterRoot(parameters: &Parameters, commitments: &[u8]) -> Vec<u8> {
        let digestLength = parameters.digestLength();
        let roundCount = parameters.roundCount;
        let hash = parameters.hashFunction();
        let mut quarterDigests = vec![0u8; 4 * digestLength];
        let mut start = 0;
        for (quarter, digest) in quarterDigests.chunks_exact_mut(digestLength).enumerate() {
            let count = roundCount / 4 + usize::from(roundCount % 4 > quarter);
            let end = start + count * digestLength;
            hash.digest(
                &[&commitments[start..end]],
                HashFunction::hashDomain,
                digest,
            );
            start = end;
        }
        let mut root = vec![0u8; digestLength];
        hash.digest(&[&quarterDigests], HashFunction::hashDomain, &mut root);
        root
    }

    /// The marks of the leaves whose commitment a verifier computes, the rounds whose second
    /// challenge bit is zero, `label_leaves`.
    fn computedLeaves(parameters: &Parameters, challenge: &[u8]) -> Vec<bool> {
        let layout = &parameters.treeLayout;
        let mut isComputed = vec![false; layout.nodeCount()];
        for (leaf, bit) in layout.leafNodes().zip(challenge) {
            isComputed[leaf] = *bit == 0;
        }
        isComputed
    }

    /// Writes the proof to the zeroed proof of a signature, `tree_proof`: from the deepest level
    /// up and from right to left, the node of each pair of children of which the verifier
    /// computes only the other. A fast set lists the commitment of each round whose challenge
    /// bit is one.
    pub(crate) fn writeProof(&self, challenge: &[u8], proof: &mut [u8]) {
        let parameters = self.parameters;
        let digestLength = parameters.digestLength();
        let mut published = proof.chunks_exact_mut(digestLength);
        if !parameters.tradeoff.usesTrees() {
            for (commitment, bit) in self.nodes.chunks_exact(digestLength).zip(challenge) {
                if *bit == 1 {
                    published
                        .next()
                        .expect("room for w commitments")
                        .copy_from_slice(commitment);
                }
            }
            return;
        }
        let layout = &parameters.treeLayout;
        let mut isComputed = Self::computedLeaves(parameters, challenge);
        let node = |index: usize| &self.nodes[index * digestLength..(index + 1) * digestLength];
        for level in (1..=layout.depth).rev() {
            for pair in (0..layout.nodeCountOfLevel(level) / 2).rev() {
                let left = layout.levelStart(level) + 2 * pair;
                let right = left + 1;
                isComputed[layout.parent(left, level)] = isComputed[left] || isComputed[right];
                let revealed = match (isComputed[left], isComputed[right]) {
                    (false, true) => left,
                    (true, false) => right,
                    _ => continue,
                };
                published
                    .next()
                    .expect("room for the longest proof")
                    .copy_from_slice(node(revealed));
            }
        }
    }

    /// The root of the commitments that a verifier computes and of a proof, and true when the
    /// bytes of the proof after its last digest are zero, `recompute_root`. The commitments of the
    /// rounds that reveal their seed are zero in the input. A fast set takes those commitments
    /// from the proof, which has no room left.
    pub(crate) fn recomputedRoot(
        parameters: &Parameters,
        commitments: &[u8],
        proof: &[u8],
        challenge: &[u8],
    ) -> (Vec<u8>, bool) {
        let digestLength = parameters.digestLength();
        let mut stored = proof.chunks_exact(digestLength);
        if !parameters.tradeoff.usesTrees() {
            let mut leaves = commitments.to_vec();
            for (leaf, bit) in leaves.chunks_exact_mut(digestLength).zip(challenge) {
                if *bit == 1 {
                    leaf.copy_from_slice(stored.next().expect("w commitments"));
                }
            }
            return (Self::quarterRoot(parameters, &leaves), true);
        }
        let layout = &parameters.treeLayout;
        let hash = parameters.hashFunction();
        let mut nodes = Self::leafNodes(parameters, commitments);
        let mut isComputed = Self::computedLeaves(parameters, challenge);
        let mut usedLength = 0;
        let mut pairInput = vec![0u8; 2 * digestLength];
        for level in (1..=layout.depth).rev() {
            for pair in (0..layout.nodeCountOfLevel(level) / 2).rev() {
                let left = layout.levelStart(level) + 2 * pair;
                if !isComputed[left] && !isComputed[left + 1] {
                    continue;
                }
                for (child, half) in [left, left + 1]
                    .into_iter()
                    .zip(pairInput.chunks_exact_mut(digestLength))
                {
                    if isComputed[child] {
                        half.copy_from_slice(
                            &nodes[child * digestLength..(child + 1) * digestLength],
                        );
                    } else {
                        half.copy_from_slice(stored.next().expect("the longest proof"));
                        usedLength += digestLength;
                    }
                }
                let parent = layout.parent(left, level);
                hash.digest(
                    &[&pairInput],
                    HashFunction::hashDomain,
                    &mut nodes[parent * digestLength..(parent + 1) * digestLength],
                );
                isComputed[parent] = true;
            }
        }
        // The rest of the proof must be zero, or a forger could hide bytes in it.
        let isPaddingZero = proof[usedLength..].iter().all(|byte| *byte == 0);
        (nodes[..digestLength].to_vec(), isPaddingZero)
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;
    use crate::Sampler;
    use crate::parameters::{Parameters, allSets, crossRSDPG192Balanced};
    use crate::testInputs::{SeededSequence, hexadecimal};
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The second challenge of the known answers: the expansion of the digest of seed 3.
    fn challenge(parameters: &Parameters) -> Vec<u8> {
        let digest = SeededSequence::new(3).bytes(parameters.digestLength());
        Sampler::new(parameters).secondChallenge(&digest)
    }

    /// The commitments of the known answers, the bytes of seed 4, and the same commitments with
    /// zeros for the rounds that reveal their seed, as a verifier has them.
    fn commitments(parameters: &Parameters, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let digestLength = parameters.digestLength();
        let all = SeededSequence::new(4).bytes(parameters.roundCount * digestLength);
        let mut computed = all.clone();
        for (commitment, bit) in computed.chunks_exact_mut(digestLength).zip(challenge) {
            if *bit == 1 {
                commitment.fill(0);
            }
        }
        (all, computed)
    }

    #[test]
    fn theRootsAndTheProofsAreThoseOfTheCCode() {
        // `tree_root`, `tree_proof` and `recompute_root`, or the functions of `NO_TREES`, of each
        // set of the oracle library. Each row gives the first 16 bytes of the root, the number
        // of digests of the proof and the digest of the proof.
        let expected: [(&str, usize, &str); 18] = [
            (
                "d71effeeffb3b76f52451b0f6df52c72",
                86,
                "16a61260cd8e168bbca3a7939e4e15eef1f12856db84f38300d5b61274787d66",
            ),
            (
                "b4e82b91e8946df4fcd62ffb92b0ff6d",
                82,
                "2e60cf353ee9d5089a7c050c862cf5f3a5e0e270d161da4c5abb96cbc573c8b5",
            ),
            (
                "9bf9ef16d8dba4e003a472f6e53491bc",
                106,
                "932c98cff523fa7166975ee9656bf0b28da74003b044fbb87f59567eba48aea6",
            ),
            (
                "de2e296138f4c28de0005d0d718e64d8",
                137,
                "d54a9e9a02bdbda17e0ecf9f2a86416c715ca1cfdf18ecfb601349b04dad75c1",
            ),
            (
                "03b32de69f759a4d0e950c3773b0fd72",
                125,
                "7311ce2038b4c55b802b9968c31a844ca0ec3b914d7be5be219bb66ef272af3b",
            ),
            (
                "6073ae95aa2bc499d35ad783fbcd9929",
                145,
                "d998ffbde36a0e8b9f2ba04657a6be6662826461fa5b03675f31798fd0062766",
            ),
            (
                "09a8e0c9ffe069fe95c5c2f1d1f098b4",
                175,
                "532d9bcbc020f97c679f077b7527c47c6ce58babdb516cbce819c5db984ce4e6",
            ),
            (
                "f565c5fe0376c3ee335fdde2d734f998",
                167,
                "02bb85abe61199a308deb93b860731d5fad98c483551c72936b5d743b09037a6",
            ),
            (
                "82d50a3946778aacc444995dcc6242eb",
                206,
                "a34d3e6f2d3db4970f92f71a8f699195aa57d1a007dbf9f3d80806c4f92b8cfe",
            ),
            (
                "d71effeeffb3b76f52451b0f6df52c72",
                79,
                "78a1f56d809729eaa7f20b69d22117818b5e7b75d6a21aa3c1f7133a0bff7e70",
            ),
            (
                "8c549d66b85d7a3d4572e2d8b459d97a",
                76,
                "8f63998218b9790bc90d4ac1a8934634a9f2beb0b2ba73f26c7021ab708acc98",
            ),
            (
                "85d495a6b2e3a5fcfd0f01fefa3faddc",
                100,
                "d07bb8c7760e84c884e0e717bb10c99d5afe6a11cc65bf801561619b3f179080",
            ),
            (
                "74c1588fa286a72eace7204abe11f581",
                100,
                "0e777925aa8c5d2ec2f8ae315160dc068adfdd9b8816144746bd1c58af0a380a",
            ),
            (
                "256cdc573e63c95b1fac0f7ffc188fa9",
                119,
                "9949d0503827ad8d452cd61b68d73a72f526b473ae9268bf02130c81b99e298b",
            ),
            (
                "f85096557134f2aab624da578f78116e",
                126,
                "b83f5522771cf92e2147cb2b0e04c2b6b610fd8ecff68a6d85b9c4ff514364e8",
            ),
            (
                "d485c32b85f22a6f1b4c296e6c4d7784",
                131,
                "59e6b514084862beea23c71c2532d13656f537103eaae9a6ffd8a66b58d74944",
            ),
            (
                "0b624cbbfc826096733a1c05037feaef",
                153,
                "84d0d7d93244a8be05ff5a33888a07b539cc005ea5150b36b3b83e20e542a891",
            ),
            (
                "3baec1c789761a71db3193dec5a248b5",
                178,
                "8cc0404398e38ca96711b66c71c030d7dd96ebac6918a8afe9dd0b0aa86790f0",
            ),
        ];
        for (parameters, (root, proofCount, proofDigest)) in allSets.iter().zip(expected) {
            let name = parameters.description.name;
            let digestLength = parameters.digestLength();
            let challenge = challenge(parameters);
            let (all, computed) = commitments(parameters, &challenge);
            let tree = MerkleTree::built(parameters, &all);
            assert_eq!(hexadecimal(&tree.root()[..16]), root, "{name}");
            let mut proof = vec![0u8; parameters.storedNodeCount * digestLength];
            tree.writeProof(&challenge, &mut proof);
            assert_eq!(OutputDigest::of(&proof), proofDigest, "{name}");
            assert!(
                proof[proofCount * digestLength..]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            let (recomputed, isPaddingZero) =
                MerkleTree::recomputedRoot(parameters, &computed, &proof, &challenge);
            assert_eq!(recomputed, tree.root(), "{name}");
            assert!(isPaddingZero, "{name}");
        }
    }

    #[test]
    fn eachByteOfThePaddingOfTheProofIsCheckedAndEachDigestIsUsed() {
        let parameters = &crossRSDPG192Balanced;
        let digestLength = parameters.digestLength();
        let challenge = challenge(parameters);
        let (all, computed) = commitments(parameters, &challenge);
        let tree = MerkleTree::built(parameters, &all);
        let mut proof = vec![0u8; parameters.storedNodeCount * digestLength];
        tree.writeProof(&challenge, &mut proof);
        // The C code gives 100 digests of the 138 that the proof holds.
        let used = 100 * digestLength;
        for position in [used, used + 1, proof.len() - 1] {
            let mut changed = proof.clone();
            changed[position] = 0x01;
            let (root, isPaddingZero) =
                MerkleTree::recomputedRoot(parameters, &computed, &changed, &challenge);
            assert!(!isPaddingZero, "byte {position}");
            assert_eq!(root, tree.root());
        }
        for position in [0, used / 2, used - 1] {
            let mut changed = proof.clone();
            changed[position] ^= 0x80;
            let (root, isPaddingZero) =
                MerkleTree::recomputedRoot(parameters, &computed, &changed, &challenge);
            assert!(isPaddingZero);
            assert_ne!(root, tree.root(), "byte {position}");
        }
        // A changed commitment of a round that publishes its response changes the root.
        let round = challenge.iter().position(|bit| *bit == 0).expect("a round");
        let mut changedCommitments = computed.clone();
        changedCommitments[round * digestLength] ^= 1;
        let (root, _) =
            MerkleTree::recomputedRoot(parameters, &changedCommitments, &proof, &challenge);
        assert_ne!(root, tree.root());
    }
}
