use crate::seedCipher::treeTweak;
use crate::{Parameters, SeedCipher};
use alloc::vec;
use alloc::vec::Vec;

/// The correlated seed tree of one repetition, as `GGMTree_Expand` of `ggm_tree.c` expands it.
///
/// The nodes have the indices of a heap: node 2 is the root seed and node 3 is the root seed
/// plus delta, the first bytes of the secret x. The children of node k are node 2k, its derived
/// seed, and node 2k + 1, the sum of node 2k and node k. The derived seeds of one level use the
/// cipher keyed with `TweakSalt(salt, 2, e, level - 1)`. The nodes N to 2N - 1 are the leaves,
/// so the leaves sum to delta. The nodes 0 and 1 are not used.
pub(crate) struct GGMTree {
    nodes: Vec<u8>,
    seedLength: usize,
    leafCount: usize,
}

impl GGMTree {
    /// The tree of a root seed, a delta and a repetition.
    pub(crate) fn expanded(
        parameters: &Parameters,
        salt: &[u8],
        rootSeed: &[u8],
        delta: &[u8],
        repetition: usize,
    ) -> Self {
        let seedLength = parameters.seedLength();
        let leafCount = parameters.leafCount();
        let mut nodes = vec![0u8; 2 * leafCount * seedLength];
        nodes[2 * seedLength..3 * seedLength].copy_from_slice(rootSeed);
        for (index, (root, part)) in rootSeed.iter().zip(delta).enumerate() {
            nodes[3 * seedLength + index] = root ^ part;
        }
        for level in 1..parameters.treeDepth {
            let cipher = SeedCipher::tweaked(salt, treeTweak, repetition, level - 1);
            let first = 1 << level;
            let parents = nodes[first * seedLength..2 * first * seedLength].to_vec();
            let mut derived = vec![0u8; parents.len()];
            cipher.derive(&parents, &mut derived);
            let children = &mut nodes[2 * first * seedLength..4 * first * seedLength];
            for ((pair, derivedSeed), parent) in children
                .chunks_exact_mut(2 * seedLength)
                .zip(derived.chunks_exact(seedLength))
                .zip(parents.chunks_exact(seedLength))
            {
                let (left, right) = pair.split_at_mut(seedLength);
                left.copy_from_slice(derivedSeed);
                for ((byte, leftByte), parentByte) in right.iter_mut().zip(&*left).zip(parent) {
                    *byte = leftByte ^ parentByte;
                }
            }
        }
        GGMTree {
            nodes,
            seedLength,
            leafCount,
        }
    }

    /// The seed of a node.
    fn node(&self, index: usize) -> &[u8] {
        &self.nodes[index * self.seedLength..(index + 1) * self.seedLength]
    }

    /// The N leaf seeds, one after another.
    pub(crate) fn leaves(&self) -> &[u8] {
        &self.nodes[self.leafCount * self.seedLength..]
    }

    /// The sibling path of a hidden leaf, as `GGMTree_Open` gives it: the sibling of the leaf,
    /// then the sibling of each ancestor up to the level of nodes 2 and 3.
    pub(crate) fn path(&self, hiddenLeaf: usize) -> Vec<u8> {
        let depth = self.leafCount.trailing_zeros() as usize;
        let mut path = Vec::with_capacity(depth * self.seedLength);
        let mut index = self.leafCount + hiddenLeaf;
        while index > 1 {
            path.extend_from_slice(self.node(index ^ 1));
            index /= 2;
        }
        path
    }

    /// The leaves of a tree from the sibling path of a hidden leaf, as
    /// `GGMTree_PartiallyExpand` computes them: every node off the path of the hidden leaf
    /// comes from the path, and the hidden leaf is zero.
    pub(crate) fn partialLeaves(
        parameters: &Parameters,
        salt: &[u8],
        path: &[u8],
        repetition: usize,
        hiddenLeaf: usize,
    ) -> Vec<u8> {
        let seedLength = parameters.seedLength();
        let leafCount = parameters.leafCount();
        let mut nodes = vec![0u8; 2 * leafCount * seedLength];
        let mut isKnown = vec![false; 2 * leafCount];
        let mut index = leafCount + hiddenLeaf;
        for sibling in path.chunks_exact(seedLength) {
            let place = index ^ 1;
            nodes[place * seedLength..(place + 1) * seedLength].copy_from_slice(sibling);
            isKnown[place] = true;
            index /= 2;
        }
        for level in 1..parameters.treeDepth {
            let cipher = SeedCipher::tweaked(salt, treeTweak, repetition, level - 1);
            let first = 1 << level;
            let knownParents: Vec<usize> = (first..2 * first)
                .filter(|parent| isKnown[*parent])
                .collect();
            let mut parents = Vec::with_capacity(knownParents.len() * seedLength);
            for parent in &knownParents {
                parents.extend_from_slice(&nodes[parent * seedLength..(parent + 1) * seedLength]);
            }
            let mut derived = vec![0u8; parents.len()];
            cipher.derive(&parents, &mut derived);
            for ((parent, derivedSeed), parentSeed) in knownParents
                .iter()
                .zip(derived.chunks_exact(seedLength))
                .zip(parents.chunks_exact(seedLength))
            {
                let left = 2 * parent;
                nodes[left * seedLength..(left + 1) * seedLength].copy_from_slice(derivedSeed);
                for (offset, (derivedByte, parentByte)) in
                    derivedSeed.iter().zip(parentSeed).enumerate()
                {
                    nodes[(left + 1) * seedLength + offset] = derivedByte ^ parentByte;
                }
                isKnown[left] = true;
                isKnown[left + 1] = true;
            }
        }
        // No line writes the hidden leaf, so it keeps the zero of `nodes`. Its ancestors are
        // never known: the path holds their siblings, and a child is known only when its
        // parent is. The C code clears the hidden leaf because its array of nodes is not
        // initialized.
        nodes.split_off(leafCount * seedLength)
    }
}

#[cfg(test)]
mod tests {
    use super::GGMTree;
    use crate::parameters::{mqom2Cat1GF16FastR3, mqom2Cat3GF16ShortR3};
    use crate::testInputs::{cAnswer, everySet, sequenceBytes};
    use OQSNativeAlgorithmTests::OutputDigest;

    #[test]
    fn theLeavesSumToDeltaAndThePathGivesEveryOtherLeaf() {
        for parameters in [&mqom2Cat1GF16FastR3, &mqom2Cat3GF16ShortR3] {
            let seedLength = parameters.seedLength();
            let salt: Vec<u8> = (0..seedLength as u8).collect();
            let root: Vec<u8> = (0..seedLength as u8).map(|byte| byte * 7 + 1).collect();
            let delta: Vec<u8> = (0..seedLength as u8).map(|byte| byte ^ 0x5A).collect();
            let tree = GGMTree::expanded(parameters, &salt, &root, &delta, 3);
            let mut sum = vec![0u8; seedLength];
            for leaf in tree.leaves().chunks_exact(seedLength) {
                for (total, byte) in sum.iter_mut().zip(leaf) {
                    *total ^= byte;
                }
            }
            assert_eq!(sum, delta);
            for hiddenLeaf in [0, 1, parameters.leafCount() / 2, parameters.leafCount() - 1] {
                let path = tree.path(hiddenLeaf);
                assert_eq!(path.len(), parameters.treeDepth * seedLength);
                let leaves = GGMTree::partialLeaves(parameters, &salt, &path, 3, hiddenLeaf);
                for (index, (leaf, expected)) in leaves
                    .chunks_exact(seedLength)
                    .zip(tree.leaves().chunks_exact(seedLength))
                    .enumerate()
                {
                    if index == hiddenLeaf {
                        assert!(leaf.iter().all(|byte| *byte == 0));
                    } else {
                        assert_eq!(leaf, expected, "leaf {index} of hidden {hiddenLeaf}");
                    }
                }
                // Another repetition keys other ciphers, so the path gives other leaves.
                let other = GGMTree::partialLeaves(parameters, &salt, &path, 4, hiddenLeaf);
                assert_ne!(other, leaves);
            }
        }
    }

    #[test]
    fn theLeavesThePathAndThePartialLeavesAreThoseOfTheCFunctions() {
        // `GGMTree_Expand` of a seeded salt, root seed and delta for the repetition 3, then
        // `GGMTree_Open` and `GGMTree_PartiallyExpand` for the hidden leaf N / 3.
        for parameters in everySet() {
            let name = parameters.description.name;
            let seedLength = parameters.seedLength();
            let salt = sequenceBytes(seedLength, 6);
            let tree = GGMTree::expanded(
                parameters,
                &salt,
                &sequenceBytes(seedLength, 7),
                &sequenceBytes(seedLength, 8),
                3,
            );
            assert_eq!(
                OutputDigest::of(tree.leaves()),
                cAnswer(name, "treeLeaves"),
                "{name}"
            );
            let hiddenLeaf = parameters.leafCount() / 3;
            let path = tree.path(hiddenLeaf);
            assert_eq!(OutputDigest::of(&path), cAnswer(name, "treePath"), "{name}");
            let leaves = GGMTree::partialLeaves(parameters, &salt, &path, 3, hiddenLeaf);
            assert_eq!(
                OutputDigest::of(&leaves),
                cAnswer(name, "partialLeaves"),
                "{name}"
            );
        }
    }
}
