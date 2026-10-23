/// The deepest level of a tree: `LOG2(T)` of the largest set, with 832 rounds, is 10.
const maximumDepth: usize = 10;

/// The shape of the seed tree and of the Merkle tree of a set with t leaves: the derived
/// parameters `TREE_*` of its `parameters.h`.
///
/// The tree has one full subtree for each binary digit of t, the largest on the left. The
/// subtrees hang on a chain of right children from the root, and the last two share the last
/// node of the chain. So the leaves of a level come after its internal nodes, and the deeper
/// subtrees come first. The nodes are numbered level by level from the root, and from left to
/// right within a level. The leaves of the rounds are the leaves in that order, deepest level
/// first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TreeLayout {
    /// The level of the deepest leaves, `LOG2(T)`.
    pub(crate) depth: usize,
    /// The number of nodes of each level, `TREE_NODES_PER_LEVEL`.
    nodesPerLevel: [usize; maximumDepth + 1],
    /// The number of leaves of each level, `TREE_LEAVES_PER_LEVEL`.
    leavesPerLevel: [usize; maximumDepth + 1],
    /// The index of the first node of each level, and the number of nodes at the end.
    levelStarts: [usize; maximumDepth + 2],
    /// The first node of each run of leaves on one level, deepest level first,
    /// `TREE_LEAVES_START_INDICES`.
    leafRunStarts: [usize; maximumDepth + 1],
    /// The number of leaves of each run, `TREE_CONSECUTIVE_LEAVES`.
    leafRunLengths: [usize; maximumDepth + 1],
    /// The number of runs, `TREE_SUBROOTS`.
    leafRunCount: usize,
}

impl TreeLayout {
    /// The layout of a tree with a number of leaves, at most 2^10.
    pub(crate) const fn new(leafCount: usize) -> Self {
        let digitCount = leafCount.count_ones() as usize;
        let mut leavesPerLevel = [0; maximumDepth + 1];
        let mut depth = 0;
        let mut subtree = 0;
        let mut bit = usize::BITS as usize;
        while bit > 0 {
            bit -= 1;
            if (leafCount >> bit) & 1 == 1 {
                subtree += 1;
                // Subtree j hangs at the level j of the chain, and the last subtree is the
                // sibling of the one before it.
                let rootLevel = if subtree < digitCount {
                    subtree
                } else {
                    digitCount - 1
                };
                let leafLevel = rootLevel + bit;
                leavesPerLevel[leafLevel] += 1 << bit;
                if leafLevel > depth {
                    depth = leafLevel;
                }
            }
        }
        let mut nodesPerLevel = [0; maximumDepth + 1];
        nodesPerLevel[0] = 1;
        let mut level = 0;
        while level < depth {
            nodesPerLevel[level + 1] = 2 * (nodesPerLevel[level] - leavesPerLevel[level]);
            level += 1;
        }
        let mut levelStarts = [0; maximumDepth + 2];
        level = 0;
        while level <= depth {
            levelStarts[level + 1] = levelStarts[level] + nodesPerLevel[level];
            level += 1;
        }
        let mut leafRunStarts = [0; maximumDepth + 1];
        let mut leafRunLengths = [0; maximumDepth + 1];
        let mut leafRunCount = 0;
        level = depth + 1;
        while level > 0 {
            level -= 1;
            if leavesPerLevel[level] > 0 {
                leafRunStarts[leafRunCount] =
                    levelStarts[level] + nodesPerLevel[level] - leavesPerLevel[level];
                leafRunLengths[leafRunCount] = leavesPerLevel[level];
                leafRunCount += 1;
            }
        }
        TreeLayout {
            depth,
            nodesPerLevel,
            leavesPerLevel,
            levelStarts,
            leafRunStarts,
            leafRunLengths,
            leafRunCount,
        }
    }

    /// The number of nodes of the tree, `2 t - 1`.
    pub(crate) const fn nodeCount(&self) -> usize {
        self.levelStarts[self.depth + 1]
    }

    /// The number of nodes of a level.
    pub(crate) const fn nodeCountOfLevel(&self, level: usize) -> usize {
        self.nodesPerLevel[level]
    }

    /// The number of nodes of a level that have children: the nodes before its leaves.
    pub(crate) const fn internalNodeCountOfLevel(&self, level: usize) -> usize {
        self.nodesPerLevel[level] - self.leavesPerLevel[level]
    }

    /// The index of the first node of a level.
    pub(crate) const fn levelStart(&self, level: usize) -> usize {
        self.levelStarts[level]
    }

    /// The shift between the index of a node of a level and the index that its left child would
    /// have in a complete tree, `TREE_OFFSETS`.
    pub(crate) const fn offset(&self, level: usize) -> usize {
        2 * self.levelStarts[level] + 1 - self.levelStarts[level + 1]
    }

    /// The left child of an internal node of a level, `LEFT_CHILD(i) - off[level]`. The right
    /// child follows it.
    pub(crate) const fn leftChild(&self, node: usize, level: usize) -> usize {
        2 * node + 1 - self.offset(level)
    }

    /// The parent of a node of a level below the root, `PARENT(i) + (off[level - 1] >> 1)`.
    ///
    /// `PARENT` of the C code gives `(i - 1) / 2` for an odd index and `(i - 2) / 2` for an even
    /// one, which is `(i - 1) / 2` rounded down in both cases.
    pub(crate) const fn parent(&self, node: usize, level: usize) -> usize {
        (node - 1) / 2 + self.offset(level - 1) / 2
    }

    /// The leaf nodes in the order of the rounds: the runs of `TREE_LEAVES_START_INDICES`, each
    /// from left to right.
    pub(crate) fn leafNodes(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.leafRunCount).flat_map(|run| {
            self.leafRunStarts[run]..self.leafRunStarts[run] + self.leafRunLengths[run]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::TreeLayout;

    /// The derived tree parameters of the `parameters.h` of a set: the round count, then
    /// `TREE_OFFSETS`, `TREE_NODES_PER_LEVEL`, `TREE_LEAVES_PER_LEVEL`,
    /// `TREE_LEAVES_START_INDICES` and `TREE_CONSECUTIVE_LEAVES`.
    type HeaderTree = (
        usize,
        &'static [usize],
        &'static [usize],
        &'static [usize],
        &'static [usize],
        &'static [usize],
    );

    /// The values of the C headers of the 18 sets, in the order of liboqs.
    const headerTrees: [HeaderTree; 18] = [
        (
            256,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[1, 2, 4, 8, 16, 32, 64, 128, 256],
            &[0, 0, 0, 0, 0, 0, 0, 0, 256],
            &[255],
            &[256],
        ),
        (
            157,
            &[0, 0, 0, 0, 0, 2, 2, 58, 58],
            &[1, 2, 4, 8, 16, 30, 60, 64, 128],
            &[0, 0, 0, 0, 1, 0, 28, 0, 128],
            &[185, 93, 30],
            &[128, 28, 1],
        ),
        (
            520,
            &[0, 0, 0, 0, 0, 16, 16, 16, 16, 16, 16],
            &[1, 2, 4, 8, 16, 16, 32, 64, 128, 256, 512],
            &[0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 512],
            &[527, 23],
            &[512, 8],
        ),
        (
            384,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 256],
            &[1, 2, 4, 8, 16, 32, 64, 128, 256, 256],
            &[0, 0, 0, 0, 0, 0, 0, 0, 128, 256],
            &[511, 383],
            &[256, 128],
        ),
        (
            239,
            &[0, 0, 0, 0, 0, 0, 0, 2, 30],
            &[1, 2, 4, 8, 16, 32, 64, 126, 224],
            &[0, 0, 0, 0, 0, 0, 1, 14, 224],
            &[253, 239, 126],
            &[224, 14, 1],
        ),
        (
            580,
            &[0, 0, 0, 0, 0, 8, 8, 8, 8, 136, 136],
            &[1, 2, 4, 8, 16, 24, 48, 96, 192, 256, 512],
            &[0, 0, 0, 0, 4, 0, 0, 0, 64, 0, 512],
            &[647, 327, 27],
            &[512, 64, 4],
        ),
        (
            512,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 512],
            &[511],
            &[512],
        ),
        (
            321,
            &[0, 0, 0, 2, 2, 2, 2, 2, 2, 130],
            &[1, 2, 4, 6, 12, 24, 48, 96, 192, 256],
            &[0, 0, 1, 0, 0, 0, 0, 0, 64, 256],
            &[385, 321, 6],
            &[256, 64, 1],
        ),
        (
            832,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 128],
            &[1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 768],
            &[0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 768],
            &[895, 447],
            &[768, 64],
        ),
        (
            256,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[1, 2, 4, 8, 16, 32, 64, 128, 256],
            &[0, 0, 0, 0, 0, 0, 0, 0, 256],
            &[255],
            &[256],
        ),
        (
            147,
            &[0, 0, 0, 0, 2, 6, 6, 38, 38],
            &[1, 2, 4, 8, 14, 24, 48, 64, 128],
            &[0, 0, 0, 1, 2, 0, 16, 0, 128],
            &[165, 85, 27, 14],
            &[128, 16, 2, 1],
        ),
        (
            512,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 512],
            &[511],
            &[512],
        ),
        (
            268,
            &[0, 0, 0, 0, 0, 8, 24, 24, 24, 24],
            &[1, 2, 4, 8, 16, 24, 32, 64, 128, 256],
            &[0, 0, 0, 0, 4, 8, 0, 0, 0, 256],
            &[279, 47, 27],
            &[256, 8, 4],
        ),
        (
            224,
            &[0, 0, 0, 0, 0, 0, 0, 0, 64],
            &[1, 2, 4, 8, 16, 32, 64, 128, 192],
            &[0, 0, 0, 0, 0, 0, 0, 32, 192],
            &[255, 223],
            &[192, 32],
        ),
        (
            512,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 512],
            &[511],
            &[512],
        ),
        (
            356,
            &[0, 0, 0, 0, 0, 0, 8, 8, 8, 200],
            &[1, 2, 4, 8, 16, 32, 56, 112, 224, 256],
            &[0, 0, 0, 0, 0, 4, 0, 0, 96, 256],
            &[455, 359, 59],
            &[256, 96, 4],
        ),
        (
            300,
            &[0, 0, 0, 0, 0, 0, 8, 24, 88, 88],
            &[1, 2, 4, 8, 16, 32, 56, 96, 128, 256],
            &[0, 0, 0, 0, 0, 4, 8, 32, 0, 256],
            &[343, 183, 111, 59],
            &[256, 32, 8, 4],
        ),
        (
            642,
            &[0, 0, 0, 0, 4, 4, 4, 4, 4, 4, 260],
            &[1, 2, 4, 8, 12, 24, 48, 96, 192, 384, 512],
            &[0, 0, 0, 2, 0, 0, 0, 0, 0, 128, 512],
            &[771, 643, 13],
            &[512, 128, 2],
        ),
    ];

    #[test]
    fn eachLayoutHasTheDerivedTreeParametersOfTheCHeaders() {
        for (leafCount, offsets, nodes, leaves, runStarts, runLengths) in headerTrees {
            let layout = TreeLayout::new(leafCount);
            let levels = 0..=layout.depth;
            assert_eq!(layout.depth + 1, offsets.len(), "{leafCount}");
            let derivedOffsets: Vec<usize> = levels.clone().map(|l| layout.offset(l)).collect();
            assert_eq!(derivedOffsets, offsets, "{leafCount}");
            assert_eq!(&layout.nodesPerLevel[..=layout.depth], nodes, "{leafCount}");
            assert_eq!(
                &layout.leavesPerLevel[..=layout.depth],
                leaves,
                "{leafCount}"
            );
            assert_eq!(
                &layout.leafRunStarts[..layout.leafRunCount],
                runStarts,
                "{leafCount}"
            );
            assert_eq!(
                &layout.leafRunLengths[..layout.leafRunCount],
                runLengths,
                "{leafCount}"
            );
            assert_eq!(layout.nodeCount(), 2 * leafCount - 1, "{leafCount}");
            assert_eq!(layout.leafNodes().count(), leafCount, "{leafCount}");
        }
    }

    #[test]
    fn theDepthIsTheLog2OfTheCHeaders() {
        // LOG2 of `parameters.h` rounds up: 9 for 384 and 8 for 256.
        for (leafCount, depth) in [(256, 8), (257, 9), (384, 9), (512, 9), (520, 10), (832, 10)] {
            assert_eq!(TreeLayout::new(leafCount).depth, depth, "{leafCount}");
        }
    }

    #[test]
    fn childrenAndParentsFollowTheNumberingOfEachLevel() {
        for (leafCount, ..) in headerTrees {
            let layout = TreeLayout::new(leafCount);
            for level in 0..layout.depth {
                let start = layout.levelStart(level);
                let childStart = layout.levelStart(level + 1);
                for position in 0..layout.internalNodeCountOfLevel(level) {
                    let node = start + position;
                    // The children of the internal node of position q are the nodes of
                    // positions 2q and 2q + 1 of the next level.
                    let left = layout.leftChild(node, level);
                    assert_eq!(left, childStart + 2 * position, "{leafCount}");
                    assert_eq!(layout.parent(left, level + 1), node, "{leafCount}");
                    assert_eq!(layout.parent(left + 1, level + 1), node, "{leafCount}");
                }
                assert_eq!(
                    layout.nodeCountOfLevel(level + 1),
                    2 * layout.internalNodeCountOfLevel(level)
                );
            }
        }
    }

    #[test]
    fn theLeavesOfTheRoundsAreTheRunsDeepestFirst() {
        let layout = TreeLayout::new(520);
        let leaves: Vec<usize> = layout.leafNodes().collect();
        assert_eq!(leaves[0], 527);
        assert_eq!(leaves[511], 527 + 511);
        assert_eq!(leaves[512], 23);
        assert_eq!(leaves[519], 30);
        let layout = TreeLayout::new(147);
        let leaves: Vec<usize> = layout.leafNodes().collect();
        assert_eq!(
            &leaves[126..],
            &[
                291, 292, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 27, 28,
                14
            ]
        );
    }
}
