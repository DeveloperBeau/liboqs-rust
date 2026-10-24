use crate::parameters::hashLength;
use crate::treeBuilder::SubtreeNodes;
use crate::{LevelType, MerkleTree, TreeBuilder};
use alloc::vec::Vec;

/// The height of the subtrees at the bottom of a tree that a state keeps in full: the whole
/// tree up to a height of 10, and subtrees of height 10 in a taller tree.
const largestSubtreeHeight: u32 = 10;

/// One tree of a working key at the leaf that signs next, with the nodes of its authentication
/// paths.
///
/// The tree is split into a top part and subtrees of height k at its bottom. The state keeps
/// the top part, the subtree of the current leaf and the next subtree in full, and builds the
/// subtree after that one leaf for each signature. So every authentication path is at hand,
/// and each signature costs the work of one leaf, as the subtrees of hash-sigs do.
#[derive(Clone, Debug)]
pub(crate) struct TreeState {
    tree: MerkleTree,
    index: u32,
    subtreeHeight: u32,
    top: Vec<[u8; hashLength]>,
    current: SubtreeNodes,
    next: Option<SubtreeNodes>,
    building: Option<TreeBuilder>,
}

impl TreeState {
    /// The height k of the bottom subtrees of a tree of a height.
    pub(crate) fn subtreeHeight(treeHeight: u32) -> u32 {
        treeHeight.min(largestSubtreeHeight)
    }

    /// A builder of a whole tree that keeps the nodes of a state at a leaf.
    pub(crate) fn builder(tree: MerkleTree, index: u32, subtreeHeight: u32) -> TreeBuilder {
        let height = tree.height();
        let subtreeCount = 1 << (height - subtreeHeight);
        let first = index >> subtreeHeight;
        let kept: Vec<u32> = (first..first + 3)
            .filter(|subtree| *subtree < subtreeCount)
            .collect();
        TreeBuilder::wholeTree(
            tree,
            1 << (height - subtreeHeight + 1),
            subtreeHeight,
            &kept,
        )
    }

    /// The state of a tree at a leaf, from every leaf of the tree, as `hss_generate_working_key`
    /// builds the subtrees of a level.
    pub(crate) fn computed(tree: MerkleTree, index: u32, subtreeHeight: u32) -> TreeState {
        let mut builder = Self::builder(tree, index, subtreeHeight);
        builder.complete();
        Self::ofCompleteBuilder(builder, index, subtreeHeight)
    }

    /// The state at a leaf of a complete builder of `builder` for that leaf.
    pub(crate) fn ofCompleteBuilder(
        mut builder: TreeBuilder,
        index: u32,
        subtreeHeight: u32,
    ) -> TreeState {
        debug_assert!(builder.isComplete());
        let first = index >> subtreeHeight;
        let current = builder
            .takeSubtree(first)
            .expect("the builder keeps the subtree of the leaf");
        let next = builder.takeSubtree(first + 1);
        let following = builder.takeSubtree(first + 2);
        let tree = builder.tree().clone();
        let building = following.map(|nodes| {
            TreeBuilder::completedSubtree(tree.clone(), subtreeHeight, first + 2, nodes)
        });
        TreeState {
            top: builder.takeTop(),
            tree,
            index,
            subtreeHeight,
            current,
            next,
            building,
        }
    }

    /// The tree of the state.
    pub(crate) fn tree(&self) -> &MerkleTree {
        &self.tree
    }

    /// The leaf that signs next.
    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    /// True when every leaf of the tree has signed.
    pub(crate) fn isExhausted(&self) -> bool {
        self.index == self.tree.leafCount()
    }

    /// The root of the tree.
    pub(crate) fn root(&self) -> &[u8; hashLength] {
        &self.top[1]
    }

    /// The LMS public key of the tree.
    pub(crate) fn publicKey(&self) -> [u8; LevelType::publicKeyLength] {
        self.tree.publicKey(self.root())
    }

    /// The authentication path of the current leaf, RFC 8554, Section 5.4.1: the sibling of
    /// each node on the way from the leaf to the root.
    pub(crate) fn authenticationPath(&self) -> Vec<[u8; hashLength]> {
        let height = self.tree.height();
        let leaf = self.tree.leafCount() + self.index;
        (0..height)
            .map(|level| {
                let sibling = (leaf >> level) ^ 1;
                if level < self.subtreeHeight {
                    let depth = self.subtreeHeight - level;
                    // The low bits below `1 << depth` cannot meet its one bit, so the join
                    // adds them.
                    let place = (1 << depth) + (sibling & ((1 << depth) - 1));
                    self.current[place as usize]
                } else {
                    self.top[sibling as usize]
                }
            })
            .collect()
    }

    /// Appends the LMS signature of a message with the current leaf.
    pub(crate) fn appendSignature(&self, message: &[u8], signature: &mut Vec<u8>) {
        debug_assert!(!self.isExhausted());
        self.tree
            .appendSignature(self.index, message, &self.authenticationPath(), signature);
    }

    /// Moves to the next leaf. The subtree in building gets one more leaf, and when the
    /// authentication path enters the next subtree, the subtrees move up by one.
    pub(crate) fn advance(&mut self) {
        debug_assert!(!self.isExhausted());
        if let Some(building) = &mut self.building {
            building.step();
        }
        self.index += 1;
        let subtreeLeafCount = 1 << self.subtreeHeight;
        if self.isExhausted() || !self.index.is_multiple_of(subtreeLeafCount) {
            return;
        }
        self.current = self
            .next
            .take()
            .expect("a next subtree before the last subtree");
        self.next = self.building.take().map(|mut building| {
            // The subtree in building has one leaf for each signature of the current subtree,
            // so it is complete here unless the state started in the middle of it.
            building.complete();
            building
                .takeSubtree(self.index / subtreeLeafCount + 1)
                .expect("the subtree of the builder")
        });
        let following = self.index / subtreeLeafCount + 2;
        let subtreeCount = self.tree.leafCount() / subtreeLeafCount;
        if following < subtreeCount {
            self.building = Some(TreeBuilder::subtree(
                self.tree.clone(),
                self.subtreeHeight,
                following,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TreeState;
    use crate::{LevelType, MerkleTree, OneTimeSignatureType, TreeBuilder, TreeType};

    /// A tree of height 5 with the cheapest one-time keys, for the traversal tests.
    fn tree() -> MerkleTree {
        MerkleTree::new(
            LevelType::new(TreeType::height5, OneTimeSignatureType::winternitz2),
            core::array::from_fn(|index| 3 * index as u8),
            core::array::from_fn(|index| 100 + index as u8),
        )
    }

    /// Every node of a tree by number, by the definition of RFC 8554, Section 5.3: the hash of
    /// each leaf and of the children of each internal node.
    fn nodesByDefinition(tree: &MerkleTree) -> Vec<[u8; 32]> {
        let leafCount = tree.leafCount();
        let mut nodes = vec![[0u8; 32]; 2 * leafCount as usize];
        for q in 0..leafCount {
            nodes[(leafCount + q) as usize] = tree.leafNode(q);
        }
        for number in (1..leafCount).rev() {
            let (left, right) = (nodes[2 * number as usize], nodes[2 * number as usize + 1]);
            nodes[number as usize] = tree.internalNode(number, &left, &right);
        }
        nodes
    }

    /// The authentication path of a leaf from every node: the sibling of each node above it.
    fn pathByDefinition(nodes: &[[u8; 32]], leafCount: u32, q: u32) -> Vec<[u8; 32]> {
        let mut number = leafCount + q;
        let mut path = Vec::new();
        while number > 1 {
            path.push(nodes[(number ^ 1) as usize]);
            number /= 2;
        }
        path
    }

    #[test]
    fn eachLeafHasTheAuthenticationPathOfTheDefinitionAcrossEverySubtree() {
        let tree = tree();
        let nodes = nodesByDefinition(&tree);
        // Subtrees of height 2 give 8 subtrees in the tree of height 5, so the walk crosses
        // a subtree edge every 4 leaves. A state that starts at a leaf in the middle of a
        // subtree builds its later subtrees as it walks.
        for (subtreeHeight, start) in [(2, 0), (2, 6), (2, 27), (3, 9), (5, 0), (5, 31)] {
            let mut state = TreeState::computed(tree.clone(), start, subtreeHeight);
            assert_eq!(state.root(), &nodes[1]);
            for q in start..32 {
                assert_eq!(state.index(), q);
                assert_eq!(
                    state.authenticationPath(),
                    pathByDefinition(&nodes, 32, q),
                    "subtree height {subtreeHeight}, start {start}, leaf {q}"
                );
                assert!(!state.isExhausted());
                state.advance();
            }
            assert!(state.isExhausted());
        }
    }

    #[test]
    fn aBuilderStepsOneLeafAtATimeAndKeepsTheTopAndTheChosenSubtrees() {
        let tree = tree();
        let nodes = nodesByDefinition(&tree);
        let mut builder = TreeBuilder::wholeTree(tree.clone(), 8, 2, &[1, 6]);
        for built in 0..32 {
            assert!(!builder.isComplete(), "{built} leaves");
            builder.step();
        }
        assert!(builder.isComplete());
        builder.step();
        assert_eq!(builder.takeTop()[1..], nodes[1..8]);
        // Subtree 1 of height 2 has its root at node 2^3 + 1 = 9, and subtree 6 at node 14.
        let subtree = builder.takeSubtree(1).expect("subtree 1");
        assert_eq!(subtree[1], nodes[9]);
        assert_eq!(subtree[2..4], nodes[18..20]);
        assert_eq!(subtree[4..8], nodes[36..40]);
        let subtree = builder.takeSubtree(6).expect("subtree 6");
        assert_eq!(subtree[1], nodes[14]);
        assert_eq!(subtree[4..8], nodes[56..60]);
        assert!(builder.takeSubtree(2).is_none());
        // A builder of one subtree builds only its leaves.
        let mut single = TreeBuilder::subtree(tree.clone(), 3, 2);
        single.complete();
        let subtree = single.takeSubtree(2).expect("subtree 2");
        assert_eq!(subtree[1], nodes[6]);
        assert_eq!(subtree[8..16], nodes[48..56]);
    }

    #[test]
    fn aStateKeepsTheTopAndBuildsOnlyTheSubtreesInsideTheTree() {
        // Subtrees of height 2 split the tree of height 5 into the subtrees 0 to 7 under the
        // top part, the nodes 1 to 15.
        let tree = tree();
        assert_eq!(TreeState::builder(tree.clone(), 0, 2).takeTop().len(), 16);
        for start in [0, 3, 4, 17, 23, 24, 27, 28, 31] {
            let mut state = TreeState::computed(tree.clone(), start, 2);
            // The whole tree gives the subtree after the next one complete.
            assert!(
                state.building.as_ref().is_none_or(TreeBuilder::isComplete),
                "start {start}"
            );
            for q in start..32 {
                let subtree = q / 4;
                assert_eq!(
                    state.next.is_some(),
                    subtree + 1 < 8,
                    "start {start}, leaf {q}"
                );
                assert_eq!(
                    state.building.is_some(),
                    subtree + 2 < 8,
                    "start {start}, leaf {q}"
                );
                state.advance();
            }
        }
        // A tree of one subtree has no next subtree.
        let state = TreeState::computed(tree, 7, 5);
        assert!(state.next.is_none() && state.building.is_none());
    }

    #[test]
    fn theSubtreeHeightIsTheWholeTreeUpToHeight10() {
        assert_eq!(TreeState::subtreeHeight(5), 5);
        assert_eq!(TreeState::subtreeHeight(10), 10);
        assert_eq!(TreeState::subtreeHeight(15), 10);
        assert_eq!(TreeState::subtreeHeight(25), 10);
    }
}
