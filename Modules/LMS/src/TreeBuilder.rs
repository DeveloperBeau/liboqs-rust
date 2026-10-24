use crate::MerkleTree;
use crate::parameters::hashLength;
use alloc::vec;
use alloc::vec::Vec;

/// The nodes of a subtree at the bottom of a tree, in heap order: its root at place 1 and the
/// children of the node at place m at the places 2m and 2m + 1.
pub(crate) type SubtreeNodes = Vec<[u8; hashLength]>;

/// The nodes of a range of leaves of a tree, computed one leaf at a time with the stack of the
/// treehash algorithm, as `hss_compute_internal_node` and `subtree_add_next_node` of
/// hash-sigs compute them.
///
/// The range is a whole tree or one subtree at its bottom, so it is aligned to its size. The
/// builder keeps each node whose number is below a limit, the top of the tree, and the nodes
/// of chosen subtrees of one height at the bottom of the tree.
#[derive(Clone, Debug)]
pub(crate) struct TreeBuilder {
    tree: MerkleTree,
    firstLeaf: u32,
    rangeHeight: u32,
    builtCount: u32,
    stack: Vec<[u8; hashLength]>,
    topLimit: u32,
    top: Vec<[u8; hashLength]>,
    subtreeHeight: u32,
    subtrees: Vec<(u32, SubtreeNodes)>,
}

impl TreeBuilder {
    /// The number of the root of subtree i of height k: the node `2^(h - k) + i`.
    fn subtreeRoot(tree: &MerkleTree, subtreeHeight: u32, index: u32) -> u32 {
        (1 << (tree.height() - subtreeHeight)) + index
    }

    /// A builder of every leaf of a tree that keeps the nodes with a number below a limit and
    /// the subtrees of a height with some indices.
    pub(crate) fn wholeTree(
        tree: MerkleTree,
        topLimit: u32,
        subtreeHeight: u32,
        subtreeIndices: &[u32],
    ) -> Self {
        let subtrees = subtreeIndices
            .iter()
            .map(|index| {
                (
                    Self::subtreeRoot(&tree, subtreeHeight, *index),
                    vec![[0u8; hashLength]; 2 << subtreeHeight],
                )
            })
            .collect();
        TreeBuilder {
            firstLeaf: 0,
            rangeHeight: tree.height(),
            builtCount: 0,
            stack: Vec::with_capacity(tree.height() as usize),
            topLimit,
            top: vec![[0u8; hashLength]; topLimit as usize],
            subtreeHeight,
            subtrees,
            tree,
        }
    }

    /// A builder of the leaves of subtree i of height k that keeps every node of the subtree.
    pub(crate) fn subtree(tree: MerkleTree, subtreeHeight: u32, index: u32) -> Self {
        TreeBuilder {
            firstLeaf: index << subtreeHeight,
            rangeHeight: subtreeHeight,
            builtCount: 0,
            stack: Vec::with_capacity(subtreeHeight as usize),
            topLimit: 0,
            top: Vec::new(),
            subtreeHeight,
            subtrees: vec![(
                Self::subtreeRoot(&tree, subtreeHeight, index),
                vec![[0u8; hashLength]; 2 << subtreeHeight],
            )],
            tree,
        }
    }

    /// The builder of subtree i whose nodes are already known, as a complete builder.
    pub(crate) fn completedSubtree(
        tree: MerkleTree,
        subtreeHeight: u32,
        index: u32,
        nodes: SubtreeNodes,
    ) -> Self {
        let mut builder = Self::subtree(tree, subtreeHeight, index);
        builder.builtCount = 1 << subtreeHeight;
        builder.subtrees[0].1 = nodes;
        builder
    }

    /// True when every leaf of the range is built.
    pub(crate) fn isComplete(&self) -> bool {
        self.builtCount == 1 << self.rangeHeight
    }

    /// Builds the next leaf of the range and each node that it completes. A complete builder
    /// does nothing.
    pub(crate) fn step(&mut self) {
        if self.isComplete() {
            return;
        }
        let q = self.firstLeaf + self.builtCount;
        let mut nodeNumber = self.tree.leafCount() + q;
        let mut node = self.tree.leafNode(q);
        self.keep(nodeNumber, 0, &node);
        let mut height = 0;
        // The range is aligned to its size, so a node below the top of the range with an odd
        // number is a right child whose left sibling waits on the stack.
        while height < self.rangeHeight && nodeNumber & 1 == 1 {
            let left = self.stack.pop().expect("the left sibling of a right child");
            nodeNumber >>= 1;
            height += 1;
            node = self.tree.internalNode(nodeNumber, &left, &node);
            self.keep(nodeNumber, height, &node);
        }
        if height < self.rangeHeight {
            self.stack.push(node);
        }
        self.builtCount += 1;
    }

    /// Builds every leaf of the range that is not built yet.
    pub(crate) fn complete(&mut self) {
        while !self.isComplete() {
            self.step();
        }
    }

    /// Keeps a node of a height when it is in the top of the tree or in a kept subtree.
    fn keep(&mut self, nodeNumber: u32, height: u32, node: &[u8; hashLength]) {
        if nodeNumber < self.topLimit {
            self.top[nodeNumber as usize] = *node;
        }
        if height > self.subtreeHeight {
            return;
        }
        let depth = self.subtreeHeight - height;
        let root = nodeNumber >> depth;
        // The low bits below `1 << depth` cannot meet its one bit, so the join adds them.
        let place = (1 << depth) + (nodeNumber & ((1 << depth) - 1));
        for (subtreeRoot, nodes) in self.subtrees.iter_mut() {
            if *subtreeRoot == root {
                nodes[place as usize] = *node;
            }
        }
    }

    /// The tree of the builder.
    pub(crate) fn tree(&self) -> &MerkleTree {
        &self.tree
    }

    /// The kept nodes of the top of the tree, by node number. The place 0 is unused.
    pub(crate) fn takeTop(&mut self) -> Vec<[u8; hashLength]> {
        core::mem::take(&mut self.top)
    }

    /// The nodes of kept subtree i, or `None` when the builder does not keep it.
    pub(crate) fn takeSubtree(&mut self, index: u32) -> Option<SubtreeNodes> {
        let root = Self::subtreeRoot(&self.tree, self.subtreeHeight, index);
        let position = self
            .subtrees
            .iter()
            .position(|(subtreeRoot, _)| *subtreeRoot == root)?;
        Some(self.subtrees.swap_remove(position).1)
    }
}
