/// The 32-byte hash address ADRS of RFC 8391, Section 2.5, as the eight words of
/// `hash_address.c`.
///
/// Word 0 is the layer, words 1 and 2 the tree, word 3 the type and word 7 the key and mask
/// selector. Words 4 to 6 depend on the type: the OTS index, the chain and the hash step of an
/// OTS address, the L-tree index, the height and the index of an L-tree address, and the
/// padding, the height and the index of a hash tree address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HashAddress {
    words: [u32; 8],
}

impl HashAddress {
    /// The type of the address of a WOTS+ key pair, `XMSS_ADDR_TYPE_OTS`.
    pub(crate) const otsType: u32 = 0;
    /// The type of the address of an L-tree, `XMSS_ADDR_TYPE_LTREE`.
    pub(crate) const lTreeType: u32 = 1;
    /// The type of the address of a node of a hash tree, `XMSS_ADDR_TYPE_HASHTREE`.
    pub(crate) const hashTreeType: u32 = 2;

    /// Sets the layer of the tree in the hypertree.
    pub(crate) fn setLayer(&mut self, layer: u32) {
        self.words[0] = layer;
    }

    /// Sets the index of the tree in its layer, in two words.
    pub(crate) fn setTree(&mut self, tree: u64) {
        self.words[1] = (tree >> 32) as u32;
        self.words[2] = tree as u32;
    }

    /// Sets the type of the address.
    pub(crate) fn setType(&mut self, kind: u32) {
        self.words[3] = kind;
    }

    /// Sets the selector of the key or of a half of the bitmask that a PRF call derives.
    pub(crate) fn setKeyAndMask(&mut self, keyAndMask: u32) {
        self.words[7] = keyAndMask;
    }

    /// Copies the layer and the tree of another address, as `copy_subtree_addr`.
    pub(crate) fn copySubtree(&mut self, other: &HashAddress) {
        self.words[..3].copy_from_slice(&other.words[..3]);
    }

    /// Sets the index of the WOTS+ key pair in its tree.
    pub(crate) fn setOTS(&mut self, index: u32) {
        self.words[4] = index;
    }

    /// Sets the chain of the WOTS+ key.
    pub(crate) fn setChain(&mut self, chain: u32) {
        self.words[5] = chain;
    }

    /// Sets the step in the chain.
    pub(crate) fn setHash(&mut self, step: u32) {
        self.words[6] = step;
    }

    /// Sets the index of the L-tree in its tree.
    pub(crate) fn setLTree(&mut self, index: u32) {
        self.words[4] = index;
    }

    /// Sets the height of the node in its tree.
    pub(crate) fn setTreeHeight(&mut self, height: u32) {
        self.words[5] = height;
    }

    /// Sets the index of the node at its height.
    pub(crate) fn setTreeIndex(&mut self, index: u32) {
        self.words[6] = index;
    }

    /// The 32 bytes of the address: each word in big-endian order, as `addr_to_bytes`.
    pub(crate) fn bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(self.words) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::HashAddress;

    #[test]
    fn eachSetterWritesItsWordOfTheLayoutOfRFC8391() {
        let mut address = HashAddress::default();
        address.setLayer(0x0102_0304);
        address.setTree(0x0506_0708_090A_0B0C);
        address.setType(HashAddress::hashTreeType);
        address.setTreeHeight(0x1112_1314);
        address.setTreeIndex(0x1516_1718);
        address.setKeyAndMask(0x191A_1B1C);
        let mut expected = [0u8; 32];
        expected[..12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        expected[12..16].copy_from_slice(&[0, 0, 0, 2]);
        expected[20..24].copy_from_slice(&[0x11, 0x12, 0x13, 0x14]);
        expected[24..28].copy_from_slice(&[0x15, 0x16, 0x17, 0x18]);
        expected[28..].copy_from_slice(&[0x19, 0x1A, 0x1B, 0x1C]);
        assert_eq!(address.bytes(), expected);
        // The OTS, the L-tree and the hash tree words share their places.
        let mut ots = HashAddress::default();
        ots.setOTS(7);
        ots.setChain(8);
        ots.setHash(9);
        let mut tree = HashAddress::default();
        tree.setLTree(7);
        tree.setTreeHeight(8);
        tree.setTreeIndex(9);
        assert_eq!(ots.bytes(), tree.bytes());
        assert_eq!(ots.bytes()[16..28], [0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 9]);
    }

    #[test]
    fn copySubtreeCopiesTheLayerAndTheTreeOnly() {
        let mut source = HashAddress::default();
        source.setLayer(3);
        source.setTree(0x1_0000_0002);
        source.setType(HashAddress::lTreeType);
        source.setLTree(5);
        let mut target = HashAddress::default();
        target.setType(HashAddress::hashTreeType);
        target.setTreeIndex(6);
        target.copySubtree(&source);
        let bytes = target.bytes();
        assert_eq!(bytes[..12], [0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(bytes[12..16], [0, 0, 0, 2]);
        assert_eq!(bytes[16..20], [0, 0, 0, 0]);
        assert_eq!(bytes[24..28], [0, 0, 0, 6]);
        assert_eq!(HashAddress::otsType, 0);
    }
}
