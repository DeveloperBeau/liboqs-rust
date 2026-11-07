/// The address `ADRS` of FIPS 205, Section 4.2: eight big-endian words of four bytes that make
/// each hash call of a key different.
///
/// Word 0 is the layer, words 1 to 3 the tree, word 4 the type, word 5 the key pair, word 6 the
/// chain or the tree height, and word 7 the hash address or the tree index. Word 1 is always
/// zero, because a tree address has at most 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Address {
    bytes: [u8; 32],
}

impl Address {
    /// The type of a hash in a WOTS+ chain.
    pub(crate) const wotsHash: u32 = 0;
    /// The type of the compression of a WOTS+ public key.
    pub(crate) const wotsPublicKey: u32 = 1;
    /// The type of a hash of an XMSS tree.
    pub(crate) const tree: u32 = 2;
    /// The type of a hash of a FORS tree.
    pub(crate) const forsTree: u32 = 3;
    /// The type of the compression of the FORS roots.
    pub(crate) const forsRoots: u32 = 4;
    /// The type of the generation of a WOTS+ secret value.
    pub(crate) const wotsPRF: u32 = 5;
    /// The type of the generation of a FORS secret value.
    pub(crate) const forsPRF: u32 = 6;

    /// The address with every byte zero, `toByte(0, 32)`.
    pub(crate) const zero: Address = Address { bytes: [0; 32] };

    /// The 32 bytes of the address, which the SHAKE functions hash.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    fn setWord(&mut self, word: usize, value: u32) {
        self.bytes[4 * word..4 * word + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// Sets the layer of the hypertree, word 0.
    pub(crate) fn setLayerAddress(&mut self, layer: u32) {
        self.setWord(0, layer);
    }

    /// Sets the tree of a layer, words 2 and 3. The C code writes the two halves of the 64-bit
    /// index and leaves word 1 as it is, which is zero.
    pub(crate) fn setTreeAddress(&mut self, tree: u64) {
        self.setWord(2, (tree >> 32) as u32);
        self.setWord(3, tree as u32);
    }

    /// Sets the type, word 4, and keeps the other words, as `adrs_set_type` of the C code does.
    pub(crate) fn setType(&mut self, addressType: u32) {
        self.setWord(4, addressType);
    }

    /// `ADRS.setTypeAndClear(Y)` of FIPS 205: sets the type and clears the last 12 bytes.
    pub(crate) fn setTypeAndClear(&mut self, addressType: u32) {
        self.setWord(4, addressType);
        self.bytes[20..].fill(0);
    }

    /// Sets the type and clears words 6 and 7 but keeps the key pair, as the FIPS 205 pair
    /// `setTypeAndClear(Y)` and `setKeyPairAddress(ADRS.getKeyPairAddress())` does.
    pub(crate) fn setTypeAndClearKeepingKeyPair(&mut self, addressType: u32) {
        self.setWord(4, addressType);
        self.bytes[24..].fill(0);
    }

    /// Sets the key pair, word 5.
    pub(crate) fn setKeyPairAddress(&mut self, keyPair: u32) {
        self.setWord(5, keyPair);
    }

    /// Sets the chain of a WOTS+ key, word 6.
    pub(crate) fn setChainAddress(&mut self, chain: u32) {
        self.setWord(6, chain);
    }

    /// Sets the height of a tree node, word 6.
    pub(crate) fn setTreeHeight(&mut self, height: u32) {
        self.setWord(6, height);
    }

    /// Sets the position in a WOTS+ chain, word 7.
    pub(crate) fn setHashAddress(&mut self, hash: u32) {
        self.setWord(7, hash);
    }

    /// Sets the index of a tree node, word 7.
    pub(crate) fn setTreeIndex(&mut self, index: u32) {
        self.setWord(7, index);
    }

    /// The compressed address `ADRS^c` of the SHA-2 functions, FIPS 205, Section 11.2:
    /// `ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]`, 22 bytes.
    pub(crate) fn compressed(&self) -> [u8; 22] {
        let mut compressed = [0u8; 22];
        compressed[0] = self.bytes[3];
        compressed[1..9].copy_from_slice(&self.bytes[8..16]);
        compressed[9..].copy_from_slice(&self.bytes[19..32]);
        compressed
    }
}

#[cfg(test)]
mod tests {
    use super::Address;

    /// An address with each field set to a value whose bytes show the field.
    fn filledAddress() -> Address {
        let mut address = Address::zero;
        address.setLayerAddress(0x0102_0304);
        address.setTreeAddress(0x1112_1314_1516_1718);
        address.setType(0x2122_2324);
        address.setKeyPairAddress(0x3132_3334);
        address.setChainAddress(0x4142_4344);
        address.setHashAddress(0x5152_5354);
        address
    }

    #[test]
    fn eachFieldIsABigEndianWordAtItsPlaceOfFIPS205Figure2() {
        let address = filledAddress();
        let expected: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44,
            0x51, 0x52, 0x53, 0x54,
        ];
        assert_eq!(address.bytes(), &expected);
        let mut tree = Address::zero;
        tree.setTreeHeight(7);
        tree.setTreeIndex(0x0A0B_0C0D);
        assert_eq!(&tree.bytes()[24..], &[0, 0, 0, 7, 0x0A, 0x0B, 0x0C, 0x0D]);
        assert_eq!(&tree.bytes()[..24], &[0u8; 24]);
    }

    #[test]
    fn typeChangesClearTheirWordsOnly() {
        let mut address = filledAddress();
        address.setType(6);
        assert_eq!(&address.bytes()[16..20], &[0, 0, 0, 6]);
        assert_eq!(&address.bytes()[20..], &filledAddress().bytes()[20..]);
        let mut cleared = filledAddress();
        cleared.setTypeAndClear(2);
        assert_eq!(&cleared.bytes()[..16], &filledAddress().bytes()[..16]);
        assert_eq!(
            &cleared.bytes()[16..],
            &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let mut kept = filledAddress();
        kept.setTypeAndClearKeepingKeyPair(1);
        assert_eq!(
            &kept.bytes()[16..],
            &[0, 0, 0, 1, 0x31, 0x32, 0x33, 0x34, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn compressedAddressKeepsTheBytesOfFIPS205Section11Point2() {
        let compressed = filledAddress().compressed();
        let expected: [u8; 22] = [
            0x04, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x24, 0x31, 0x32, 0x33, 0x34,
            0x41, 0x42, 0x43, 0x44, 0x51, 0x52, 0x53, 0x54,
        ];
        assert_eq!(compressed, expected);
    }

    #[test]
    fn typeConstantsAreTheValuesOfFIPS205Section4Point2() {
        assert_eq!(
            [
                Address::wotsHash,
                Address::wotsPublicKey,
                Address::tree,
                Address::forsTree,
                Address::forsRoots,
                Address::wotsPRF,
                Address::forsPRF
            ],
            [0, 1, 2, 3, 4, 5, 6]
        );
    }
}
