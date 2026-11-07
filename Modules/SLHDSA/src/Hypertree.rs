use crate::{Address, ByteConversion, HashContext, HashValue, Parameters};

/// The hypertree of FIPS 205, Sections 5 to 7: WOTS+ one-time signatures, the XMSS trees of
/// their public keys, and `d` layers of XMSS trees, each layer signing the roots of the layer
/// below.
///
/// Each function keeps the address changes of the C code in their order, so every hash sees
/// the address that the C code gives it.
pub(crate) struct Hypertree;

/// The digits of a WOTS+ message and of its checksum, one for each chain.
type ChainDigits = [u32; Parameters::maximumChainCount];

impl Hypertree {
    /// The root of the top XMSS tree, `PK.root` of `slh_keygen_internal`, FIPS 205,
    /// Algorithm 18.
    pub(crate) fn root(context: &mut HashContext) -> HashValue {
        let parameters = context.parameters();
        context.address = Address::zero;
        context.address.setLayerAddress(parameters.layerCount - 1);
        Self::xmssNode(context, 0, parameters.treeHeight)
    }

    /// `ht_sign` of FIPS 205, Algorithm 12: the hypertree signature of a message of `n` bytes
    /// with the XMSS tree and the leaf of the bottom layer.
    pub(crate) fn sign(
        context: &mut HashContext,
        signature: &mut [u8],
        message: &[u8],
        treeIndex: u64,
        leafIndex: u32,
    ) {
        let parameters = context.parameters();
        let n = parameters.hashLength;
        let xmssLength = parameters.xmssSignatureLength();
        let leafMask = (1u64 << parameters.treeHeight) - 1;
        let mut treeIndex = treeIndex;
        let mut leafIndex = leafIndex;
        context.address = Address::zero;
        context.address.setTreeAddress(treeIndex);
        let mut root = [0u8; Parameters::maximumHashLength];
        root[..n].copy_from_slice(&message[..n]);
        Self::xmssSign(context, &mut signature[..xmssLength], &root[..n], leafIndex);
        for layer in 1..parameters.layerCount as usize {
            // The root of the tree below comes from its signature, as in the C code.
            let below = &signature[(layer - 1) * xmssLength..layer * xmssLength];
            root = Self::xmssPublicKeyFromSignature(context, leafIndex, below, &root[..n]);
            leafIndex = (treeIndex & leafMask) as u32;
            treeIndex >>= parameters.treeHeight;
            context.address.setLayerAddress(layer as u32);
            context.address.setTreeAddress(treeIndex);
            Self::xmssSign(
                context,
                &mut signature[layer * xmssLength..(layer + 1) * xmssLength],
                &root[..n],
                leafIndex,
            );
        }
    }

    /// `ht_verify` of FIPS 205, Algorithm 13: true when a hypertree signature of a message of
    /// `n` bytes leads to `PK.root`.
    pub(crate) fn isValid(
        context: &mut HashContext,
        message: &[u8],
        signature: &[u8],
        treeIndex: u64,
        leafIndex: u32,
    ) -> bool {
        let parameters = context.parameters();
        let n = parameters.hashLength;
        let xmssLength = parameters.xmssSignatureLength();
        let leafMask = (1u64 << parameters.treeHeight) - 1;
        let mut treeIndex = treeIndex;
        let mut leafIndex = leafIndex;
        context.address = Address::zero;
        context.address.setTreeAddress(treeIndex);
        let mut node =
            Self::xmssPublicKeyFromSignature(context, leafIndex, &signature[..xmssLength], message);
        for layer in 1..parameters.layerCount as usize {
            leafIndex = (treeIndex & leafMask) as u32;
            treeIndex >>= parameters.treeHeight;
            context.address.setLayerAddress(layer as u32);
            context.address.setTreeAddress(treeIndex);
            node = Self::xmssPublicKeyFromSignature(
                context,
                leafIndex,
                &signature[layer * xmssLength..(layer + 1) * xmssLength],
                &node[..n],
            );
        }
        node[..n] == *context.publicRoot()
    }

    /// `xmss_node` of FIPS 205, Algorithm 9, without recursion, as in the C code: the root of
    /// the subtree of a height whose leaves are the WOTS+ keys from `index 2^height`.
    pub(crate) fn xmssNode(context: &mut HashContext, index: u32, height: u32) -> HashValue {
        let parameters = context.parameters();
        let n = parameters.hashLength;
        let chainCount = parameters.chainCount();
        let mut publicValues = [0u8; Parameters::maximumChainCount * Parameters::maximumHashLength];
        let mut stack = [[0u8; Parameters::maximumHashLength]; Parameters::maximumTreeHeight + 1];
        let mut stackCount = 0;
        let firstLeaf = index << height;
        for position in 0..1u32 << height {
            let leaf = firstLeaf + position;
            // The WOTS+ public key of the leaf, `wots_pkGen` of FIPS 205, Algorithm 6.
            context.address.setKeyPairAddress(leaf);
            for chain in 0..chainCount {
                context.address.setChainAddress(chain as u32);
                let value = context.wotsChain(Parameters::largestDigit);
                publicValues[chain * n..(chain + 1) * n].copy_from_slice(&value[..n]);
            }
            context
                .address
                .setTypeAndClearKeepingKeyPair(Address::wotsPublicKey);
            stack[stackCount] = context.t(&[&publicValues[..chainCount * n]]);
            stackCount += 1;
            // Each trailing one bit of the position joins two nodes of the next height.
            let mut joinHeight = 0;
            while (position >> joinHeight) & 1 == 1 {
                context.address.setTypeAndClear(Address::tree);
                context.address.setTreeHeight(joinHeight + 1);
                context.address.setTreeIndex(leaf >> (joinHeight + 1));
                stackCount -= 1;
                let right = stack[stackCount];
                stack[stackCount - 1] = context.h(&stack[stackCount - 1][..n], &right[..n]);
                joinHeight += 1;
            }
        }
        debug_assert_eq!(stackCount, 1);
        stack[0]
    }

    /// `xmss_sign` of FIPS 205, Algorithm 10: the WOTS+ signature of a message of `n` bytes
    /// with a leaf, and the authentication path of the leaf.
    fn xmssSign(context: &mut HashContext, signature: &mut [u8], message: &[u8], leafIndex: u32) {
        let parameters = context.parameters();
        let n = parameters.hashLength;
        let wotsLength = parameters.chainCount() * n;
        for height in 0..parameters.treeHeight {
            let sibling = (leafIndex >> height) ^ 1;
            let node = Self::xmssNode(context, sibling, height);
            let start = wotsLength + height as usize * n;
            signature[start..start + n].copy_from_slice(&node[..n]);
        }
        context
            .address
            .setTypeAndClearKeepingKeyPair(Address::wotsHash);
        context.address.setKeyPairAddress(leafIndex);
        Self::wotsSign(context, &mut signature[..wotsLength], message);
    }

    /// `xmss_pkFromSig` of FIPS 205, Algorithm 11: the root of an XMSS tree from the signature
    /// of a message with a leaf.
    fn xmssPublicKeyFromSignature(
        context: &mut HashContext,
        leafIndex: u32,
        signature: &[u8],
        message: &[u8],
    ) -> HashValue {
        let parameters = context.parameters();
        let n = parameters.hashLength;
        let wotsLength = parameters.chainCount() * n;
        context
            .address
            .setTypeAndClearKeepingKeyPair(Address::wotsHash);
        context.address.setKeyPairAddress(leafIndex);
        let mut node = Self::wotsPublicKeyFromSignature(context, &signature[..wotsLength], message);
        context.address.setTypeAndClear(Address::tree);
        for height in 0..parameters.treeHeight {
            context.address.setTreeHeight(height + 1);
            context.address.setTreeIndex(leafIndex >> (height + 1));
            let start = wotsLength + height as usize * n;
            let sibling = &signature[start..start + n];
            node = if (leafIndex >> height) & 1 == 0 {
                context.h(&node[..n], sibling)
            } else {
                context.h(sibling, &node[..n])
            };
        }
        node
    }

    /// `wots_sign` of FIPS 205, Algorithm 7: each chain from its secret value to the digit of
    /// the message or of the checksum.
    fn wotsSign(context: &mut HashContext, signature: &mut [u8], message: &[u8]) {
        let parameters = context.parameters();
        let n = parameters.hashLength;
        let digits = Self::chainDigits(parameters, message);
        for (chain, digit) in digits[..parameters.chainCount()].iter().enumerate() {
            context.address.setChainAddress(chain as u32);
            let value = context.wotsChain(*digit);
            signature[chain * n..(chain + 1) * n].copy_from_slice(&value[..n]);
        }
    }

    /// `wots_pkFromSig` of FIPS 205, Algorithm 8: the WOTS+ public key from a signature, each
    /// chain continued from its digit to the end.
    fn wotsPublicKeyFromSignature(
        context: &mut HashContext,
        signature: &[u8],
        message: &[u8],
    ) -> HashValue {
        let parameters = context.parameters();
        let n = parameters.hashLength;
        let chainCount = parameters.chainCount();
        let digits = Self::chainDigits(parameters, message);
        let mut publicValues = [0u8; Parameters::maximumChainCount * Parameters::maximumHashLength];
        for (chain, digit) in digits[..chainCount].iter().enumerate() {
            context.address.setChainAddress(chain as u32);
            let value = context.chain(
                &signature[chain * n..(chain + 1) * n],
                *digit,
                Parameters::largestDigit - *digit,
            );
            publicValues[chain * n..(chain + 1) * n].copy_from_slice(&value[..n]);
        }
        context
            .address
            .setTypeAndClearKeepingKeyPair(Address::wotsPublicKey);
        context.t(&[&publicValues[..chainCount * n]])
    }

    /// The digits of the chains of a WOTS+ signature, `wots_csum` of the C code: the `len_1`
    /// digits of the message, then the `len_2` digits of the checksum, shifted so that its
    /// digits fill whole bytes, FIPS 205, Algorithm 7, lines 2 to 9.
    fn chainDigits(parameters: &Parameters, message: &[u8]) -> ChainDigits {
        let messageChainCount = parameters.messageChainCount();
        let checksumChainCount = parameters.checksumChainCount();
        let bits = Parameters::winternitzBits;
        let mut digits = [0u32; Parameters::maximumChainCount];
        ByteConversion::base2b(
            &message[..parameters.hashLength],
            bits,
            &mut digits[..messageChainCount],
        );
        let mut checksum = 0u32;
        for digit in &digits[..messageChainCount] {
            checksum += Parameters::largestDigit - digit;
        }
        let checksumBits = checksumChainCount as u32 * bits;
        checksum <<= (8 - (checksumBits & 7)) & 7;
        let mut checksumBytes = [0u8; 4];
        let checksumLength = checksumBits.div_ceil(8) as usize;
        ByteConversion::toBytes(checksum, &mut checksumBytes[..checksumLength]);
        ByteConversion::base2b(
            &checksumBytes[..checksumLength],
            bits,
            &mut digits[messageChainCount..messageChainCount + checksumChainCount],
        );
        digits
    }
}

#[cfg(test)]
mod tests {
    use super::Hypertree;
    use crate::{Address, HashContext, parameterSets};

    #[test]
    fn chainDigitsOfTheZeroMessageCarryTheLargestChecksum() {
        // FIPS 205, Algorithm 7, by hand for n = 16: 32 zero digits give the checksum
        // 32 * 15 = 480, shifted by 4 bits to 0x1E00, whose digits are 1, 14 and 0.
        let digits = Hypertree::chainDigits(&parameterSets[0], &[0u8; 16]);
        assert_eq!(&digits[..32], &[0u32; 32]);
        assert_eq!(&digits[32..35], &[1, 14, 0]);
        // A message of all ones has the checksum 0.
        let digits = Hypertree::chainDigits(&parameterSets[0], &[0xFF; 16]);
        assert_eq!(&digits[..32], &[15u32; 32]);
        assert_eq!(&digits[32..35], &[0, 0, 0]);
        // For n = 32: 64 zero digits give 960, shifted to 0x3C00: 3, 12 and 0.
        let digits = Hypertree::chainDigits(&parameterSets[4], &[0u8; 32]);
        assert_eq!(&digits[64..67], &[3, 12, 0]);
        // The digits of 0x12 0x34 are 1, 2, 3 and 4, and the checksum counts each digit.
        let mut message = [0xFFu8; 16];
        message[0] = 0x12;
        message[1] = 0x34;
        let digits = Hypertree::chainDigits(&parameterSets[0], &message);
        assert_eq!(&digits[..4], &[1, 2, 3, 4]);
        // 14 + 13 + 12 + 11 = 50, shifted to 0x0320: 0, 3 and 2.
        assert_eq!(&digits[32..35], &[0, 3, 2]);
    }

    fn context(setIndex: usize) -> HashContext {
        let set = &parameterSets[setIndex];
        let seeds: Vec<u8> = (0..4 * set.hashLength as u8).collect();
        HashContext::fromSecretKey(set, &seeds)
    }

    #[test]
    fn wotsSignatureLeadsBackToTheLeafOfTheTree() {
        // SHA2-128f and SHAKE-128f, which have trees of height 3.
        for setIndex in [1, 7] {
            let mut context = context(setIndex);
            let n = context.parameters().hashLength;
            let message = [0x5Cu8; 16];
            context.address = Address::zero;
            context.address.setLayerAddress(2);
            context.address.setTreeAddress(11);
            let leaf = Hypertree::xmssNode(&mut context, 5, 0);
            let mut signature = vec![0u8; context.parameters().xmssSignatureLength()];
            Hypertree::xmssSign(&mut context, &mut signature, &message[..n], 5);
            context.address = Address::zero;
            context.address.setLayerAddress(2);
            context.address.setTreeAddress(11);
            context
                .address
                .setTypeAndClearKeepingKeyPair(Address::wotsHash);
            context.address.setKeyPairAddress(5);
            let wotsLength = context.parameters().chainCount() * n;
            let publicKey = Hypertree::wotsPublicKeyFromSignature(
                &mut context,
                &signature[..wotsLength],
                &message,
            );
            assert_eq!(publicKey, leaf, "set {setIndex}");
        }
    }

    #[test]
    fn xmssSignatureLeadsToTheRootOfItsTreeForEveryLeaf() {
        let mut context = context(1);
        let parameters = context.parameters();
        let message = [0xA7u8; 16];
        context.address = Address::zero;
        context.address.setTreeAddress(3);
        let root = Hypertree::xmssNode(&mut context, 0, parameters.treeHeight);
        let mut signature = vec![0u8; parameters.xmssSignatureLength()];
        for leaf in 0..1u32 << parameters.treeHeight {
            context.address = Address::zero;
            context.address.setTreeAddress(3);
            Hypertree::xmssSign(&mut context, &mut signature, &message, leaf);
            context.address = Address::zero;
            context.address.setTreeAddress(3);
            assert_eq!(
                Hypertree::xmssPublicKeyFromSignature(&mut context, leaf, &signature, &message),
                root,
                "leaf {leaf}"
            );
            // The signature of one leaf does not lead to the root from another leaf.
            context.address = Address::zero;
            context.address.setTreeAddress(3);
            assert_ne!(
                Hypertree::xmssPublicKeyFromSignature(&mut context, leaf ^ 1, &signature, &message),
                root
            );
        }
    }

    #[test]
    fn hypertreeSignatureVerifiesAndAChangedMessageDoesNot() {
        for setIndex in [1, 7] {
            let set = &parameterSets[setIndex];
            let n = set.hashLength;
            let seeds: Vec<u8> = (10..10 + 3 * n as u8).collect();
            let mut keyContext = HashContext::new(
                set,
                &seeds[..n],
                &seeds[n..2 * n],
                &seeds[2 * n..],
                &[0; 32],
            );
            let root = Hypertree::root(&mut keyContext);
            let mut secretKey = seeds.clone();
            secretKey.extend_from_slice(&root[..n]);
            let mut context = HashContext::fromSecretKey(set, &secretKey);
            let message = [0x3Du8; 32];
            let mut signature = vec![0u8; set.layerCount as usize * set.xmssSignatureLength()];
            let treeIndex =
                0x2_1234_5678_9ABC & ((1 << (set.hypertreeHeight - set.treeHeight)) - 1);
            Hypertree::sign(&mut context, &mut signature, &message[..n], treeIndex, 6);
            assert!(Hypertree::isValid(
                &mut context,
                &message[..n],
                &signature,
                treeIndex,
                6
            ));
            let mut changed = message;
            changed[0] ^= 1;
            assert!(!Hypertree::isValid(
                &mut context,
                &changed[..n],
                &signature,
                treeIndex,
                6
            ));
            assert!(!Hypertree::isValid(
                &mut context,
                &message[..n],
                &signature,
                treeIndex ^ 1,
                6
            ));
            assert!(!Hypertree::isValid(
                &mut context,
                &message[..n],
                &signature,
                treeIndex,
                7
            ));
            let last = signature.len() - 1;
            signature[last] ^= 0x80;
            assert!(!Hypertree::isValid(
                &mut context,
                &message[..n],
                &signature,
                treeIndex,
                6
            ));
        }
    }
}
