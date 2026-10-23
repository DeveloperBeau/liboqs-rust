use crate::{Address, ByteConversion, HashContext, HashValue, Parameters};

/// The forest of random subsets FORS of FIPS 205, Section 8: `k` trees of height `a` whose
/// leaves sign the digest of a message, one leaf in each tree.
///
/// The address holds the tree address, the key pair and the type `FORS_TREE` of the caller,
/// as in the C code.
pub(crate) struct FORS;

/// The leaf of each FORS tree that a digest selects.
type LeafIndices = [u32; Parameters::maximumFORSTreeCount];

impl FORS {
    /// The leaf of each tree, `base_2b(md, a, k)`.
    fn leafIndices(parameters: &Parameters, digest: &[u8]) -> LeafIndices {
        let mut indices = [0u32; Parameters::maximumFORSTreeCount];
        ByteConversion::base2b(
            digest,
            parameters.forsTreeHeight,
            &mut indices[..parameters.forsTreeCount as usize],
        );
        indices
    }

    /// `fors_node` of FIPS 205, Algorithm 15, without recursion, as in the C code: the root of
    /// the subtree of a height whose leaves start at `index 2^height`.
    fn node(context: &mut HashContext, index: u32, height: u32) -> HashValue {
        let n = context.parameters().hashLength;
        let mut stack =
            [[0u8; Parameters::maximumHashLength]; Parameters::maximumFORSTreeHeight + 1];
        let mut stackCount = 0;
        let firstLeaf = index << height;
        for position in 0..1u32 << height {
            let leaf = firstLeaf + position;
            context.address.setTreeIndex(leaf);
            stack[stackCount] = context.forsLeaf();
            stackCount += 1;
            // Each trailing one bit of the position joins two nodes of the next height.
            let mut joinHeight = 0;
            while (position >> joinHeight) & 1 == 1 {
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

    /// `fors_sign` of FIPS 205, Algorithm 16: for each tree the secret value of the selected
    /// leaf and its authentication path.
    pub(crate) fn sign(context: &mut HashContext, signature: &mut [u8], digest: &[u8]) {
        let parameters = context.parameters();
        let n = parameters.hashLength;
        let height = parameters.forsTreeHeight;
        let indices = Self::leafIndices(parameters, digest);
        for tree in 0..parameters.forsTreeCount {
            let index = indices[tree as usize];
            let start = tree as usize * (1 + height as usize) * n;
            context.address.setTreeIndex((tree << height) + index);
            let secret = context.forsSecret();
            signature[start..start + n].copy_from_slice(&secret[..n]);
            for level in 0..height {
                let sibling = (index >> level) ^ 1;
                let node = Self::node(context, (tree << (height - level)) + sibling, level);
                let position = start + (1 + level as usize) * n;
                signature[position..position + n].copy_from_slice(&node[..n]);
            }
        }
    }

    /// `fors_pkFromSig` of FIPS 205, Algorithm 17: the FORS public key from a signature, the
    /// hash `T_k` of the root of each tree.
    pub(crate) fn publicKeyFromSignature(
        context: &mut HashContext,
        signature: &[u8],
        digest: &[u8],
    ) -> HashValue {
        let parameters = context.parameters();
        let n = parameters.hashLength;
        let height = parameters.forsTreeHeight;
        let treeCount = parameters.forsTreeCount as usize;
        let indices = Self::leafIndices(parameters, digest);
        let mut roots = [0u8; Parameters::maximumFORSTreeCount * Parameters::maximumHashLength];
        for tree in 0..treeCount {
            let leafIndex = indices[tree];
            let start = tree * (1 + height as usize) * n;
            context.address.setTreeHeight(0);
            let index = ((tree as u32) << height) + leafIndex;
            context.address.setTreeIndex(index);
            let mut node = context.f(&signature[start..start + n]);
            for level in 0..height {
                context.address.setTreeHeight(level + 1);
                context.address.setTreeIndex(index >> (level + 1));
                let position = start + (1 + level as usize) * n;
                let sibling = &signature[position..position + n];
                node = if (leafIndex >> level) & 1 == 0 {
                    context.h(&node[..n], sibling)
                } else {
                    context.h(sibling, &node[..n])
                };
            }
            roots[tree * n..(tree + 1) * n].copy_from_slice(&node[..n]);
        }
        context
            .address
            .setTypeAndClearKeepingKeyPair(Address::forsRoots);
        context.t(&[&roots[..treeCount * n]])
    }
}

#[cfg(test)]
mod tests {
    use super::FORS;
    use crate::{Address, HashContext, parameterSets};

    fn contextAtKeyPair(setIndex: usize) -> HashContext {
        let set = &parameterSets[setIndex];
        let secretKey: Vec<u8> = (0..4 * set.hashLength as u8)
            .map(|byte| byte ^ 0x5A)
            .collect();
        let mut context = HashContext::fromSecretKey(set, &secretKey);
        context.address = Address::zero;
        context.address.setTreeAddress(0x1234);
        context
            .address
            .setTypeAndClearKeepingKeyPair(Address::forsTree);
        context.address.setKeyPairAddress(3);
        context
    }

    #[test]
    fn leafIndicesAreTheDigitsOfTheTreeHeight() {
        // SHA2-128f has 33 trees of height 6, so a digest of 25 bytes. The bits of 0xFC 0x0F
        // 0xFF 0x00 give the digits 63, 0, 63, 63 and 0.
        let mut digest = [0u8; 25];
        digest[..4].copy_from_slice(&[0xFC, 0x0F, 0xFF, 0x00]);
        digest[24] = 0xFD;
        let indices = FORS::leafIndices(&parameterSets[1], &digest);
        assert_eq!(&indices[..5], &[63, 0, 63, 63, 0]);
        // The last digit of the 198 bits is the high 6 bits of the last byte, and its low 2
        // bits are not read.
        assert_eq!(indices[32], 63);
        assert_eq!(&indices[33..], &[0, 0]);
    }

    #[test]
    fn signatureLeadsToTheRootsOfTheTrees() {
        for setIndex in [1, 7] {
            let mut context = contextAtKeyPair(setIndex);
            let set = context.parameters();
            let n = set.hashLength;
            let digest: Vec<u8> = (0..set.forsDigestLength() as u8)
                .map(|byte| byte.wrapping_mul(37))
                .collect();
            let mut signature = vec![0u8; set.forsSignatureLength()];
            FORS::sign(&mut context, &mut signature, &digest);
            let publicKey = FORS::publicKeyFromSignature(&mut context, &signature, &digest);
            // The public key is T_k of the root of each whole tree.
            let mut roots = Vec::new();
            for tree in 0..set.forsTreeCount {
                context
                    .address
                    .setTypeAndClearKeepingKeyPair(Address::forsTree);
                let root = FORS::node(&mut context, tree, set.forsTreeHeight);
                roots.extend_from_slice(&root[..n]);
            }
            context
                .address
                .setTypeAndClearKeepingKeyPair(Address::forsRoots);
            assert_eq!(publicKey, context.t(&[&roots]), "set {setIndex}");
            // A changed digest selects other leaves and gives another key.
            let mut changed = digest.clone();
            changed[0] ^= 0x80;
            context
                .address
                .setTypeAndClearKeepingKeyPair(Address::forsTree);
            assert_ne!(
                FORS::publicKeyFromSignature(&mut context, &signature, &changed),
                publicKey
            );
        }
    }

    #[test]
    fn eachSecretValueIsThePRFOfItsLeafAddress() {
        let mut context = contextAtKeyPair(1);
        let set = context.parameters();
        let n = set.hashLength;
        let digest = vec![0u8; set.forsDigestLength()];
        let mut signature = vec![0u8; set.forsSignatureLength()];
        FORS::sign(&mut context, &mut signature, &digest);
        // With a zero digest, tree t signs its leaf t 2^a, whose secret value is the PRF of the
        // address of type FORS_PRF, height 0 and that index.
        for tree in [0u32, 5, 32] {
            context
                .address
                .setTypeAndClearKeepingKeyPair(Address::forsPRF);
            context.address.setTreeIndex(tree << set.forsTreeHeight);
            let start = tree as usize * (1 + set.forsTreeHeight as usize) * n;
            assert_eq!(&signature[start..start + n], &context.prf()[..n]);
        }
    }
}
