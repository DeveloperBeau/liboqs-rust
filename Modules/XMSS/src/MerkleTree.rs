use crate::wots::maximumChainCount;
use crate::{BigEndian, HashAddress, KeyedHash, WOTS};

/// The hash trees of XMSS, as `xmss_commons.c` computes them: the leaf of a WOTS+ key pair, its
/// L-tree, the root of an authentication path, and the verification of a signature of XMSS and of
/// XMSS^MT.
pub(crate) struct MerkleTree;

impl MerkleTree {
    /// The leaf of a WOTS+ public key, as `l_tree`: the pairs of each row are hashed until one
    /// node is left, and an odd node moves up a row. The key is overwritten.
    pub(crate) fn lTree(
        hash: &KeyedHash,
        publicKey: &mut [u8],
        address: &mut HashAddress,
    ) -> [u8; 64] {
        let parameters = hash.parameters();
        let hashLength = parameters.hashLength;
        let mut length = parameters.chainCount as u32;
        let mut height = 0;
        address.setTreeHeight(height);
        while length > 1 {
            let parentCount = length >> 1;
            for parentIndex in 0..parentCount {
                address.setTreeIndex(parentIndex);
                let start = 2 * parentIndex as usize * hashLength;
                let parent = hash.nodeHash(&publicKey[start..start + 2 * hashLength], address);
                let target = parentIndex as usize * hashLength;
                publicKey[target..target + hashLength].copy_from_slice(&parent[..hashLength]);
            }
            if length & 1 == 1 {
                let last = (length - 1) as usize * hashLength;
                publicKey.copy_within(last..last + hashLength, (length >> 1) as usize * hashLength);
                length = (length >> 1) + 1;
            } else {
                length >>= 1;
            }
            height += 1;
            address.setTreeHeight(height);
        }
        let mut leaf = [0u8; 64];
        leaf[..hashLength].copy_from_slice(&publicKey[..hashLength]);
        leaf
    }

    /// The root of a tree from a leaf, its index and its authentication path of h nodes, as
    /// `compute_root`.
    fn computeRoot(
        hash: &KeyedHash,
        leaf: &[u8],
        leafIndex: u64,
        authenticationPath: &[u8],
        address: &mut HashAddress,
    ) -> [u8; 64] {
        let parameters = hash.parameters();
        let hashLength = parameters.hashLength;
        let mut children = [0u8; 128];
        let mut index = leafIndex;
        // An odd index is a right child, so its sibling of the path goes on the left.
        let (left, right) = children.split_at_mut(hashLength);
        if index & 1 == 1 {
            right[..hashLength].copy_from_slice(&leaf[..hashLength]);
            left.copy_from_slice(&authenticationPath[..hashLength]);
        } else {
            left.copy_from_slice(&leaf[..hashLength]);
            right[..hashLength].copy_from_slice(&authenticationPath[..hashLength]);
        }
        let mut sibling = hashLength;
        for height in 0..parameters.treeHeight - 1 {
            address.setTreeHeight(height);
            index >>= 1;
            address.setTreeIndex(index as u32);
            let parent = hash.nodeHash(&children[..2 * hashLength], address);
            let path = &authenticationPath[sibling..sibling + hashLength];
            if index & 1 == 1 {
                children[hashLength..2 * hashLength].copy_from_slice(&parent[..hashLength]);
                children[..hashLength].copy_from_slice(path);
            } else {
                children[..hashLength].copy_from_slice(&parent[..hashLength]);
                children[hashLength..2 * hashLength].copy_from_slice(path);
            }
            sibling += hashLength;
        }
        // The last step has no node of the path to place.
        address.setTreeHeight(parameters.treeHeight - 1);
        index >>= 1;
        address.setTreeIndex(index as u32);
        hash.nodeHash(&children[..2 * hashLength], address)
    }

    /// The leaf of the WOTS+ key pair at an OTS address, as `gen_leaf_wots`: the L-tree of its
    /// public key at an L-tree address.
    pub(crate) fn leaf(
        hash: &KeyedHash,
        secretSeed: &[u8],
        lTreeAddress: &mut HashAddress,
        otsAddress: &mut HashAddress,
    ) -> [u8; 64] {
        let parameters = hash.parameters();
        let mut publicKey = [0u8; maximumChainCount * 64];
        let publicKey = &mut publicKey[..parameters.wotsSignatureLength];
        WOTS::publicKey(hash, publicKey, secretSeed, otsAddress);
        Self::lTree(hash, publicKey, lTreeAddress)
    }

    /// True when a signature of the length of the parameters is valid for a message and the root
    /// of a public key whose public seed `hash` holds, as `xmssmt_core_sign_open`.
    ///
    /// Each layer turns the node of the layer below into a WOTS+ public key, its leaf and the
    /// root of its tree. XMSS is the case of one layer.
    pub(crate) fn isValidSignature(
        hash: &KeyedHash,
        message: &[u8],
        signature: &[u8],
        publicRoot: &[u8],
    ) -> bool {
        let parameters = hash.parameters();
        let hashLength = parameters.hashLength;
        let indexLength = parameters.indexLength;
        let mut otsAddress = HashAddress::default();
        let mut lTreeAddress = HashAddress::default();
        let mut nodeAddress = HashAddress::default();
        otsAddress.setType(HashAddress::otsType);
        lTreeAddress.setType(HashAddress::lTreeType);
        nodeAddress.setType(HashAddress::hashTreeType);
        let mut index = BigEndian::read(&signature[..indexLength]);
        let mut node = [0u8; 64];
        hash.messageHash(
            &mut node,
            &signature[indexLength..indexLength + hashLength],
            publicRoot,
            index,
            message,
        );
        let mut offset = indexLength + hashLength;
        let mut publicKey = [0u8; maximumChainCount * 64];
        let publicKey = &mut publicKey[..parameters.wotsSignatureLength];
        let pathLength = parameters.treeHeight as usize * hashLength;
        for layer in 0..parameters.layerCount {
            let leafIndex = (index & ((1 << parameters.treeHeight) - 1)) as u32;
            index >>= parameters.treeHeight;
            otsAddress.setLayer(layer);
            lTreeAddress.setLayer(layer);
            nodeAddress.setLayer(layer);
            lTreeAddress.setTree(index);
            otsAddress.setTree(index);
            nodeAddress.setTree(index);
            otsAddress.setOTS(leafIndex);
            let wotsSignature = &signature[offset..offset + parameters.wotsSignatureLength];
            WOTS::publicKeyFromSignature(
                hash,
                publicKey,
                wotsSignature,
                &node[..hashLength],
                &mut otsAddress,
            );
            offset += parameters.wotsSignatureLength;
            lTreeAddress.setLTree(leafIndex);
            let leaf = Self::lTree(hash, publicKey, &mut lTreeAddress);
            node = Self::computeRoot(
                hash,
                &leaf,
                u64::from(leafIndex),
                &signature[offset..offset + pathLength],
                &mut nodeAddress,
            );
            offset += pathLength;
        }
        node[..hashLength] == publicRoot[..hashLength]
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;
    use crate::testInputs::{address, coreHashes, sequenceBytes};
    use crate::{KeyedHash, Parameters, Variant};
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The digests of the leaves of `gen_leaf_wots` of the C program for each core hash, in the
    /// order of `coreHashes`.
    const leaves: [&str; 7] = [
        "4691fcdde46f7993124b5f23f1af776e0e8256185e971b3ee12de0c4442515a1",
        "0897052e454f44208df235d5d60c08f6f7548cb9a26f3947f0a0df35fffe1076",
        "7a0a376d483f2541afe00cd08476a8f4e7e070cdfb6518747f53702e6a6d0d0f",
        "18056ae6c2debf837415e0835eedba3625c15a6d754cc80923355bee4ede759a",
        "d1fe639b3dc684330d43c825504cf737d5667892527cd897bac552eb28a73353",
        "a3b2577f5c49500abb86d88c62cf92acc8af126697315877bbc42a44c166ccca",
        "d6336e0e16bba595f3d00c7463ffbcebc76c8b482efb4fd60d8195a0da598419",
    ];

    #[test]
    fn eachLeafIsTheLeafOfTheCFunction() {
        for ((function, identifier), expected) in coreHashes.iter().zip(leaves) {
            let parameters = Parameters::of(Variant::xmss, *identifier).expect("a set");
            let hashLength = parameters.hashLength;
            let hash = KeyedHash::new(&parameters, *function, &sequenceBytes(hashLength, 12));
            let mut lTreeAddress = address([1, 0, 2, 1, 3, 0, 0, 0]);
            let mut otsAddress = address([1, 0, 2, 0, 3, 0, 0, 0]);
            let leaf = MerkleTree::leaf(
                &hash,
                &sequenceBytes(hashLength, 11),
                &mut lTreeAddress,
                &mut otsAddress,
            );
            assert_eq!(
                OutputDigest::of(&leaf[..hashLength]),
                expected,
                "{function:?}"
            );
            // The L-tree of len nodes has ceil(log2(len)) rows: 6 for 51 nodes, 7 for 67 and 8
            // for 131, and the address leaves at the height above its last row.
            let rows = u32::BITS - (parameters.chainCount as u32 - 1).leading_zeros();
            assert_eq!(
                lTreeAddress,
                address([1, 0, 2, 1, 3, rows, 0, 2]),
                "{function:?}"
            );
        }
    }

    #[test]
    fn anOddRowMovesItsLastNodeUp() {
        // Three leaves: the first two make a parent, the third moves up, and the root is the
        // parent of the two. The test computes the same with the node hash itself.
        let mut parameters = Parameters::of(Variant::xmss, 0x01).expect("XMSS-SHA2_10_256");
        parameters.chainCount = 3;
        let hash = KeyedHash::new(
            &parameters,
            crate::CoreHash::sha256N32,
            &sequenceBytes(32, 1),
        );
        let nodes = sequenceBytes(96, 2);
        let mut publicKey = nodes.clone();
        let mut lTreeAddress = address([0, 0, 0, 1, 4, 0, 0, 0]);
        let leaf = MerkleTree::lTree(&hash, &mut publicKey, &mut lTreeAddress);
        let mut first = address([0, 0, 0, 1, 4, 0, 0, 0]);
        let parent = hash.nodeHash(&nodes[..64], &mut first);
        let mut second = address([0, 0, 0, 1, 4, 1, 0, 0]);
        let mut children = parent[..32].to_vec();
        children.extend_from_slice(&nodes[64..]);
        let root = hash.nodeHash(&children, &mut second);
        assert_eq!(leaf[..32], root[..32]);
    }
}
