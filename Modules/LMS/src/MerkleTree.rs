use crate::parameters::{hashLength, identifierLength, seedLength};
use crate::{LevelType, OneTimeSignature, SeedDerivation};
use OQSNativeSHA2::SHA256;
use alloc::vec::Vec;

/// The domain separator `D_LEAF` of the hash of a leaf.
const leafDomain: [u8; 2] = [0x82, 0x82];

/// The domain separator `D_INTR` of the hash of an internal node.
const internalDomain: [u8; 2] = [0x83, 0x83];

/// One LMS tree of a key, RFC 8554, Section 5: its types, its identifier I and the seed of its
/// one-time keys, with the hashes of its nodes as `hss_compute.c` and `lm_verify.c` of
/// hash-sigs compute them.
///
/// The nodes are numbered as in RFC 8554: the root is node 1, the children of node r are the
/// nodes 2r and 2r + 1, and the leaf q is the node `2^h + q`.
#[derive(Clone, Debug)]
pub(crate) struct MerkleTree {
    /// The types of the tree and of its one-time signatures.
    pub(crate) kind: LevelType,
    /// The identifier I.
    pub(crate) identifier: [u8; identifierLength],
    /// The seed of the one-time keys.
    pub(crate) seed: [u8; seedLength],
}

impl MerkleTree {
    /// The tree of a type, an identifier and a seed.
    pub(crate) fn new(
        kind: LevelType,
        identifier: [u8; identifierLength],
        seed: [u8; seedLength],
    ) -> Self {
        MerkleTree {
            kind,
            identifier,
            seed,
        }
    }

    /// The height h of the tree.
    pub(crate) fn height(&self) -> u32 {
        self.kind.tree.height()
    }

    /// The number of leaves, `2^h`.
    pub(crate) fn leafCount(&self) -> u32 {
        1 << self.height()
    }

    /// The derivation of the secret values of the tree.
    pub(crate) fn derivation(&self) -> SeedDerivation<'_> {
        SeedDerivation::new(&self.identifier, &self.seed)
    }

    /// The one-time signature of the type of the tree.
    pub(crate) fn oneTimeSignature(&self) -> OneTimeSignature {
        OneTimeSignature::new(self.kind.oneTimeSignature)
    }

    /// The hash of a leaf node with the one-time public key K of its leaf:
    /// `H(I || u32str(r) || u16str(D_LEAF) || K)`.
    pub(crate) fn leafNodeOfKey(
        identifier: &[u8; identifierLength],
        nodeNumber: u32,
        publicKey: &[u8; hashLength],
    ) -> [u8; hashLength] {
        let mut input = [0u8; identifierLength + 6 + hashLength];
        input[..identifierLength].copy_from_slice(identifier);
        input[identifierLength..identifierLength + 4].copy_from_slice(&nodeNumber.to_be_bytes());
        input[identifierLength + 4..identifierLength + 6].copy_from_slice(&leafDomain);
        input[identifierLength + 6..].copy_from_slice(publicKey);
        SHA256::hash(&input)
    }

    /// The hash of an internal node r of its children:
    /// `H(I || u32str(r) || u16str(D_INTR) || left || right)`, `hss_combine_internal_nodes`.
    pub(crate) fn internalNodeOf(
        identifier: &[u8; identifierLength],
        nodeNumber: u32,
        left: &[u8; hashLength],
        right: &[u8; hashLength],
    ) -> [u8; hashLength] {
        let mut input = [0u8; identifierLength + 6 + 2 * hashLength];
        input[..identifierLength].copy_from_slice(identifier);
        input[identifierLength..identifierLength + 4].copy_from_slice(&nodeNumber.to_be_bytes());
        input[identifierLength + 4..identifierLength + 6].copy_from_slice(&internalDomain);
        input[identifierLength + 6..identifierLength + 6 + hashLength].copy_from_slice(left);
        input[identifierLength + 6 + hashLength..].copy_from_slice(right);
        SHA256::hash(&input)
    }

    /// The node of leaf q: the hash of the one-time public key of the leaf.
    pub(crate) fn leafNode(&self, q: u32) -> [u8; hashLength] {
        let publicKey = self
            .oneTimeSignature()
            .publicKey(&self.identifier, q, &self.derivation());
        Self::leafNodeOfKey(&self.identifier, self.leafCount() + q, &publicKey)
    }

    /// The internal node r of the tree of its children.
    pub(crate) fn internalNode(
        &self,
        nodeNumber: u32,
        left: &[u8; hashLength],
        right: &[u8; hashLength],
    ) -> [u8; hashLength] {
        Self::internalNodeOf(&self.identifier, nodeNumber, left, right)
    }

    /// The LMS public key of the tree with its root, RFC 8554, Section 5.3: the two typecodes,
    /// I and the root.
    pub(crate) fn publicKey(&self, root: &[u8; hashLength]) -> [u8; LevelType::publicKeyLength] {
        let mut publicKey = [0u8; LevelType::publicKeyLength];
        publicKey[..4].copy_from_slice(&self.kind.tree.code().to_be_bytes());
        publicKey[4..8].copy_from_slice(&self.kind.oneTimeSignature.code().to_be_bytes());
        publicKey[8..8 + identifierLength].copy_from_slice(&self.identifier);
        publicKey[8 + identifierLength..].copy_from_slice(root);
        publicKey
    }

    /// The tree under leaf q of a tree of the level above, with the type of its level, as
    /// `hss_generate_child_seed_I_value` derives its seed and its identifier.
    pub(crate) fn child(&self, q: u32, kind: LevelType) -> MerkleTree {
        let derivation = self.derivation();
        MerkleTree::new(kind, derivation.childIdentifier(q), derivation.childSeed(q))
    }

    /// Appends the LMS signature of a message with leaf q, RFC 8554, Algorithm 6, as
    /// `generate_merkle_signature` and `hss_sign_finalize` write it: q, the one-time signature
    /// with the randomizer of leaf q, the tree typecode and the authentication path.
    pub(crate) fn appendSignature(
        &self,
        q: u32,
        message: &[u8],
        authenticationPath: &[[u8; hashLength]],
        signature: &mut Vec<u8>,
    ) {
        debug_assert_eq!(authenticationPath.len(), self.height() as usize);
        let derivation = self.derivation();
        let randomizer = derivation.randomizer(q);
        let messageHash = OneTimeSignature::messageHash(&self.identifier, q, &randomizer, message);
        signature.extend_from_slice(&q.to_be_bytes());
        self.oneTimeSignature().appendSignature(
            &self.identifier,
            q,
            &derivation,
            &randomizer,
            &messageHash,
            signature,
        );
        signature.extend_from_slice(&self.kind.tree.code().to_be_bytes());
        for node in authenticationPath {
            signature.extend_from_slice(node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;
    use crate::testInputs::{identifierAndSeed, sequenceBytes};
    use crate::{LevelType, OneTimeSignature, OneTimeSignatureType, TreeType};
    use OQSNativeAlgorithmTests::OutputDigest;
    use OQSNativeSHA2::SHA256;

    fn tree() -> MerkleTree {
        let (identifier, seed) = identifierAndSeed();
        MerkleTree::new(
            LevelType::new(TreeType::height5, OneTimeSignatureType::winternitz1),
            identifier,
            seed,
        )
    }

    #[test]
    fn internalNodesAreTheNodesOfHashSigs() {
        // `OQS_LMS_NAMESPACE_hss_combine_internal_nodes` of the C oracle for the node 0x123,
        // with the sequences of the seeds 4 and 5 as the left and the right child.
        let left: [u8; 32] = sequenceBytes(32, 4).try_into().expect("32 bytes");
        let right: [u8; 32] = sequenceBytes(32, 5).try_into().expect("32 bytes");
        assert_eq!(
            OutputDigest::of(&tree().internalNode(0x123, &left, &right)),
            "d9456133c05dc049b18e1e36d0617d691ec90a2d663a69498eeb4c335052098e"
        );
    }

    #[test]
    fn leafNodesHashTheOneTimePublicKeyAsSection5Point3OfRFC8554Says() {
        let tree = tree();
        let publicKey = OneTimeSignature::new(OneTimeSignatureType::winternitz1).publicKey(
            &tree.identifier,
            7,
            &tree.derivation(),
        );
        // I, u32str(2^5 + 7), u16str(D_LEAF) and K, written out by hand.
        let mut input = tree.identifier.to_vec();
        input.extend_from_slice(&[0, 0, 0, 39, 0x82, 0x82]);
        input.extend_from_slice(&publicKey);
        assert_eq!(tree.leafNode(7), SHA256::hash(&input));
    }

    #[test]
    fn publicKeysAndChildrenFollowTheLayoutsOfHashSigs() {
        let tree = tree();
        let root = [0x5A; 32];
        let publicKey = tree.publicKey(&root);
        assert_eq!(&publicKey[..8], &[0, 0, 0, 5, 0, 0, 0, 1]);
        assert_eq!(&publicKey[8..24], &tree.identifier);
        assert_eq!(&publicKey[24..], &root);
        // `hss_generate_child_seed_I_value` of the C oracle for leaf 5.
        let child = tree.child(
            5,
            LevelType::new(TreeType::height10, OneTimeSignatureType::winternitz8),
        );
        assert_eq!(
            OutputDigest::of(&child.seed),
            "9094d27ea43ebf1e50e6efeaff39ed604f752e08fc31a89aa6569fa342be37b0"
        );
        assert_eq!(
            OutputDigest::of(&child.identifier),
            "a617d9a5b3617474b57cf61e141f108a843d6c1fa6e15483bb956f8ebb4ed7d0"
        );
        assert_eq!(child.height(), 10);
    }
}
