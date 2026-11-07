use crate::parameters::{Parameters, privateKeyLength};
use crate::{LMS, LevelType, MerkleTree, PrivateKey, TreeBuilder, TreeState};
use OQSNativeDomain::{KeyStatePersisting, StatefulSigning};
use OQSNativeEntities::{OQSError, SecretBytes};
use alloc::vec::Vec;

/// The working key of hash-sigs: a secret key loaded once, with the trees of its levels, that
/// signs many messages without a new load, as `hss_generate_signature` signs with an
/// `hss_working_key`.
///
/// A load costs about one key generation for each level, because it builds every tree that
/// a signature goes through. Each signature then costs a few leaves: the leaf that signs, one
/// leaf of the next subtree of each tree, and one leaf of the next tree of each lower level.
/// Each signature advances the secret key and saves it before the signature comes back, and a
/// failed save releases no signature. The key in memory has advanced in both cases, so it
/// never signs twice with one state.
///
/// The parameter set comes from the secret key, as in hash-sigs. Each signature equals the
/// signature that liboqs makes with the same secret key, which loads the key again for each
/// signature.
pub struct LMSWorkingKey {
    parameters: &'static Parameters,
    privateKey: PrivateKey,
    auxiliaryData: Vec<u8>,
    levels: Vec<Level>,
    isExhausted: bool,
}

/// One level of a working key: its tree at the leaf that signs next, the signed public key that
/// the level above gives it, and the next tree of the level in building.
struct Level {
    state: TreeState,
    signedPublicKey: Vec<u8>,
    nextTree: Option<TreeBuilder>,
}

impl LMSWorkingKey {
    /// Loads a serialized secret key for a parameter set, as `hss_load_private_key` does
    /// without aux data.
    pub(crate) fn load(
        parameters: &'static Parameters,
        secretKey: &[u8],
    ) -> Result<Self, OQSError> {
        let privateKey = PrivateKey::ofSecretKey(secretKey)?;
        // The C code copies a signature of the parameter set of the key into a buffer of the
        // length of the scheme, so a longer signature would overflow it. Such a key is refused
        // before it signs.
        if privateKey.parameterSet().signatureLength() > parameters.description.signatureLength {
            return Err(OQSError::operationFailed);
        }
        let digits = Self::leafIndices(&privateKey.levels, privateKey.count());
        let mut levels: Vec<Level> = Vec::with_capacity(digits.len());
        for (place, (kind, index)) in privateKey.levels.iter().zip(&digits).enumerate() {
            let tree = match levels.last() {
                None => MerkleTree::new(*kind, privateKey.identifier(), privateKey.seed()),
                Some(parent) => parent.state.tree().child(parent.state.index(), *kind),
            };
            let state =
                TreeState::computed(tree, *index, TreeState::subtreeHeight(kind.tree.height()));
            let mut level = Level {
                state,
                signedPublicKey: Vec::new(),
                nextTree: None,
            };
            if let Some(parent) = levels.last() {
                level.signedPublicKey = Self::signedPublicKey(parent, &level.state);
            }
            levels.push(level);
            if place > 0 {
                let nextTree = Self::nextTree(&levels, place);
                levels[place].nextTree = nextTree;
            }
        }
        Ok(LMSWorkingKey {
            parameters,
            auxiliaryData: secretKey[privateKeyLength..].to_vec(),
            privateKey,
            levels,
            isExhausted: false,
        })
    }

    /// The leaf index of each level at a count, the top level first, as
    /// `hss_generate_working_key` splits the count.
    fn leafIndices(levels: &[LevelType], count: u64) -> Vec<u32> {
        let mut rest = count;
        let mut indices: Vec<u32> = levels
            .iter()
            .rev()
            .map(|kind| {
                let height = kind.tree.height();
                let index = (rest & ((1 << height) - 1)) as u32;
                rest >>= height;
                index
            })
            .collect();
        indices.reverse();
        indices
    }

    /// The signed public key of a tree: the LMS signature of its public key by the current
    /// leaf of its parent, then the public key, as `hss_create_signed_public_key` makes it.
    fn signedPublicKey(parent: &Level, child: &TreeState) -> Vec<u8> {
        let publicKey = child.publicKey();
        let mut signedPublicKey = Vec::new();
        parent
            .state
            .appendSignature(&publicKey, &mut signedPublicKey);
        signedPublicKey.extend_from_slice(&publicKey);
        signedPublicKey
    }

    /// The builder of the tree that follows the current tree of a level below the top: the
    /// child of the next leaf of the parent, or of the first leaf of the next tree of the
    /// parent when the parent is at its last leaf. `None` when no tree follows.
    fn nextTree(levels: &[Level], place: usize) -> Option<TreeBuilder> {
        let parent = &levels[place - 1];
        let kind = levels[place].state.tree().kind;
        let index = parent.state.index() + 1;
        let tree = if index < parent.state.tree().leafCount() {
            parent.state.tree().child(index, kind)
        } else {
            parent.nextTree.as_ref()?.tree().child(0, kind)
        };
        let subtreeHeight = TreeState::subtreeHeight(kind.tree.height());
        Some(TreeState::builder(tree, 0, subtreeHeight))
    }

    /// The serialized secret key in its current state: the private key, then the aux data,
    /// as `oqs_serialize_lms_key` writes it.
    pub fn secretKey(&self) -> SecretBytes {
        let mut bytes = Vec::with_capacity(privateKeyLength + self.auxiliaryData.len());
        bytes.extend_from_slice(&self.privateKey.bytes);
        bytes.extend_from_slice(&self.auxiliaryData);
        SecretBytes::new(bytes)
    }

    /// Signs a message, advances the secret key and saves the advanced key through
    /// `persisting`. The signature comes back only when the save succeeds.
    ///
    /// A key after its last signature is `OQSError::keyExhausted`, and a failed save is
    /// `OQSError::persistenceFailed`.
    pub fn sign(
        &mut self,
        message: &[u8],
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        let signature = self.signatureWithAdvancedKey(message)?;
        if !self.isExhausted {
            self.advanceTrees();
        }
        let secretKey = self.secretKey();
        LMS::of(self.parameters).releaseSignature(signature, secretKey.bytes(), persisting)
    }

    /// The signature of a message and the advanced secret key, as the one signature of a
    /// key that liboqs loads for it. The trees stay where they are, so the working key ends
    /// here.
    pub(crate) fn signatureOnce(
        mut self,
        message: &[u8],
    ) -> Result<(Vec<u8>, SecretBytes), OQSError> {
        let signature = self.signatureWithAdvancedKey(message)?;
        Ok((signature, self.secretKey()))
    }

    /// The signature of a message by the current leaf of the bottom tree, with the signed
    /// public keys of the levels below the top, and the private key advanced as
    /// `hss_advance_count` advances it: the count of the next signature, or a key filled with
    /// `0xFF` after the last signature.
    fn signatureWithAdvancedKey(&mut self, message: &[u8]) -> Result<Vec<u8>, OQSError> {
        if self.isExhausted {
            return Err(OQSError::keyExhausted);
        }
        let parameterSet = self.privateKey.parameterSet();
        let mut signature = Vec::with_capacity(parameterSet.signatureLength());
        signature.extend_from_slice(&((self.levels.len() - 1) as u32).to_be_bytes());
        for level in &self.levels[1..] {
            signature.extend_from_slice(&level.signedPublicKey);
        }
        let bottom = self.levels.last().expect("at least one level");
        bottom.state.appendSignature(message, &mut signature);
        let count = self.privateKey.count();
        if count == parameterSet.maximumCount() {
            self.privateKey.markExhausted();
            self.isExhausted = true;
        } else {
            self.privateKey.setCount(count + 1);
        }
        Ok(signature)
    }

    /// Moves the trees to the next signature: the bottom tree moves to its next leaf, each
    /// next tree gets one more leaf, and an exhausted tree gives way to its next tree.
    fn advanceTrees(&mut self) {
        for level in &mut self.levels[1..] {
            if let Some(nextTree) = &mut level.nextTree {
                nextTree.step();
            }
        }
        let bottom = self.levels.len() - 1;
        self.levels[bottom].state.advance();
        if self.levels[bottom].state.isExhausted() {
            self.replaceTree(bottom);
        }
    }

    /// Replaces the exhausted tree of a level below the top with its next tree, after the
    /// parent moves to its next leaf, which signs the new tree.
    fn replaceTree(&mut self, place: usize) {
        let parent = place - 1;
        self.levels[parent].state.advance();
        if self.levels[parent].state.isExhausted() {
            self.replaceTree(parent);
        }
        let mut builder = self.levels[place]
            .nextTree
            .take()
            .expect("a next tree before the last count");
        // The next tree gets one leaf for each signature, so it is complete here unless the
        // key was loaded in the middle of the current tree.
        builder.complete();
        let subtreeHeight = TreeState::subtreeHeight(builder.tree().height());
        let state = TreeState::ofCompleteBuilder(builder, 0, subtreeHeight);
        self.levels[place].signedPublicKey = Self::signedPublicKey(&self.levels[parent], &state);
        self.levels[place].state = state;
        self.levels[place].nextTree = Self::nextTree(&self.levels, place);
    }
}

#[cfg(test)]
mod tests {
    use super::LMSWorkingKey;
    use crate::parameters::lmsSHA256H25W1;
    use crate::{LMS, LevelType, OneTimeSignatureType, PrivateKey, TreeType};
    use OQSNativeDomain::{KeyStatePersisting, StatefulSigning};
    use OQSNativeEntities::OQSError;

    /// A store that keeps each saved key.
    struct RecordingStore(Vec<Vec<u8>>);

    impl KeyStatePersisting for RecordingStore {
        fn persist(&mut self, secretKey: &[u8]) -> Result<(), OQSError> {
            self.0.push(secretKey.to_vec());
            Ok(())
        }
    }

    /// The private key of three levels of height 5 with the Winternitz parameter 4 at a count.
    /// hash-sigs reads keys of up to eight levels, and liboqs signs such a key under any set
    /// whose signature has room for it, such as `LMS_SHA256_H25_W1`.
    fn threeLevelKey(count: u64) -> Vec<u8> {
        let level = LevelType::new(TreeType::height5, OneTimeSignatureType::winternitz4);
        let mut privateKey = PrivateKey::new(&[level; 3], &[0x31; 32], &[0x72; 16]);
        privateKey.setCount(count);
        privateKey.bytes.to_vec()
    }

    /// The signature of a key at a count by a working key loaded for it alone.
    fn freshSignature(count: u64, message: &[u8]) -> Vec<u8> {
        let key = LMSWorkingKey::load(&lmsSHA256H25W1, &threeLevelKey(count)).expect("a key");
        key.signatureOnce(message).expect("a signature").0
    }

    #[test]
    fn aWorkingKeySignsAcrossTreesOfEveryLevelAsFreshLoadsDo() {
        // From the count 1015 the walk crosses the end of a bottom tree at 1024, which is also
        // the end of a middle tree, and the end of a bottom tree at 1056. The next trees of a
        // key loaded in the middle of a tree are built at the first change.
        let scheme = LMS::lmsSHA256H25W1;
        let start = 1015;
        let mut workingKey = scheme
            .workingKey(&threeLevelKey(start))
            .expect("a working key");
        let mut store = RecordingStore(Vec::new());
        for count in start..1060 {
            let message = count.to_be_bytes();
            let signature = workingKey.sign(&message, &mut store).expect("a signature");
            assert_eq!(
                store.0.last(),
                Some(&threeLevelKey(count + 1)),
                "count {count}"
            );
            assert_eq!(
                workingKey.secretKey().bytes(),
                &threeLevelKey(count + 1)[..]
            );
            let isChecked = count < start + 2 || (1022..1026).contains(&count) || count >= 1054;
            if isChecked {
                assert_eq!(signature, freshSignature(count, &message), "count {count}");
            }
            assert!(
                scheme.isValidSignature(&signature, &message, &publicKey()),
                "count {count}"
            );
        }
    }

    /// The public key of the three-level key: the level count and the public key of the top
    /// tree.
    fn publicKey() -> Vec<u8> {
        let privateKey = PrivateKey::ofSecretKey(&threeLevelKey(0)).expect("a key");
        let tree = crate::MerkleTree::new(
            privateKey.levels[0],
            privateKey.identifier(),
            privateKey.seed(),
        );
        let state = crate::TreeState::computed(tree.clone(), 0, 5);
        let mut key = 3u32.to_be_bytes().to_vec();
        key.extend_from_slice(&tree.publicKey(state.root()));
        key
    }

    #[test]
    fn theLastSignatureFillsTheKeyWithFFAndEndsTheWorkingKey() {
        let level = LevelType::new(TreeType::height5, OneTimeSignatureType::winternitz4);
        let mut privateKey = PrivateKey::new(&[level; 2], &[0x31; 32], &[0x72; 16]);
        privateKey.setCount(1021);
        // Two levels of the Winternitz parameter 4 fit the signature of `LMS_SHA256_H25_W1`.
        let mut workingKey = LMS::lmsSHA256H25W1
            .workingKey(&privateKey.bytes)
            .expect("a working key");
        let mut store = RecordingStore(Vec::new());
        for count in 1021..1024 {
            workingKey.sign(b"m", &mut store).expect("a signature");
            if count < 1023 {
                assert_eq!(
                    u64::from_be_bytes(
                        store.0.last().expect("a key")[..8]
                            .try_into()
                            .expect("8 bytes")
                    ),
                    count + 1
                );
            }
        }
        assert_eq!(store.0.last(), Some(&vec![0xFF; 64]));
        assert_eq!(
            workingKey.sign(b"m", &mut store),
            Err(OQSError::keyExhausted)
        );
        assert_eq!(store.0.len(), 3);
        assert_eq!(
            LMS::lmsSHA256H5W8H5W8.workingKey(&[0xFF; 64]).map(|_| ()),
            Err(OQSError::keyExhausted)
        );
    }

    #[test]
    fn aKeyWhoseSignatureIsLongerThanTheSignatureOfTheSchemeIsRefused() {
        // Three levels of 7160 bytes do not fit the 5104 bytes of `LMS_SHA256_H25_W2`, so the C
        // code would write past its buffer. The key fits `LMS_SHA256_H25_W1`.
        assert_eq!(
            LMS::lmsSHA256H25W2
                .workingKey(&threeLevelKey(0))
                .map(|_| ()),
            Err(OQSError::operationFailed)
        );
        assert!(LMS::lmsSHA256H25W1.workingKey(&threeLevelKey(0)).is_ok());
    }
}
