use crate::{
    BDSState, BigEndian, CoreHash, HashAddress, KeyedHash, Parameters, SigningFailure, WOTS,
};
use OQSNativeDomain::RandomGenerating;
use alloc::vec;
use alloc::vec::Vec;

/// The key generation and the signature of `xmss_core_fast.c` for one set of parameters and one
/// `CoreHash`.
///
/// A secret key here is the key after its object identifier, as the C code sees it: the index,
/// SK_SEED, SK_PRF, the root, PUB_SEED, the 2 d - 1 BDS states and, for XMSS^MT, the d - 1
/// WOTS+ signatures of the roots of the current trees below the top layer.
pub(crate) struct CoreAlgorithms<'parameters> {
    parameters: &'parameters Parameters,
    function: CoreHash,
}

impl<'parameters> CoreAlgorithms<'parameters> {
    /// Makes the algorithms of a set of parameters with the core hash of a set.
    pub(crate) fn new(parameters: &'parameters Parameters, function: CoreHash) -> Self {
        CoreAlgorithms {
            parameters,
            function,
        }
    }

    /// The offset of SK_SEED, after the index.
    fn secretSeedOffset(&self) -> usize {
        self.parameters.indexLength
    }

    /// The offset of the root, after SK_SEED and SK_PRF.
    fn rootOffset(&self) -> usize {
        self.parameters.indexLength + 2 * self.parameters.hashLength
    }

    /// The offset of PUB_SEED, after the root.
    fn publicSeedOffset(&self) -> usize {
        self.parameters.indexLength + 3 * self.parameters.hashLength
    }

    /// The key pair of a zeroed secret key, as `xmss_core_keypair` and `xmssmt_core_keypair`.
    ///
    /// The key draws 2 n random bytes for SK_SEED and SK_PRF, then n bytes for PUB_SEED. Each
    /// layer below the top computes the root of its first tree, and the layer above signs that
    /// root with its first WOTS+ key. The public key gets the root of the top tree and PUB_SEED.
    pub(crate) fn keyPair(
        &self,
        publicKey: &mut [u8],
        secretKey: &mut [u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<(), SigningFailure> {
        let parameters = self.parameters;
        let hashLength = parameters.hashLength;
        let layerCount = parameters.layerCount as usize;
        let (mut states, wotsSignatures) =
            BDSState::deserialized(parameters, secretKey, 2 * layerCount - 1)?;
        for state in &mut states {
            state.restart();
        }
        secretKey[..parameters.indexLength].fill(0);
        let secretSeed = self.secretSeedOffset();
        random.fillRandomBytes(&mut secretKey[secretSeed..secretSeed + 2 * hashLength]);
        let publicSeed = self.publicSeedOffset();
        random.fillRandomBytes(&mut secretKey[publicSeed..publicSeed + hashLength]);
        publicKey[hashLength..2 * hashLength]
            .copy_from_slice(&secretKey[publicSeed..publicSeed + hashLength]);
        let mut seedBytes = [0u8; 64];
        seedBytes[..hashLength].copy_from_slice(&secretKey[secretSeed..secretSeed + hashLength]);
        let seed = &seedBytes[..hashLength];
        let hash = KeyedHash::new(
            parameters,
            self.function,
            &secretKey[publicSeed..publicSeed + hashLength],
        );
        let mut address = HashAddress::default();
        address.setLayer(0);
        for (layer, state) in states.iter_mut().enumerate().take(layerCount) {
            let root = state.initializeTree(secretKey, &hash, seed, &address)?;
            publicKey[..hashLength].copy_from_slice(&root[..hashLength]);
            if layer + 1 < layerCount {
                address.setLayer(layer as u32 + 1);
                let start = wotsSignatures + layer * parameters.wotsSignatureLength;
                WOTS::sign(
                    &hash,
                    &mut secretKey[start..start + parameters.wotsSignatureLength],
                    &root[..hashLength],
                    seed,
                    &mut address,
                );
            }
        }
        let root = self.rootOffset();
        secretKey[root..root + hashLength].copy_from_slice(&publicKey[..hashLength]);
        BDSState::serialize(&states, parameters, secretKey)
    }

    /// Checks the index of a secret key before a signature, as both signature functions do.
    /// From the last index on, the C code wipes the key after its object identifier. At the last
    /// index it then signs with the wiped key, and past it the signature fails.
    fn checkedIndex(&self, secretKey: &mut [u8]) -> Result<u64, SigningFailure> {
        let index = BigEndian::read(&secretKey[..self.parameters.indexLength]);
        let lastIndex = self.parameters.lastIndex();
        if index >= lastIndex {
            secretKey
                .get_mut(..self.parameters.secretKeyLength)
                .ok_or(SigningFailure::undefined)?
                .fill(0);
            if index > lastIndex {
                return Err(SigningFailure::exhausted);
            }
        }
        Ok(index)
    }

    /// The seeds that a signature copies out of the key: SK_SEED, SK_PRF and PUB_SEED.
    fn seeds(&self, secretKey: &[u8]) -> ([u8; 64], [u8; 64], [u8; 64]) {
        let hashLength = self.parameters.hashLength;
        let mut secretSeed = [0u8; 64];
        let mut prfKey = [0u8; 64];
        let mut publicSeed = [0u8; 64];
        let start = self.secretSeedOffset();
        secretSeed[..hashLength].copy_from_slice(&secretKey[start..start + hashLength]);
        prfKey[..hashLength]
            .copy_from_slice(&secretKey[start + hashLength..start + 2 * hashLength]);
        let start = self.publicSeedOffset();
        publicSeed[..hashLength].copy_from_slice(&secretKey[start..start + hashLength]);
        (secretSeed, prfKey, publicSeed)
    }

    /// The randomness R and the digest of a message at an index: R = PRF(SK_PRF, toByte(idx,
    /// 32)) and H_msg(R, root, idx, M) with the root that the key holds now.
    fn messageDigest(
        &self,
        hash: &KeyedHash,
        prfKey: &[u8],
        secretKey: &[u8],
        index: u64,
        message: &[u8],
    ) -> ([u8; 64], [u8; 64]) {
        let hashLength = self.parameters.hashLength;
        let mut indexBytes = [0u8; 32];
        BigEndian::write(index, &mut indexBytes);
        let mut randomness = [0u8; 64];
        hash.prf(&mut randomness, &indexBytes, prfKey);
        let root = self.rootOffset();
        let mut digest = [0u8; 64];
        hash.messageHash(
            &mut digest,
            &randomness,
            &secretKey[root..root + hashLength],
            index,
            message,
        );
        (randomness, digest)
    }

    /// The XMSS signature of a message, as `xmss_core_sign`, which advances the secret key. The
    /// signature is the index, R, the WOTS+ signature of the digest and the authentication path.
    pub(crate) fn singleTreeSignature(
        &self,
        secretKey: &mut [u8],
        message: &[u8],
    ) -> Result<Vec<u8>, SigningFailure> {
        let parameters = self.parameters;
        let hashLength = parameters.hashLength;
        let treeHeight = parameters.treeHeight;
        let (mut states, _) = BDSState::deserialized(parameters, secretKey, 1)?;
        let index = self.checkedIndex(secretKey)?;
        let (secretSeed, prfKey, publicSeed) = self.seeds(secretKey);
        let secretSeed = &secretSeed[..hashLength];
        // The C code keeps the index in 4 bytes.
        BigEndian::write(index + 1, &mut secretKey[..4]);
        let hash = KeyedHash::new(parameters, self.function, &publicSeed);
        let (randomness, digest) = self.messageDigest(&hash, &prfKey, secretKey, index, message);
        let mut signature = vec![0u8; parameters.signatureLength];
        BigEndian::write(index, &mut signature[..4]);
        signature[4..4 + hashLength].copy_from_slice(&randomness[..hashLength]);
        let mut otsAddress = HashAddress::default();
        otsAddress.setType(HashAddress::otsType);
        otsAddress.setOTS(index as u32);
        let wotsStart = 4 + hashLength;
        let pathStart = wotsStart + parameters.wotsSignatureLength;
        WOTS::sign(
            &hash,
            &mut signature[wotsStart..pathStart],
            &digest[..hashLength],
            secretSeed,
            &mut otsAddress,
        );
        // The path of this leaf was computed in the previous signature.
        signature[pathStart..]
            .copy_from_slice(states[0].authenticationPathBytes(secretKey, parameters)?);
        if index < (1 << treeHeight) - 1 {
            let state = &mut states[0];
            state.advanceAuthenticationPath(secretKey, index, &hash, secretSeed, &otsAddress)?;
            state.updateTreeHashes(secretKey, treeHeight >> 1, &hash, secretSeed, &otsAddress)?;
        }
        BDSState::serialize(&states, parameters, secretKey)?;
        Ok(signature)
    }

    /// The XMSS^MT signature of a message, as `xmssmt_core_sign`, which advances the secret key.
    ///
    /// The signature is the index, R, then for each layer a WOTS+ signature and an
    /// authentication path: the bottom layer signs the digest, and each layer above signs the
    /// root of the tree below, with the WOTS+ signature that the key keeps. Then the BDS states
    /// of the current trees and of the next trees advance, and each tree that ends gives its
    /// place to its next tree, whose root the layer above signs.
    pub(crate) fn multiTreeSignature(
        &self,
        secretKey: &mut [u8],
        message: &[u8],
    ) -> Result<Vec<u8>, SigningFailure> {
        let parameters = self.parameters;
        let hashLength = parameters.hashLength;
        let treeHeight = parameters.treeHeight;
        let layerCount = parameters.layerCount;
        let fullHeight = parameters.fullHeight;
        let indexLength = parameters.indexLength;
        let wotsLength = parameters.wotsSignatureLength;
        let (mut states, wotsSignatures) =
            BDSState::deserialized(parameters, secretKey, 2 * layerCount as usize - 1)?;
        let index = self.checkedIndex(secretKey)?;
        let (secretSeed, prfKey, publicSeed) = self.seeds(secretKey);
        let secretSeed = &secretSeed[..hashLength];
        BigEndian::write(index + 1, &mut secretKey[..indexLength]);
        let hash = KeyedHash::new(parameters, self.function, &publicSeed);
        let (randomness, digest) = self.messageDigest(&hash, &prfKey, secretKey, index, message);
        let mut signature = Vec::with_capacity(parameters.signatureLength);
        let mut indexBytes = [0u8; 8];
        BigEndian::write(index, &mut indexBytes[..indexLength]);
        signature.extend_from_slice(&indexBytes[..indexLength]);
        signature.extend_from_slice(&randomness[..hashLength]);
        // The lowest layer signs the digest.
        let leafMask = (1u64 << treeHeight) - 1;
        let mut treeIndex = index >> treeHeight;
        let mut leafIndex = (index & leafMask) as u32;
        let mut otsAddress = HashAddress::default();
        otsAddress.setType(HashAddress::otsType);
        otsAddress.setLayer(0);
        otsAddress.setTree(treeIndex);
        otsAddress.setOTS(leafIndex);
        let start = signature.len();
        signature.resize(start + wotsLength, 0);
        WOTS::sign(
            &hash,
            &mut signature[start..],
            &digest[..hashLength],
            secretSeed,
            &mut otsAddress,
        );
        signature.extend_from_slice(states[0].authenticationPathBytes(secretKey, parameters)?);
        for (layer, state) in states.iter().enumerate().take(layerCount as usize).skip(1) {
            let start = wotsSignatures + (layer - 1) * wotsLength;
            let kept = secretKey
                .get(start..start + wotsLength)
                .ok_or(SigningFailure::undefined)?;
            signature.extend_from_slice(kept);
            signature.extend_from_slice(state.authenticationPathBytes(secretKey, parameters)?);
        }
        let mut updates = treeHeight >> 1;
        let mut address = HashAddress::default();
        address.setTree(treeIndex.wrapping_add(1));
        let next = layerCount as usize;
        // The next tree of the lowest layer gets a leaf at each signature while it exists.
        if (1 + treeIndex)
            .wrapping_mul(1 << treeHeight)
            .wrapping_add(u64::from(leafIndex))
            < 1 << fullHeight
        {
            states[next].addNextLeaf(secretKey, &hash, secretSeed, &address)?;
        }
        let mut lastSwappedLayer: i64 = -1;
        for layer in 0..layerCount {
            let layerHeight = treeHeight * layer;
            let layerSpan = (1u64 << (layerHeight + treeHeight)) - 1;
            if (index + 1) & layerSpan != 0 {
                // The tree of this layer goes on.
                leafIndex = ((index >> layerHeight) & leafMask) as u32;
                treeIndex = index >> (layerHeight + treeHeight);
                address.setLayer(layer);
                // The C code passes the tree index through `uint32_t` here.
                address.setTree(u64::from(treeIndex as u32));
                let state = &mut states[layer as usize];
                if i64::from(layer) == lastSwappedLayer + 1 {
                    state.advanceAuthenticationPath(
                        secretKey,
                        u64::from(leafIndex),
                        &hash,
                        secretSeed,
                        &address,
                    )?;
                }
                updates =
                    state.updateTreeHashes(secretKey, updates, &hash, secretSeed, &address)?;
                address.setTree(treeIndex.wrapping_add(1));
                let hasNextTree = (1 + treeIndex)
                    .wrapping_mul(1 << treeHeight)
                    .wrapping_add(u64::from(leafIndex))
                    < 1 << (fullHeight - layerHeight);
                if hasNextTree && layer > 0 && updates > 0 {
                    // Only a tree below the top layer has a next tree.
                    let nextState = states
                        .get_mut(next + layer as usize)
                        .ok_or(SigningFailure::undefined)?;
                    if nextState.nextLeaf() < 1 << fullHeight {
                        nextState.addNextLeaf(secretKey, &hash, secretSeed, &address)?;
                        updates -= 1;
                    }
                }
            } else if index < parameters.lastIndex() {
                // The tree of this layer ends, and its next tree takes its place.
                BDSState::swap(
                    &mut states,
                    next + layer as usize,
                    layer as usize,
                    secretKey,
                    parameters,
                )?;
                otsAddress.setLayer(layer + 1);
                let treeShift = (layer + 2) * treeHeight;
                otsAddress.setTree(
                    (index + 1)
                        .checked_shr(treeShift)
                        .ok_or(SigningFailure::undefined)?,
                );
                let parentShift = (layer + 1) * treeHeight;
                let parentLeaf = (index >> parentShift).wrapping_add(1) & leafMask;
                otsAddress.setOTS(parentLeaf as u32);
                let root = states[layer as usize].firstStackNode(secretKey, parameters)?;
                let mut rootBytes = [0u8; 64];
                rootBytes[..hashLength].copy_from_slice(root);
                let start = wotsSignatures + layer as usize * wotsLength;
                let target = secretKey
                    .get_mut(start..start + wotsLength)
                    .ok_or(SigningFailure::undefined)?;
                WOTS::sign(
                    &hash,
                    target,
                    &rootBytes[..hashLength],
                    secretSeed,
                    &mut otsAddress,
                );
                states[next + layer as usize].restart();
                // The WOTS+ signature counts as one update.
                updates = updates.wrapping_sub(1);
                lastSwappedLayer = i64::from(layer);
                states[layer as usize].completeTreeHashes();
            }
        }
        BDSState::serialize(&states, parameters, secretKey)?;
        Ok(signature)
    }
}
