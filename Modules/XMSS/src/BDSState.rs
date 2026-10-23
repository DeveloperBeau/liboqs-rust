use crate::{BigEndian, HashAddress, KeyedHash, MerkleTree, Parameters, SigningFailure};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;

/// One treehash instance of the BDS traversal, as `treehash_inst` of `xmss_core_fast.c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TreeHashInstance {
    /// The height of the node that the instance computes, `h`.
    height: u8,
    /// The index of the next leaf that the instance hashes, `next_idx`.
    nextIndex: u64,
    /// The number of nodes of the instance on the stack of the state, `stackusage`.
    stackUsage: u8,
    /// Not zero when the instance holds its node, `completed`.
    completed: u8,
    /// The offset of the node of the instance in the key.
    node: usize,
}

/// The BDS state of one tree, as `bds_state` of `xmss_core_fast.c`: the traversal of Buchmann,
/// Dahmen and Szydlo that keeps the authentication path of the next leaf ready.
///
/// The C state points into the secret key for its arrays, and copies its counters out of the key
/// and back. This state keeps the offsets of the arrays in the key, which is the key after its
/// object identifier, and its counters. Each access computes the place of a node with the
/// unsigned 32-bit arithmetic of the C code and checks that the place lies in the key. A state
/// that no key generation makes can send the C code outside its buffers, and then the access
/// fails here with `SigningFailure::undefined`.
pub(crate) struct BDSState {
    stack: usize,
    stackOffset: u32,
    stackLevels: usize,
    authenticationPath: usize,
    keep: usize,
    treeHash: Vec<TreeHashInstance>,
    nextLeaf: u64,
}

/// The place of `length` bytes at `base + offset` in a key of `keyLength` bytes. The offset is
/// the unsigned 32-bit value that the C code adds to a pointer into the key.
fn place(
    keyLength: usize,
    base: usize,
    offset: u32,
    length: usize,
) -> Result<Range<usize>, SigningFailure> {
    let start = base
        .checked_add(offset as usize)
        .ok_or(SigningFailure::undefined)?;
    let end = start.checked_add(length).ok_or(SigningFailure::undefined)?;
    if end > keyLength {
        return Err(SigningFailure::undefined);
    }
    Ok(start..end)
}

/// Copies bytes of the key to another place of the key, as `memcpy` does. Overlapping places,
/// which only a forged state gives, are undefined for `memcpy`.
fn copyWithinKey(
    key: &mut [u8],
    source: Range<usize>,
    destination: usize,
) -> Result<(), SigningFailure> {
    let target = place(key.len(), destination, 0, source.len())?;
    if source.start != target.start && source.start < target.end && target.start < source.end {
        return Err(SigningFailure::undefined);
    }
    key.copy_within(source, destination);
    Ok(())
}

/// Swaps two places of the same length in the key, as `memswap` of `deep_state_swap`.
fn swapWithinKey(
    key: &mut [u8],
    first: usize,
    second: usize,
    length: usize,
) -> Result<(), SigningFailure> {
    if length == 0 || first == second {
        return Ok(());
    }
    let (low, high) = if first < second {
        (first, second)
    } else {
        (second, first)
    };
    place(key.len(), high, 0, length)?;
    if low + length > high {
        return Err(SigningFailure::undefined);
    }
    let (left, right) = key.split_at_mut(high);
    left[low..low + length].swap_with_slice(&mut right[..length]);
    Ok(())
}

/// A right shift of the `int` index of `bds_state_update`. A shift by 32 or more is undefined in
/// C, and a negative index shifts in its sign, as GCC and Clang do.
fn shiftedLeafIndex(index: i32, amount: u32) -> Result<i32, SigningFailure> {
    index.checked_shr(amount).ok_or(SigningFailure::undefined)
}

impl BDSState {
    /// The OTS, L-tree and hash tree addresses of a tree, with the layer and the tree of an
    /// address, as each traversal function of the C code makes them.
    fn addresses(address: &HashAddress) -> (HashAddress, HashAddress, HashAddress) {
        let mut otsAddress = HashAddress::default();
        let mut lTreeAddress = HashAddress::default();
        let mut nodeAddress = HashAddress::default();
        otsAddress.copySubtree(address);
        otsAddress.setType(HashAddress::otsType);
        lTreeAddress.copySubtree(address);
        lTreeAddress.setType(HashAddress::lTreeType);
        nodeAddress.copySubtree(address);
        nodeAddress.setType(HashAddress::hashTreeType);
        (otsAddress, lTreeAddress, nodeAddress)
    }

    /// The states of a key, as `xmssmt_deserialize_state`: the counters are read, and the arrays
    /// stay in the key. Returns the states and the offset of what follows them, the WOTS+
    /// signatures of an XMSS^MT key.
    pub(crate) fn deserialized(
        parameters: &Parameters,
        key: &[u8],
        count: usize,
    ) -> Result<(Vec<BDSState>, usize), SigningFailure> {
        let hashLength = parameters.hashLength;
        let treeHeight = parameters.treeHeight as usize;
        let read = |offset: usize, length: usize| -> Result<u64, SigningFailure> {
            let range = place(key.len(), offset, 0, length)?;
            Ok(BigEndian::read(&key[range]))
        };
        let mut offset = parameters.indexLength + 4 * hashLength;
        let mut states = Vec::with_capacity(count);
        for _ in 0..count {
            let stack = offset;
            offset += (treeHeight + 1) * hashLength;
            let stackOffset = read(offset, 4)? as u32;
            offset += 4;
            let stackLevels = offset;
            offset += treeHeight + 1;
            let authenticationPath = offset;
            offset += treeHeight * hashLength;
            let keep = offset;
            offset += (treeHeight >> 1) * hashLength;
            let mut treeHash = Vec::with_capacity(treeHeight);
            for _ in 0..treeHeight {
                let height = read(offset, 1)? as u8;
                let nextIndex = read(offset + 1, 4)?;
                let stackUsage = read(offset + 5, 1)? as u8;
                let completed = read(offset + 6, 1)? as u8;
                treeHash.push(TreeHashInstance {
                    height,
                    nextIndex,
                    stackUsage,
                    completed,
                    node: offset + 7,
                });
                offset += 7 + hashLength;
            }
            // The retained nodes of `retain` have no bytes for k = 0.
            let nextLeaf = read(offset, 4)?;
            offset += 4;
            states.push(BDSState {
                stack,
                stackOffset,
                stackLevels,
                authenticationPath,
                keep,
                treeHash,
                nextLeaf,
            });
        }
        Ok((states, offset))
    }

    /// Writes the counters of states back into the key, as `xmssmt_serialize_state`. Each
    /// counter keeps the low bytes of its value.
    pub(crate) fn serialize(
        states: &[BDSState],
        parameters: &Parameters,
        key: &mut [u8],
    ) -> Result<(), SigningFailure> {
        let hashLength = parameters.hashLength;
        let treeHeight = parameters.treeHeight as usize;
        let mut write = |offset: usize, length: usize, value: u64| {
            let range = place(key.len(), offset, 0, length)?;
            BigEndian::write(value, &mut key[range]);
            Ok::<(), SigningFailure>(())
        };
        let mut offset = parameters.indexLength + 4 * hashLength;
        for state in states {
            offset += (treeHeight + 1) * hashLength;
            write(offset, 4, u64::from(state.stackOffset))?;
            offset += 4;
            offset += treeHeight + 1;
            offset += treeHeight * hashLength;
            offset += (treeHeight >> 1) * hashLength;
            for instance in &state.treeHash {
                write(offset, 1, u64::from(instance.height))?;
                write(offset + 1, 4, instance.nextIndex)?;
                write(offset + 5, 1, u64::from(instance.stackUsage))?;
                write(offset + 6, 1, u64::from(instance.completed))?;
                offset += 7 + hashLength;
            }
            write(offset, 4, state.nextLeaf)?;
            offset += 4;
        }
        Ok(())
    }

    /// The level of the node in a slot of the stack, `stacklevels[slot]`.
    fn level(&self, key: &[u8], slot: u32) -> Result<u8, SigningFailure> {
        let range = place(key.len(), self.stackLevels, slot, 1)?;
        Ok(key[range.start])
    }

    /// Sets the level of the node in a slot of the stack.
    fn setLevel(&self, key: &mut [u8], slot: u32, level: u8) -> Result<(), SigningFailure> {
        let range = place(key.len(), self.stackLevels, slot, 1)?;
        key[range.start] = level;
        Ok(())
    }

    /// The place of `count` nodes from a slot of the stack, `stack + slot * n`.
    fn stackPlace(
        &self,
        key: &[u8],
        slot: u32,
        count: usize,
        hashLength: usize,
    ) -> Result<Range<usize>, SigningFailure> {
        place(
            key.len(),
            self.stack,
            slot.wrapping_mul(hashLength as u32),
            count * hashLength,
        )
    }

    /// The place of the node at a height of the authentication path, `auth + height * n`.
    fn authenticationPlace(
        &self,
        key: &[u8],
        height: u32,
        hashLength: usize,
    ) -> Result<Range<usize>, SigningFailure> {
        place(
            key.len(),
            self.authenticationPath,
            height.wrapping_mul(hashLength as u32),
            hashLength,
        )
    }

    /// The place of a kept node, `keep + index * n`.
    fn keepPlace(
        &self,
        key: &[u8],
        index: u32,
        hashLength: usize,
    ) -> Result<Range<usize>, SigningFailure> {
        place(
            key.len(),
            self.keep,
            index.wrapping_mul(hashLength as u32),
            hashLength,
        )
    }

    /// The authentication path of the next leaf, h nodes.
    pub(crate) fn authenticationPathBytes<'key>(
        &self,
        key: &'key [u8],
        parameters: &Parameters,
    ) -> Result<&'key [u8], SigningFailure> {
        let range = place(
            key.len(),
            self.authenticationPath,
            0,
            parameters.treeHeight as usize * parameters.hashLength,
        )?;
        Ok(&key[range])
    }

    /// The first node of the stack, which holds the root of a completed tree.
    pub(crate) fn firstStackNode<'key>(
        &self,
        key: &'key [u8],
        parameters: &Parameters,
    ) -> Result<&'key [u8], SigningFailure> {
        let range = place(key.len(), self.stack, 0, parameters.hashLength)?;
        Ok(&key[range])
    }

    /// The index of the next leaf of the state, `next_leaf`.
    pub(crate) fn nextLeaf(&self) -> u64 {
        self.nextLeaf
    }

    /// Empties the stack and starts the state again at leaf 0, as `xmssmt_core_sign` does for a
    /// state that becomes the next tree.
    pub(crate) fn restart(&mut self) {
        self.stackOffset = 0;
        self.nextLeaf = 0;
    }

    /// Marks each treehash instance as completed.
    pub(crate) fn completeTreeHashes(&mut self) {
        for instance in &mut self.treeHash {
            instance.completed = 1;
        }
    }

    /// Computes the root of the tree of an address and the initial state, as `treehash_init`
    /// of a key generation: the authentication path of leaf 0, and the node of index 3 at each
    /// height for the treehash instances. The stack of the C code is a buffer of its own.
    pub(crate) fn initializeTree(
        &mut self,
        key: &mut [u8],
        hash: &KeyedHash,
        secretSeed: &[u8],
        address: &HashAddress,
    ) -> Result<[u8; 64], SigningFailure> {
        let parameters = hash.parameters();
        let hashLength = parameters.hashLength;
        let height = parameters.treeHeight;
        let (mut otsAddress, mut lTreeAddress, mut nodeAddress) = Self::addresses(address);
        let mut stack = vec![0u8; (height as usize + 1) * hashLength];
        let mut stackLevels = vec![0u32; height as usize + 1];
        let mut stackOffset = 0usize;
        for (instanceHeight, instance) in self.treeHash.iter_mut().enumerate() {
            instance.height = instanceHeight as u8;
            instance.completed = 1;
            instance.stackUsage = 0;
        }
        let slot = |index: usize| index * hashLength..(index + 1) * hashLength;
        for (count, index) in (0..1u32 << height).enumerate() {
            let count = count as u32;
            lTreeAddress.setLTree(index);
            otsAddress.setOTS(index);
            let leaf = MerkleTree::leaf(hash, secretSeed, &mut lTreeAddress, &mut otsAddress);
            stack[slot(stackOffset)].copy_from_slice(&leaf[..hashLength]);
            stackLevels[stackOffset] = 0;
            stackOffset += 1;
            if count == 3 {
                // The C code copies the slot above the new leaf, which the merge below then
                // overwrites with the leaf of index 3.
                let node = place(key.len(), self.treeHash[0].node, 0, hashLength)?;
                key[node].copy_from_slice(&stack[slot(stackOffset)]);
            }
            while stackOffset > 1 && stackLevels[stackOffset - 1] == stackLevels[stackOffset - 2] {
                let nodeHeight = stackLevels[stackOffset - 1];
                let top = &stack[slot(stackOffset - 1)];
                if count >> nodeHeight == 1 {
                    let target = self.authenticationPlace(key, nodeHeight, hashLength)?;
                    key[target].copy_from_slice(top);
                } else if nodeHeight < height && count >> nodeHeight == 3 {
                    let target = place(
                        key.len(),
                        self.treeHash[nodeHeight as usize].node,
                        0,
                        hashLength,
                    )?;
                    key[target].copy_from_slice(top);
                }
                nodeAddress.setTreeHeight(stackLevels[stackOffset - 1]);
                nodeAddress.setTreeIndex(index >> (stackLevels[stackOffset - 1] + 1));
                let children = (stackOffset - 2) * hashLength..stackOffset * hashLength;
                let parent = hash.nodeHash(&stack[children], &mut nodeAddress);
                stack[slot(stackOffset - 2)].copy_from_slice(&parent[..hashLength]);
                stackLevels[stackOffset - 2] += 1;
                stackOffset -= 1;
            }
        }
        let mut root = [0u8; 64];
        root[..hashLength].copy_from_slice(&stack[..hashLength]);
        Ok(root)
    }

    /// The lowest level of the nodes of a treehash instance on the stack, as
    /// `treehash_minheight_on_stack`.
    fn minimumHeightOnStack(
        &self,
        key: &[u8],
        parameters: &Parameters,
        instance: &TreeHashInstance,
    ) -> Result<u32, SigningFailure> {
        let mut minimum = parameters.treeHeight;
        for position in 0..u32::from(instance.stackUsage) {
            let level = u32::from(
                self.level(key, self.stackOffset.wrapping_sub(position).wrapping_sub(1))?,
            );
            if level < minimum {
                minimum = level;
            }
        }
        Ok(minimum)
    }

    /// One step of a treehash instance, as `treehash_update`: its next leaf, merged with the
    /// nodes of the instance on the stack while their levels match.
    fn updateTreeHash(
        &mut self,
        key: &mut [u8],
        instanceIndex: usize,
        hash: &KeyedHash,
        secretSeed: &[u8],
        address: &HashAddress,
    ) -> Result<(), SigningFailure> {
        let parameters = hash.parameters();
        let hashLength = parameters.hashLength;
        let (mut otsAddress, mut lTreeAddress, mut nodeAddress) = Self::addresses(address);
        let mut instance = self.treeHash[instanceIndex];
        lTreeAddress.setLTree(instance.nextIndex as u32);
        otsAddress.setOTS(instance.nextIndex as u32);
        let mut nodes = [0u8; 128];
        let leaf = MerkleTree::leaf(hash, secretSeed, &mut lTreeAddress, &mut otsAddress);
        nodes[..hashLength].copy_from_slice(&leaf[..hashLength]);
        let mut nodeHeight = 0u32;
        while instance.stackUsage > 0
            && u32::from(self.level(key, self.stackOffset.wrapping_sub(1))?) == nodeHeight
        {
            nodes.copy_within(..hashLength, hashLength);
            let top = self.stackPlace(key, self.stackOffset.wrapping_sub(1), 1, hashLength)?;
            nodes[..hashLength].copy_from_slice(&key[top]);
            nodeAddress.setTreeHeight(nodeHeight);
            let parentIndex = instance
                .nextIndex
                .checked_shr(nodeHeight + 1)
                .ok_or(SigningFailure::undefined)?;
            nodeAddress.setTreeIndex(parentIndex as u32);
            let parent = hash.nodeHash(&nodes[..2 * hashLength], &mut nodeAddress);
            nodes[..hashLength].copy_from_slice(&parent[..hashLength]);
            nodeHeight += 1;
            instance.stackUsage -= 1;
            self.stackOffset = self.stackOffset.wrapping_sub(1);
        }
        if nodeHeight == u32::from(instance.height) {
            let target = place(key.len(), instance.node, 0, hashLength)?;
            key[target].copy_from_slice(&nodes[..hashLength]);
            instance.completed = 1;
        } else {
            let top = self.stackPlace(key, self.stackOffset, 1, hashLength)?;
            key[top].copy_from_slice(&nodes[..hashLength]);
            instance.stackUsage = instance.stackUsage.wrapping_add(1);
            self.setLevel(key, self.stackOffset, nodeHeight as u8)?;
            self.stackOffset = self.stackOffset.wrapping_add(1);
            instance.nextIndex = instance.nextIndex.wrapping_add(1);
        }
        self.treeHash[instanceIndex] = instance;
        Ok(())
    }

    /// Spends up to `updates` steps on the treehash instances that need them most, as
    /// `bds_treehash_update`, and returns the steps that are left.
    ///
    /// The C function returns the count as a `char`, and its caller reads it back as an unsigned
    /// int. A `char` is signed on x86-64, where the oracle runs, so a count that went below zero,
    /// which the XMSS^MT sets of tree height 5 reach when three trees end at once, comes back as
    /// a large value, as here. The keys of key generations keep the count between -9 and 10,
    /// where the conversion changes nothing, so a unit test pins it with larger counts. A target
    /// with an unsigned `char`, such as AArch64 Linux, gets 255 minus the steps used.
    pub(crate) fn updateTreeHashes(
        &mut self,
        key: &mut [u8],
        updates: u32,
        hash: &KeyedHash,
        secretSeed: &[u8],
        address: &HashAddress,
    ) -> Result<u32, SigningFailure> {
        let parameters = hash.parameters();
        let treeHeight = parameters.treeHeight;
        let mut used = 0u32;
        for _ in 0..updates {
            let mut lowest = treeHeight;
            let mut level = treeHeight;
            for (index, instance) in self.treeHash.iter().enumerate() {
                let low = if instance.completed != 0 {
                    treeHeight
                } else if instance.stackUsage == 0 {
                    index as u32
                } else {
                    self.minimumHeightOnStack(key, parameters, instance)?
                };
                if low < lowest {
                    level = index as u32;
                    lowest = low;
                }
            }
            if level == treeHeight {
                break;
            }
            self.updateTreeHash(key, level as usize, hash, secretSeed, address)?;
            used += 1;
        }
        Ok(updates.wrapping_sub(used) as u8 as i8 as u32)
    }

    /// Adds the next leaf to the state of a next tree, as `bds_state_update`, and merges the
    /// nodes of equal level on its stack. The nodes that the authentication path and the
    /// treehash instances of the new tree need start there. A state at its last leaf does
    /// nothing.
    pub(crate) fn addNextLeaf(
        &mut self,
        key: &mut [u8],
        hash: &KeyedHash,
        secretSeed: &[u8],
        address: &HashAddress,
    ) -> Result<(), SigningFailure> {
        let parameters = hash.parameters();
        let hashLength = parameters.hashLength;
        let treeHeight = parameters.treeHeight;
        // `int idx = state->next_leaf` keeps the low 32 bits as a signed value.
        let index = self.nextLeaf as u32 as i32;
        if index == 1 << treeHeight {
            return Ok(());
        }
        let (mut otsAddress, mut lTreeAddress, mut nodeAddress) = Self::addresses(address);
        otsAddress.setOTS(index as u32);
        lTreeAddress.setLTree(index as u32);
        let top = self.stackPlace(key, self.stackOffset, 1, hashLength)?;
        let leaf = MerkleTree::leaf(hash, secretSeed, &mut lTreeAddress, &mut otsAddress);
        key[top].copy_from_slice(&leaf[..hashLength]);
        self.setLevel(key, self.stackOffset, 0)?;
        self.stackOffset = self.stackOffset.wrapping_add(1);
        if index == 3 {
            // The C code copies the slot above the new leaf. The merge of the leaf below
            // overwrites the copy with the leaf of index 3.
            let above = self.stackPlace(key, self.stackOffset, 1, hashLength)?;
            copyWithinKey(key, above, self.treeHash[0].node)?;
        }
        while self.stackOffset > 1
            && self.level(key, self.stackOffset - 1)? == self.level(key, self.stackOffset - 2)?
        {
            let nodeHeight = u32::from(self.level(key, self.stackOffset - 1)?);
            let shifted = shiftedLeafIndex(index, nodeHeight)?;
            let top = self.stackPlace(key, self.stackOffset - 1, 1, hashLength)?;
            if shifted == 1 {
                let target = self.authenticationPlace(key, nodeHeight, hashLength)?;
                copyWithinKey(key, top, target.start)?;
            } else if nodeHeight < treeHeight && shifted == 3 {
                copyWithinKey(key, top, self.treeHash[nodeHeight as usize].node)?;
            } else if nodeHeight >= treeHeight {
                // The C code would store a retained node with a shift by a negative amount.
                return Err(SigningFailure::undefined);
            }
            // The C code reads the level again after the copy.
            let level = u32::from(self.level(key, self.stackOffset - 1)?);
            nodeAddress.setTreeHeight(level);
            nodeAddress.setTreeIndex(shiftedLeafIndex(index, level + 1)? as u32);
            let children = self.stackPlace(key, self.stackOffset - 2, 2, hashLength)?;
            let parent = hash.nodeHash(&key[children.clone()], &mut nodeAddress);
            key[children.start..children.start + hashLength].copy_from_slice(&parent[..hashLength]);
            let below = self.level(key, self.stackOffset - 2)?;
            self.setLevel(key, self.stackOffset - 2, below.wrapping_add(1))?;
            self.stackOffset -= 1;
        }
        self.nextLeaf = self.nextLeaf.wrapping_add(1);
        Ok(())
    }

    /// Moves the authentication path from a leaf to the next leaf, as `bds_round`: the lowest
    /// height tau at which the index has a zero bit decides which nodes change, and the
    /// treehash instances below tau restart for the nodes that come later.
    pub(crate) fn advanceAuthenticationPath(
        &mut self,
        key: &mut [u8],
        leafIndex: u64,
        hash: &KeyedHash,
        secretSeed: &[u8],
        address: &HashAddress,
    ) -> Result<(), SigningFailure> {
        let parameters = hash.parameters();
        let hashLength = parameters.hashLength;
        let treeHeight = parameters.treeHeight;
        let (mut otsAddress, mut lTreeAddress, mut nodeAddress) = Self::addresses(address);
        let tau = (0..treeHeight)
            .find(|height| (leafIndex >> height) & 1 == 0)
            .unwrap_or(treeHeight);
        let mut children = [0u8; 128];
        if tau > 0 {
            let node = self.authenticationPlace(key, tau - 1, hashLength)?;
            children[..hashLength].copy_from_slice(&key[node]);
            // The kept node is read before the next step may replace it.
            let kept = self.keepPlace(key, (tau - 1) >> 1, hashLength)?;
            children[hashLength..2 * hashLength].copy_from_slice(&key[kept]);
        }
        if (leafIndex >> (tau + 1)) & 1 == 0 && tau < treeHeight - 1 {
            let node = self.authenticationPlace(key, tau, hashLength)?;
            let kept = self.keepPlace(key, tau >> 1, hashLength)?;
            copyWithinKey(key, node, kept.start)?;
        }
        if tau == 0 {
            lTreeAddress.setLTree(leafIndex as u32);
            otsAddress.setOTS(leafIndex as u32);
            let target = self.authenticationPlace(key, 0, hashLength)?;
            let leaf = MerkleTree::leaf(hash, secretSeed, &mut lTreeAddress, &mut otsAddress);
            key[target].copy_from_slice(&leaf[..hashLength]);
        } else {
            nodeAddress.setTreeHeight(tau - 1);
            nodeAddress.setTreeIndex((leafIndex >> tau) as u32);
            let target = self.authenticationPlace(key, tau, hashLength)?;
            let parent = hash.nodeHash(&children[..2 * hashLength], &mut nodeAddress);
            key[target].copy_from_slice(&parent[..hashLength]);
            for height in 0..tau {
                let node = place(
                    key.len(),
                    self.treeHash[height as usize].node,
                    0,
                    hashLength,
                )?;
                let target = self.authenticationPlace(key, height, hashLength)?;
                copyWithinKey(key, node, target.start)?;
            }
            for height in 0..tau.min(treeHeight) {
                // The C code adds in `unsigned long` and keeps the low 32 bits.
                let startIndex =
                    leafIndex.wrapping_add(1).wrapping_add(3 * (1u64 << height)) as u32;
                if startIndex < 1 << treeHeight {
                    let instance = &mut self.treeHash[height as usize];
                    instance.height = height as u8;
                    instance.nextIndex = u64::from(startIndex);
                    instance.completed = 0;
                    instance.stackUsage = 0;
                }
            }
        }
        Ok(())
    }

    /// Swaps the contents of two states in the key and their counters, as `deep_state_swap`.
    /// The offsets of the two states stay where they are.
    pub(crate) fn swap(
        states: &mut [BDSState],
        first: usize,
        second: usize,
        key: &mut [u8],
        parameters: &Parameters,
    ) -> Result<(), SigningFailure> {
        if first == second {
            return Ok(());
        }
        let hashLength = parameters.hashLength;
        let treeHeight = parameters.treeHeight as usize;
        let regions = |state: &BDSState| {
            let mut regions = vec![
                (state.stack, (treeHeight + 1) * hashLength),
                (state.stackLevels, treeHeight + 1),
                (state.authenticationPath, treeHeight * hashLength),
                (state.keep, (treeHeight >> 1) * hashLength),
            ];
            regions.extend(
                state
                    .treeHash
                    .iter()
                    .map(|instance| (instance.node, hashLength)),
            );
            regions
        };
        let firstRegions = regions(&states[first]);
        let secondRegions = regions(&states[second]);
        for ((firstStart, length), (secondStart, _)) in firstRegions.into_iter().zip(secondRegions)
        {
            swapWithinKey(key, firstStart, secondStart, length)?;
        }
        let (low, high) = if first < second {
            (first, second)
        } else {
            (second, first)
        };
        let (left, right) = states.split_at_mut(high);
        let (lowState, highState) = (&mut left[low], &mut right[0]);
        core::mem::swap(&mut lowState.stackOffset, &mut highState.stackOffset);
        core::mem::swap(&mut lowState.nextLeaf, &mut highState.nextLeaf);
        for (lowInstance, highInstance) in lowState.treeHash.iter_mut().zip(&mut highState.treeHash)
        {
            core::mem::swap(&mut lowInstance.height, &mut highInstance.height);
            core::mem::swap(&mut lowInstance.nextIndex, &mut highInstance.nextIndex);
            core::mem::swap(&mut lowInstance.stackUsage, &mut highInstance.stackUsage);
            core::mem::swap(&mut lowInstance.completed, &mut highInstance.completed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BDSState, copyWithinKey, place, swapWithinKey};
    use crate::testInputs::pattern;
    use crate::{CoreHash, HashAddress, KeyedHash, Parameters, SigningFailure, Variant};

    /// The parameters of XMSS-SHA2_10_256: n = 32 and h = 10, one state of 1241 bytes.
    fn parameters() -> Parameters {
        Parameters::of(Variant::xmss, 0x01).expect("XMSS-SHA2_10_256")
    }

    /// A key after its identifier with the completion byte of each treehash instance of the state
    /// of XMSS-SHA2_10_256, whose instances start at 979 and take 39 bytes each.
    fn keyWithInstances(completed: u8) -> Vec<u8> {
        let mut key = vec![0u8; 1373];
        for instance in 0..10 {
            let start = 979 + 39 * instance;
            key[start] = instance as u8;
            key[start + 6] = completed;
        }
        key
    }

    #[test]
    fn theLayoutOfAStateIsTheLayoutOfXMSSCoreFastC() {
        let parameters = parameters();
        let mut key = pattern(1373, 1);
        let (states, end) = BDSState::deserialized(&parameters, &key, 1).expect("a state");
        assert_eq!(end, 1373);
        let state = &states[0];
        // The index, the four values of n bytes, then the 11 nodes of the stack.
        assert_eq!(state.stack, 132);
        assert_eq!(
            state.stackOffset,
            u32::from_be_bytes([key[484], key[485], key[486], key[487]])
        );
        assert_eq!(
            (state.stackLevels, state.authenticationPath, state.keep),
            (488, 499, 819)
        );
        assert_eq!(state.treeHash[0].node, 979 + 7);
        assert_eq!(state.treeHash[9].height, key[979 + 9 * 39]);
        assert_eq!(
            state.treeHash[3].nextIndex,
            u64::from(u32::from_be_bytes(
                key[979 + 117 + 1..979 + 117 + 5].try_into().expect("4")
            ))
        );
        assert_eq!(
            state.nextLeaf,
            u64::from(u32::from_be_bytes(
                key[1369..1373].try_into().expect("4 bytes")
            ))
        );
        // Serializing the state writes the same counters back.
        let copy = key.clone();
        BDSState::serialize(&states, &parameters, &mut key).expect("serialize");
        assert_eq!(key, copy);
    }

    #[test]
    fn eachCounterKeepsTheLowBytesOfItsValue() {
        let parameters = parameters();
        let mut key = vec![0u8; 1373];
        let (mut states, _) = BDSState::deserialized(&parameters, &key, 1).expect("a state");
        states[0].stackOffset = 0x0102_0304;
        states[0].nextLeaf = 0x0005_0607_0809;
        states[0].treeHash[2].nextIndex = 0x0001_0A0B_0C0D;
        states[0].treeHash[2].completed = 7;
        BDSState::serialize(&states, &parameters, &mut key).expect("serialize");
        assert_eq!(key[484..488], [1, 2, 3, 4]);
        assert_eq!(key[1369..1373], [6, 7, 8, 9]);
        assert_eq!(
            key[979 + 78 + 1..979 + 78 + 7],
            [0x0A, 0x0B, 0x0C, 0x0D, 0, 7]
        );
    }

    #[test]
    fn theCountOfUpdatesComesBackAsASignedChar() {
        // `bds_treehash_update` returns `updates - used` as a `char`, which is signed on x86-64,
        // where the oracle runs, and the caller reads it back as an unsigned int.
        let parameters = parameters();
        let hash = KeyedHash::new(&parameters, CoreHash::sha256N32, &pattern(32, 1));
        let mut key = keyWithInstances(1);
        let (mut states, _) = BDSState::deserialized(&parameters, &key, 1).expect("a state");
        let address = HashAddress::default();
        let seed = pattern(32, 2);
        // Every instance is completed, so no update is used.
        for (updates, returned) in [
            (5u32, 5u32),
            (127, 127),
            (128, 0xFFFF_FF80),
            (255, 0xFFFF_FFFF),
            (256, 0),
            (u32::MAX, u32::MAX),
        ] {
            assert_eq!(
                states[0].updateTreeHashes(&mut key, updates, &hash, &seed, &address),
                Ok(returned),
                "{updates}"
            );
        }
    }

    #[test]
    fn anUnfinishedInstanceUsesAnUpdateAndTheLowestInstanceGoesFirst() {
        let parameters = parameters();
        let hash = KeyedHash::new(&parameters, CoreHash::sha256N32, &pattern(32, 1));
        let mut key = keyWithInstances(1);
        // Instances 3 and 1 are unfinished with empty stacks: instance 1 is the lowest.
        key[979 + 39 + 6] = 0;
        key[979 + 3 * 39 + 6] = 0;
        let (mut states, _) = BDSState::deserialized(&parameters, &key, 1).expect("a state");
        let seed = pattern(32, 2);
        let used = states[0]
            .updateTreeHashes(&mut key, 1, &hash, &seed, &HashAddress::default())
            .expect("an update");
        assert_eq!(used, 0);
        // The leaf of instance 1 went onto the stack, at level 0, and its next index moved on.
        assert_eq!(
            (states[0].stackOffset, states[0].treeHash[1].stackUsage),
            (1, 1)
        );
        assert_eq!(states[0].treeHash[1].nextIndex, 1);
        assert_eq!(states[0].treeHash[3].stackUsage, 0);
        assert_eq!(key[488], 0);
        assert_ne!(key[132..164], [0u8; 32]);
    }

    #[test]
    fn aPlaceOutsideTheKeyIsUndefined() {
        assert_eq!(place(100, 90, 0, 10), Ok(90..100));
        assert_eq!(place(100, 90, 1, 10), Err(SigningFailure::undefined));
        assert_eq!(place(100, 0, u32::MAX, 1), Err(SigningFailure::undefined));
        assert_eq!(place(100, usize::MAX, 1, 0), Err(SigningFailure::undefined));
        assert_eq!(
            place(100, 99, 0, usize::MAX),
            Err(SigningFailure::undefined)
        );
    }

    #[test]
    fn overlappingCopiesAndSwapsAreUndefinedAndTheOthersMoveTheBytes() {
        let mut key: Vec<u8> = (0..64).collect();
        assert_eq!(
            copyWithinKey(&mut key, 0..8, 4),
            Err(SigningFailure::undefined)
        );
        assert_eq!(
            copyWithinKey(&mut key, 8..16, 4),
            Err(SigningFailure::undefined)
        );
        assert_eq!(
            copyWithinKey(&mut key, 0..8, 60),
            Err(SigningFailure::undefined)
        );
        // A copy onto itself changes nothing, as `memcpy` of one place does in practice.
        assert_eq!(copyWithinKey(&mut key, 8..16, 8), Ok(()));
        assert_eq!(copyWithinKey(&mut key, 0..8, 8), Ok(()));
        assert_eq!(key[8..16], [0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            swapWithinKey(&mut key, 0, 4, 8),
            Err(SigningFailure::undefined)
        );
        assert_eq!(
            swapWithinKey(&mut key, 60, 0, 8),
            Err(SigningFailure::undefined)
        );
        assert_eq!(swapWithinKey(&mut key, 32, 16, 8), Ok(()));
        assert_eq!(key[16..24], [32, 33, 34, 35, 36, 37, 38, 39]);
        assert_eq!(key[32..40], [16, 17, 18, 19, 20, 21, 22, 23]);
    }

    #[test]
    fn aSwapExchangesTheContentsAndTheCountersOfTwoStates() {
        // XMSSMT-SHA2_20/4_256 has 7 states of 625 bytes after the 131 bytes of the index and
        // the four values of n bytes.
        let parameters = Parameters::of(Variant::xmssmt, 0x02).expect("XMSSMT-SHA2_20/4_256");
        let mut key = pattern(parameters.secretKeyLength, 3);
        let original = key.clone();
        let (mut states, _) = BDSState::deserialized(&parameters, &key, 7).expect("states");
        BDSState::swap(&mut states, 4, 0, &mut key, &parameters).expect("a swap");
        // The bytes of the two states change places, with the counters, which the serialization
        // writes back. The other states and the WOTS+ signatures stay.
        BDSState::serialize(&states, &parameters, &mut key).expect("serialize");
        let state =
            |bytes: &[u8], index: usize| bytes[131 + 625 * index..131 + 625 * (index + 1)].to_vec();
        assert_eq!(state(&key, 0), state(&original, 4));
        assert_eq!(state(&key, 4), state(&original, 0));
        for index in [1, 2, 3, 5, 6] {
            assert_eq!(state(&key, index), state(&original, index));
        }
        assert_eq!(key[131 + 7 * 625..], original[131 + 7 * 625..]);
        assert_eq!(key[..131], original[..131]);
        // Swapping a state with itself changes nothing.
        let before = key.clone();
        BDSState::swap(&mut states, 2, 2, &mut key, &parameters).expect("no swap");
        assert_eq!(key, before);
    }
}
