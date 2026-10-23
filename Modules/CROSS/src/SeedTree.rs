use crate::Parameters;
use alloc::vec;
use alloc::vec::Vec;

/// The seeds of the rounds of a signature, from `seedtree.c`.
///
/// The balanced and the small sets expand the root seed into a binary tree of the shape of
/// `TreeLayout`: each node expands, with the salt and its index as the domain separator, into
/// the seeds of its two children, and the leaves are the seeds of the rounds. A signature
/// reveals the fewest nodes whose subtrees hold the leaves of the rounds that reveal their seed,
/// so a verifier rebuilds those leaves and no other. The fast sets expand the root seed into 4
/// seeds and each of those into a quarter of the round seeds, and a signature lists each seed
/// that it reveals.
pub(crate) struct SeedTree<'parameters> {
    parameters: &'parameters Parameters,
    /// The seeds of the nodes of the tree, or the seeds of the rounds of a fast set.
    nodeSeeds: Vec<u8>,
    /// The seeds of the rounds, `seed_leaves`.
    roundSeeds: Vec<u8>,
}

/// A node that the seed path reveals, `TO_PUBLISH`, and one that it does not.
const toPublish: u8 = 1;

impl<'parameters> SeedTree<'parameters> {
    /// The seeds of the root seed of a signature and its salt: `gen_seed_tree` and
    /// `seed_leaves` with trees, or `seed_leaves` of a fast set.
    pub(crate) fn generated(
        parameters: &'parameters Parameters,
        rootSeed: &[u8],
        salt: &[u8],
    ) -> Self {
        let seedLength = parameters.seedLength();
        let hash = parameters.hashFunction();
        if !parameters.tradeoff.usesTrees() {
            let roundSeeds = Self::quarterSeeds(parameters, rootSeed, salt);
            return SeedTree {
                parameters,
                nodeSeeds: roundSeeds.clone(),
                roundSeeds,
            };
        }
        let layout = &parameters.treeLayout;
        let mut nodeSeeds = vec![0u8; layout.nodeCount() * seedLength];
        nodeSeeds[..seedLength].copy_from_slice(rootSeed);
        for level in 0..layout.depth {
            for position in 0..layout.internalNodeCountOfLevel(level) {
                let node = layout.levelStart(level) + position;
                let left = layout.leftChild(node, level);
                let (parents, children) = nodeSeeds.split_at_mut(left * seedLength);
                let seed = &parents[node * seedLength..(node + 1) * seedLength];
                hash.reader(&[seed, salt], node as u16)
                    .squeeze(&mut children[..2 * seedLength]);
            }
        }
        let roundSeeds = Self::leafSeeds(parameters, &nodeSeeds);
        SeedTree {
            parameters,
            nodeSeeds,
            roundSeeds,
        }
    }

    /// The round seeds of a fast set, `seed_leaves` of `NO_TREES`: the root seed and the salt
    /// expand with the domain separator 0 into 4 seeds, and seed i with the separator i + 1 into
    /// the seeds of the quarter i of the rounds. The first `t mod 4` quarters have one round more.
    fn quarterSeeds(parameters: &Parameters, rootSeed: &[u8], salt: &[u8]) -> Vec<u8> {
        let seedLength = parameters.seedLength();
        let roundCount = parameters.roundCount;
        let hash = parameters.hashFunction();
        let mut quarterSeeds = vec![0u8; 4 * seedLength];
        hash.reader(&[rootSeed, salt], 0).squeeze(&mut quarterSeeds);
        let mut roundSeeds = vec![0u8; roundCount * seedLength];
        let mut start = 0;
        for (quarter, seed) in quarterSeeds.chunks_exact(seedLength).enumerate() {
            let count = roundCount / 4 + usize::from(roundCount % 4 > quarter);
            let end = start + count * seedLength;
            hash.reader(&[seed, salt], quarter as u16 + 1)
                .squeeze(&mut roundSeeds[start..end]);
            start = end;
        }
        roundSeeds
    }

    /// The seeds of the leaves of a tree in the order of the rounds, `seed_leaves`.
    fn leafSeeds(parameters: &Parameters, nodeSeeds: &[u8]) -> Vec<u8> {
        let seedLength = parameters.seedLength();
        parameters
            .treeLayout
            .leafNodes()
            .flat_map(|leaf| &nodeSeeds[leaf * seedLength..(leaf + 1) * seedLength])
            .copied()
            .collect()
    }

    /// The marks of the nodes that the seed path covers, `compute_seeds_to_publish`: a leaf takes
    /// the bit of its round in the second challenge, and a parent is marked when both children
    /// are.
    fn publishedNodes(parameters: &Parameters, challenge: &[u8]) -> Vec<u8> {
        let layout = &parameters.treeLayout;
        let mut marks = vec![0u8; layout.nodeCount()];
        for (leaf, bit) in layout.leafNodes().zip(challenge) {
            marks[leaf] = *bit;
        }
        for level in (1..=layout.depth).rev() {
            for pair in (0..layout.nodeCountOfLevel(level) / 2).rev() {
                let node = layout.levelStart(level) + 2 * pair;
                let isPublished = marks[node] == toPublish && marks[node + 1] == toPublish;
                marks[layout.parent(node, level)] = u8::from(isPublished);
            }
        }
        marks
    }

    /// The seed of a round.
    pub(crate) fn roundSeed(&self, round: usize) -> &[u8] {
        let seedLength = self.parameters.seedLength();
        &self.roundSeeds[round * seedLength..(round + 1) * seedLength]
    }

    /// Writes the revealed seeds to the zeroed path of a signature, `seed_path`: with trees, each
    /// marked node whose parent is not marked, level by level from the top. A fast set lists the
    /// seed of each round whose challenge bit is one.
    pub(crate) fn writePath(&self, challenge: &[u8], path: &mut [u8]) {
        let parameters = self.parameters;
        let seedLength = parameters.seedLength();
        let mut published = path.chunks_exact_mut(seedLength);
        if !parameters.tradeoff.usesTrees() {
            for (round, bit) in challenge.iter().enumerate() {
                if *bit == toPublish {
                    published
                        .next()
                        .expect("room for w seeds")
                        .copy_from_slice(self.roundSeed(round));
                }
            }
            return;
        }
        let layout = &parameters.treeLayout;
        let marks = Self::publishedNodes(parameters, challenge);
        for level in 1..=layout.depth {
            for position in 0..layout.nodeCountOfLevel(level) {
                let node = layout.levelStart(level) + position;
                if marks[node] == toPublish && marks[layout.parent(node, level)] != toPublish {
                    published
                        .next()
                        .expect("room for the longest path")
                        .copy_from_slice(
                            &self.nodeSeeds[node * seedLength..(node + 1) * seedLength],
                        );
                }
            }
        }
    }

    /// The seeds of the rounds that a path reveals, and true when the bytes of the path after
    /// its last seed are zero: `rebuild_tree` and `seed_leaves` with trees, or `rebuild_leaves`
    /// of a fast set, whose path has no room left. The seeds of the other rounds are zero.
    pub(crate) fn rebuilt(
        parameters: &'parameters Parameters,
        challenge: &[u8],
        path: &[u8],
        salt: &[u8],
    ) -> (Self, bool) {
        let seedLength = parameters.seedLength();
        let mut stored = path.chunks_exact(seedLength);
        if !parameters.tradeoff.usesTrees() {
            let mut roundSeeds = vec![0u8; parameters.roundCount * seedLength];
            for (seed, bit) in roundSeeds.chunks_exact_mut(seedLength).zip(challenge) {
                if *bit == toPublish {
                    seed.copy_from_slice(stored.next().expect("w seeds"));
                }
            }
            let tree = SeedTree {
                parameters,
                nodeSeeds: roundSeeds.clone(),
                roundSeeds,
            };
            return (tree, true);
        }
        let layout = &parameters.treeLayout;
        let hash = parameters.hashFunction();
        let marks = Self::publishedNodes(parameters, challenge);
        let mut nodeSeeds = vec![0u8; layout.nodeCount() * seedLength];
        let mut usedLength = 0;
        for level in 1..=layout.depth {
            for position in 0..layout.nodeCountOfLevel(level) {
                let node = layout.levelStart(level) + position;
                if marks[node] != toPublish {
                    continue;
                }
                if marks[layout.parent(node, level)] != toPublish {
                    nodeSeeds[node * seedLength..(node + 1) * seedLength]
                        .copy_from_slice(stored.next().expect("the longest path"));
                    usedLength += seedLength;
                }
                if position < layout.internalNodeCountOfLevel(level) {
                    let left = layout.leftChild(node, level);
                    let (parents, children) = nodeSeeds.split_at_mut(left * seedLength);
                    let seed = &parents[node * seedLength..(node + 1) * seedLength];
                    hash.reader(&[seed, salt], node as u16)
                        .squeeze(&mut children[..2 * seedLength]);
                }
            }
        }
        // The rest of the path must be zero, or a forger could hide bytes in it.
        let isPaddingZero = path[usedLength..].iter().all(|byte| *byte == 0);
        let roundSeeds = Self::leafSeeds(parameters, &nodeSeeds);
        let tree = SeedTree {
            parameters,
            nodeSeeds,
            roundSeeds,
        };
        (tree, isPaddingZero)
    }
}

#[cfg(test)]
mod tests {
    use super::SeedTree;
    use crate::Sampler;
    use crate::parameters::{Parameters, allSets, crossRSDP128Small, crossRSDPG128Fast};
    use crate::testInputs::{SeededSequence, shortDigest};

    /// The second challenge of the known answers: the expansion of the digest of seed 3.
    fn challenge(parameters: &Parameters) -> Vec<u8> {
        let digest = SeededSequence::new(3).bytes(parameters.digestLength());
        Sampler::new(parameters).secondChallenge(&digest)
    }

    /// The root seed and the salt of the known answers: the bytes of seed 5.
    fn rootSeedAndSalt(parameters: &Parameters) -> (Vec<u8>, Vec<u8>) {
        let mut sequence = SeededSequence::new(5);
        let rootSeed = sequence.bytes(parameters.seedLength());
        let salt = sequence.bytes(parameters.digestLength());
        (rootSeed, salt)
    }

    #[test]
    fn theSeedsAndThePathsAreThoseOfTheCCode() {
        // `gen_seed_tree`, `seed_leaves`, `seed_path` and `rebuild_tree`, or the functions of
        // `NO_TREES`, of each set of the oracle library. Each row gives the digest of the tree,
        // empty for a fast set, of the round seeds, the number of seeds of the path, the digest
        // of the path, and the digest of the round seeds that the path rebuilds.
        let expected: [(&str, &str, usize, &str, &str); 18] = [
            (
                "25a94646f6002a1d0ddf849858463d6f",
                "f232aa89ce5dbc79129f25b7dd9c9864",
                86,
                "d61434f69161ce448965b63b7d40c0c0",
                "30240fe49acfc974326fdac58f949e00",
            ),
            (
                "",
                "4ea42f5c46e97daaec66f4b1257082ff",
                82,
                "9a9ebb1e7fa46fa8049d9ecf236092a7",
                "9bd99ceaa851ae547c669e81c096c4cd",
            ),
            (
                "68e073dcbe528c19b57bd14730cceef2",
                "67001f69aefbc1eea051f17eb2200679",
                106,
                "06e36e16ebbbb56da37b9aa8a33b26b7",
                "f84a0f19ad1735e73ea7641a6b26bf2e",
            ),
            (
                "dd17f59756c397e564ed9c8cb64684d7",
                "20309265414e1d7ee9db1d8973e3a2e7",
                137,
                "4b357ead2c0ff45d1bb4008b8f888bbc",
                "914c8c3b5872ce2a78ec405ee202b468",
            ),
            (
                "",
                "86ea1ea19556f915022fe478997f6eb0",
                125,
                "2b44bcc00ccb63d823569ff08ccfc635",
                "643fc97e7ae03d83c7d63a40db4d74dc",
            ),
            (
                "ab8023a010675ea4adc69f2fce00a494",
                "6b00ae8296607de19b73a667a440dbd1",
                145,
                "a307b4a5c56c4abffc46073fccb27fe9",
                "22f5cefbc860567987db80cda04bf8f8",
            ),
            (
                "7f45880ce63702555cb96a7d3ee62752",
                "d4956b0e97c888e4aac9510379c99767",
                175,
                "40f7a1e754ffdd6de99bed226b352a9e",
                "f7de19f4a2ca14c595fdb41380801d1c",
            ),
            (
                "",
                "84cca87371b86bea4146fb230e5f66ed",
                167,
                "ea37a7dd910e15320938d58a8a7071a9",
                "c0b983b89b1cde7c8f58e6113378198e",
            ),
            (
                "45563c63d9772126d260dfd9a9f01ef7",
                "4e3cb6b151dd34be3900585a635527d3",
                206,
                "9b983549019e511d26f5bf6dc8ed22e9",
                "20ba30e2650a161d68f396edd5526226",
            ),
            (
                "25a94646f6002a1d0ddf849858463d6f",
                "f232aa89ce5dbc79129f25b7dd9c9864",
                79,
                "30631a2c10cd66d9c0eca777cf0ad244",
                "d9beb054f65c7f3b5a009227580825db",
            ),
            (
                "",
                "598352fbeaa42ed1306842dd13bb803d",
                76,
                "5401b6a3eaca09900b627bded05d9f36",
                "521a5fc28cc0949996c2ae1d7066f0e0",
            ),
            (
                "6699398036d4418fac0205efccbcdc5a",
                "8d055bf4b4731901f7355dda1e9aa452",
                100,
                "8bf529a330fffad4ed80b69901727489",
                "d583059b6f645c982c7ab313250822c4",
            ),
            (
                "70e0c9cd5d5c397de7f65fa912f173bc",
                "c7fc7ad2a57207a80a6e1ffea146b30d",
                100,
                "0e1c39ea0280571bddd5641022a6f8c3",
                "73b3683d93ac71ee3be73e16bca6b503",
            ),
            (
                "",
                "786cb153f36217de5c90725aaa824c7b",
                119,
                "c8d40307cdbbc3785519bf63b1367918",
                "c1ed69d162c2eefd2eed0dcf94eac13c",
            ),
            (
                "3e3e4510eb5ff524e10322bdc83b2694",
                "77cb66c5478a26efe296e7695bacee9b",
                126,
                "884414da1d16765d6076a9f757196810",
                "99b338f272c23fb9457447d9423c781a",
            ),
            (
                "70c87a272063a1c64add6447181344fa",
                "a9fdd274168cb8614863dc95f36c84f9",
                131,
                "9c6a63bc417e49976d4423da35a7ec7c",
                "8a4ab42fef13e98f0643eefbd2e234a5",
            ),
            (
                "",
                "8861f85ac0c463eda1681acaced3f4d0",
                153,
                "c50ea5ef56a4ebf1d69cca2fce79e054",
                "224022f4fb4bef805e5c41c91f4aa3d2",
            ),
            (
                "3a8e0279c44932293b54a34193eac2a1",
                "7f4ebefc6c1ef6f8e29653529c454175",
                178,
                "023c8bbc1d4a86b6db1257c29c9ba2e1",
                "3b52604d76430ced358115481c58b4e8",
            ),
        ];
        for (parameters, (treeDigest, seedsDigest, pathCount, pathDigest, rebuiltDigest)) in
            allSets.iter().zip(expected)
        {
            let name = parameters.description.name;
            let seedLength = parameters.seedLength();
            let (rootSeed, salt) = rootSeedAndSalt(parameters);
            let tree = SeedTree::generated(parameters, &rootSeed, &salt);
            if parameters.tradeoff.usesTrees() {
                assert_eq!(shortDigest(&tree.nodeSeeds), treeDigest, "{name}");
            }
            assert_eq!(shortDigest(&tree.roundSeeds), seedsDigest, "{name}");
            let challenge = challenge(parameters);
            let mut path = vec![0u8; parameters.storedNodeCount * seedLength];
            tree.writePath(&challenge, &mut path);
            assert_eq!(shortDigest(&path), pathDigest, "{name}");
            // The seeds after the count of the C code are the zeros of the padding.
            assert!(path[pathCount * seedLength..].iter().all(|byte| *byte == 0));
            assert!(
                path[(pathCount - 1) * seedLength..pathCount * seedLength]
                    .iter()
                    .any(|byte| *byte != 0)
            );
            let (rebuilt, isPaddingZero) = SeedTree::rebuilt(parameters, &challenge, &path, &salt);
            assert!(isPaddingZero, "{name}");
            assert_eq!(shortDigest(&rebuilt.roundSeeds), rebuiltDigest, "{name}");
            // The rebuilt seeds are the seeds of the rounds whose bit is one, and zeros.
            for (round, bit) in challenge.iter().enumerate() {
                let expected = if *bit == 1 {
                    tree.roundSeed(round).to_vec()
                } else {
                    vec![0u8; seedLength]
                };
                assert_eq!(
                    rebuilt.roundSeed(round),
                    &expected[..],
                    "{name}, round {round}"
                );
            }
        }
    }

    #[test]
    fn eachByteOfThePaddingOfThePathIsChecked() {
        let parameters = &crossRSDP128Small;
        let seedLength = parameters.seedLength();
        let (rootSeed, salt) = rootSeedAndSalt(parameters);
        let tree = SeedTree::generated(parameters, &rootSeed, &salt);
        let challenge = challenge(parameters);
        let mut path = vec![0u8; parameters.storedNodeCount * seedLength];
        tree.writePath(&challenge, &mut path);
        // The C code reveals 106 seeds of the 129 that the path holds.
        let used = 106 * seedLength;
        for position in [used, used + 1, path.len() - 1] {
            let mut changed = path.clone();
            changed[position] = 0x40;
            let (rebuilt, isPaddingZero) =
                SeedTree::rebuilt(parameters, &challenge, &changed, &salt);
            assert!(!isPaddingZero, "byte {position}");
            // The padding does not change the seeds.
            assert_eq!(
                rebuilt.roundSeeds,
                SeedTree::rebuilt(parameters, &challenge, &path, &salt)
                    .0
                    .roundSeeds
            );
        }
        // The last revealed seed is no padding.
        let mut changed = path.clone();
        changed[used - 1] ^= 1;
        let (rebuilt, isPaddingZero) = SeedTree::rebuilt(parameters, &challenge, &changed, &salt);
        assert!(isPaddingZero);
        assert_ne!(
            rebuilt.roundSeeds,
            SeedTree::rebuilt(parameters, &challenge, &path, &salt)
                .0
                .roundSeeds
        );
    }

    #[test]
    fn theQuartersOfAFastSetTakeTheRemainderFirst() {
        // cross-rsdpg-128-fast has t = 147 = 4 * 36 + 3: quarters of 37, 37, 37 and 36 rounds.
        let parameters = &crossRSDPG128Fast;
        let seedLength = parameters.seedLength();
        let (rootSeed, salt) = rootSeedAndSalt(parameters);
        let seeds = SeedTree::quarterSeeds(parameters, &rootSeed, &salt);
        let hash = parameters.hashFunction();
        let mut quarterSeeds = vec![0u8; 4 * seedLength];
        hash.reader(&[&rootSeed, &salt], 0)
            .squeeze(&mut quarterSeeds);
        let mut start = 0;
        for (quarter, count) in [37, 37, 37, 36].into_iter().enumerate() {
            let mut expected = vec![0u8; count * seedLength];
            let seed = &quarterSeeds[quarter * seedLength..(quarter + 1) * seedLength];
            hash.reader(&[seed, &salt], quarter as u16 + 1)
                .squeeze(&mut expected);
            assert_eq!(
                &seeds[start..start + expected.len()],
                &expected[..],
                "{quarter}"
            );
            start += expected.len();
        }
        assert_eq!(start, seeds.len());
    }
}
