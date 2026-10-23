use crate::{CodeParameters, HashFunction, Problem, Tradeoff, TreeLayout};
use OQSNativeEntities::SignatureDescription;
use core::ops::Range;

/// The parameters of one CROSS parameter set, from the `parameters.h` and `set.h` of its folder
/// `src/sig/cross/upcross_cross-<set>_clean`, with the facts of its liboqs file
/// `src/sig/cross/sig_cross_<set>.c`.
pub(crate) struct Parameters {
    /// The problem, the security level and the code.
    pub(crate) code: CodeParameters,
    /// Balanced, fast or small.
    pub(crate) tradeoff: Tradeoff,
    /// The number t of rounds, `T`.
    pub(crate) roundCount: usize,
    /// The weight w of the second challenge, `W`: the number of rounds that reveal their seed.
    pub(crate) challengeWeight: usize,
    /// The room of a signature for the seeds of the seed path and for the digests of the Merkle
    /// proof, `TREE_NODES_TO_STORE`. It is w for the fast sets.
    pub(crate) storedNodeCount: usize,
    /// The random bits of the first challenge, `BITS_CHALL_1_FPSTAR_CT_RNG`.
    pub(crate) firstChallengeRandomBits: usize,
    /// The random bits of the second challenge, `BITS_CWSTR_RNG`.
    pub(crate) secondChallengeRandomBits: usize,
    /// The shape of the trees of t leaves.
    pub(crate) treeLayout: TreeLayout,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: SignatureDescription,
}

/// The version text of every CROSS set in liboqs.
const version: &str = "2.2 + PQClean and OQS patches";

/// The length in bytes of a vector of values of some bits, `DENSELY_PACKED_*_SIZE`: whole
/// groups of 8 values, then the bytes of the remaining values.
const fn packedLength(count: usize, bits: u32) -> usize {
    (count / 8) * bits as usize + ((count % 8) * bits as usize).div_ceil(8)
}

impl Parameters {
    /// Makes the parameters of a set: its name and NIST level, its code and its trade-off, the
    /// rounds t, the weight w and the stored node count, and the random bits of the two
    /// challenges.
    const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        code: CodeParameters,
        tradeoff: Tradeoff,
        rounds: [usize; 3],
        challengeRandomBits: [usize; 2],
    ) -> Self {
        let [roundCount, challengeWeight, storedNodeCount] = rounds;
        let mut parameters = Parameters {
            code,
            tradeoff,
            roundCount,
            challengeWeight,
            storedNodeCount,
            firstChallengeRandomBits: challengeRandomBits[0],
            secondChallengeRandomBits: challengeRandomBits[1],
            treeLayout: TreeLayout::new(roundCount),
            description: SignatureDescription {
                name,
                algorithmVersion: version,
                claimedNISTLevel,
                isEUFCMASecure: true,
                isSUFCMASecure: false,
                supportsContext: false,
                publicKeyLength: 0,
                secretKeyLength: 0,
                signatureLength: 0,
            },
        };
        parameters.description.publicKeyLength = parameters.publicKeyLength();
        parameters.description.secretKeyLength = parameters.digestLength();
        parameters.description.signatureLength = parameters.signatureLength();
        parameters
    }

    /// RSDP or RSDP(G).
    pub(crate) const fn problem(&self) -> Problem {
        self.code.problem
    }

    /// SHAKE128 for the security level 128, and SHAKE256 above it.
    pub(crate) const fn hashFunction(&self) -> HashFunction {
        if self.code.securityBits == 128 {
            HashFunction::shake128
        } else {
            HashFunction::shake256
        }
    }

    /// The length of a seed of a round or of a tree node, lambda / 8, `SEED_LENGTH_BYTES`.
    pub(crate) const fn seedLength(&self) -> usize {
        self.code.securityBits / 8
    }

    /// The length of a hash, of a salt and of the seed of a key pair, 2 lambda / 8:
    /// `HASH_DIGEST_LENGTH`, `SALT_LENGTH_BYTES` and `KEYPAIR_SEED_LENGTH_BYTES`.
    pub(crate) const fn digestLength(&self) -> usize {
        2 * self.code.securityBits / 8
    }

    /// The number of rounds that publish a response, t - w: the rounds whose second challenge
    /// is 0.
    pub(crate) const fn responseCount(&self) -> usize {
        self.roundCount - self.challengeWeight
    }

    /// The length of a packed vector of n field elements, `DENSELY_PACKED_FP_VEC_SIZE`.
    pub(crate) const fn fieldVectorLength(&self) -> usize {
        packedLength(self.code.length, self.problem().fieldBits())
    }

    /// The length of a packed syndrome of n - k field elements, `DENSELY_PACKED_FP_SYN_SIZE`.
    pub(crate) const fn syndromeLength(&self) -> usize {
        packedLength(
            self.code.length - self.code.dimension,
            self.problem().fieldBits(),
        )
    }

    /// The number of exponents of a sampled restricted vector and of the restricted vector of
    /// a response: n for RSDP, and m for RSDP(G), whose vectors are elements of the subgroup by
    /// their m coordinates.
    pub(crate) const fn restrictedExponentCount(&self) -> usize {
        match self.problem() {
            Problem::rsdp => self.code.length,
            Problem::rsdpg => self.code.subgroupDimension,
        }
    }

    /// The length of the packed restricted vector of a response: `DENSELY_PACKED_FZ_VEC_SIZE`
    /// for RSDP and `DENSELY_PACKED_FZ_RSDP_G_VEC_SIZE` for RSDP(G).
    pub(crate) const fn restrictedVectorLength(&self) -> usize {
        packedLength(
            self.restrictedExponentCount(),
            self.problem().restrictedBits(),
        )
    }

    /// The length of a response of a round, `resp_0_t`: the packed y and the packed restricted
    /// vector.
    pub(crate) const fn responseLength(&self) -> usize {
        self.fieldVectorLength() + self.restrictedVectorLength()
    }

    /// The length of a public key, `pk_t`: the seed of the matrices and the packed syndrome.
    pub(crate) const fn publicKeyLength(&self) -> usize {
        self.digestLength() + self.syndromeLength()
    }

    /// The length of a signature, `CROSS_sig_t`.
    pub(crate) const fn signatureLength(&self) -> usize {
        self.responsesRange().end
    }

    /// The salt of a signature, `salt`.
    pub(crate) const fn saltRange(&self) -> Range<usize> {
        0..self.digestLength()
    }

    /// The digest of the commitments of a signature, `digest_cmt`.
    pub(crate) const fn commitmentDigestRange(&self) -> Range<usize> {
        self.digestLength()..2 * self.digestLength()
    }

    /// The digest of the second challenge of a signature, `digest_chall_2`.
    pub(crate) const fn secondChallengeDigestRange(&self) -> Range<usize> {
        2 * self.digestLength()..3 * self.digestLength()
    }

    /// The seeds that a signature reveals, `path`.
    pub(crate) const fn pathRange(&self) -> Range<usize> {
        let start = 3 * self.digestLength();
        start..start + self.storedNodeCount * self.seedLength()
    }

    /// The digests of the Merkle proof of a signature, `proof`.
    pub(crate) const fn proofRange(&self) -> Range<usize> {
        let start = self.pathRange().end;
        start..start + self.storedNodeCount * self.digestLength()
    }

    /// The second commitments of the rounds that publish a response, `resp_1`.
    pub(crate) const fn commitmentResponsesRange(&self) -> Range<usize> {
        let start = self.proofRange().end;
        start..start + self.responseCount() * self.digestLength()
    }

    /// The responses of the rounds that publish one, `resp_0`.
    pub(crate) const fn responsesRange(&self) -> Range<usize> {
        let start = self.commitmentResponsesRange().end;
        start..start + self.responseCount() * self.responseLength()
    }

    /// The domain separator of the expansion of the secret seed, `3 T + 1`.
    pub(crate) const fn secretSeedDomain(&self) -> u16 {
        (3 * self.roundCount + 1) as u16
    }

    /// The domain separator of the expansion of the seed of the matrices, `3 T + 2`.
    pub(crate) const fn publicSeedDomain(&self) -> u16 {
        (3 * self.roundCount + 2) as u16
    }

    /// The domain separator of the expansion of the seed of the secret vector, `3 T + 3`.
    pub(crate) const fn errorSeedDomain(&self) -> u16 {
        (3 * self.roundCount + 3) as u16
    }

    /// The domain separator of the expansion of the first challenge, `3 T - 1`.
    pub(crate) const fn firstChallengeDomain(&self) -> u16 {
        (3 * self.roundCount - 1) as u16
    }

    /// The domain separator of the expansion of the second challenge, `3 T`.
    pub(crate) const fn secondChallengeDomain(&self) -> u16 {
        (3 * self.roundCount) as u16
    }

    /// The domain separator of the seed expansion of a round, `i + 2 T - 1`. The commitments of
    /// the round add `HASH_DOMAIN_SEP_CONST` to it.
    pub(crate) const fn roundDomain(&self, round: usize) -> u16 {
        (round + 2 * self.roundCount - 1) as u16
    }
}

/// The code of RSDP at the security level 128.
const rsdp128: CodeParameters = CodeParameters {
    problem: Problem::rsdp,
    securityBits: 128,
    length: 127,
    dimension: 76,
    subgroupDimension: 0,
    fieldVectorRandomBits: 1127,
    parityMatrixRandomBits: 28028,
    restrictedVectorRandomBits: 717,
    subgroupMatrixRandomBits: 0,
};

/// The code of RSDP at the security level 192.
const rsdp192: CodeParameters = CodeParameters {
    problem: Problem::rsdp,
    securityBits: 192,
    length: 187,
    dimension: 111,
    subgroupDimension: 0,
    fieldVectorRandomBits: 1673,
    parityMatrixRandomBits: 60711,
    restrictedVectorRandomBits: 1065,
    subgroupMatrixRandomBits: 0,
};

/// The code of RSDP at the security level 256.
const rsdp256: CodeParameters = CodeParameters {
    problem: Problem::rsdp,
    securityBits: 256,
    length: 251,
    dimension: 150,
    subgroupDimension: 0,
    fieldVectorRandomBits: 2247,
    parityMatrixRandomBits: 108_689,
    restrictedVectorRandomBits: 1431,
    subgroupMatrixRandomBits: 0,
};

/// The code of RSDP(G) at the security level 128.
const rsdpg128: CodeParameters = CodeParameters {
    problem: Problem::rsdpg,
    securityBits: 128,
    length: 55,
    dimension: 36,
    subgroupDimension: 25,
    fieldVectorRandomBits: 729,
    parityMatrixRandomBits: 6624,
    restrictedVectorRandomBits: 343,
    subgroupMatrixRandomBits: 5677,
};

/// The code of RSDP(G) at the security level 192.
const rsdpg192: CodeParameters = CodeParameters {
    problem: Problem::rsdpg,
    securityBits: 192,
    length: 79,
    dimension: 48,
    subgroupDimension: 40,
    fieldVectorRandomBits: 1071,
    parityMatrixRandomBits: 14211,
    restrictedVectorRandomBits: 539,
    subgroupMatrixRandomBits: 11655,
};

/// The code of RSDP(G) at the security level 256.
const rsdpg256: CodeParameters = CodeParameters {
    problem: Problem::rsdpg,
    securityBits: 256,
    length: 106,
    dimension: 69,
    subgroupDimension: 48,
    fieldVectorRandomBits: 1431,
    parityMatrixRandomBits: 24192,
    restrictedVectorRandomBits: 679,
    subgroupMatrixRandomBits: 20594,
};

// The eighteen sets, in the order of liboqs. Each row gives the name and the NIST level of the
// set, its code and its trade-off, then `[T, W, TREE_NODES_TO_STORE]` and
// `[BITS_CHALL_1_FPSTAR_CT_RNG, BITS_CWSTR_RNG]` of its `parameters.h`.

/// cross-rsdp-128-balanced.
pub(crate) const crossRSDP128Balanced: Parameters = Parameters::new(
    "cross-rsdp-128-balanced",
    1,
    rsdp128,
    Tradeoff::balanced,
    [256, 215, 108],
    [2170, 4776],
);

/// cross-rsdp-128-fast.
pub(crate) const crossRSDP128Fast: Parameters = Parameters::new(
    "cross-rsdp-128-fast",
    1,
    rsdp128,
    Tradeoff::fast,
    [157, 82, 82],
    [1421, 3656],
);

/// cross-rsdp-128-small.
pub(crate) const crossRSDP128Small: Parameters = Parameters::new(
    "cross-rsdp-128-small",
    1,
    rsdp128,
    Tradeoff::small,
    [520, 488, 129],
    [4130, 10390],
);

/// cross-rsdp-192-balanced.
pub(crate) const crossRSDP192Balanced: Parameters = Parameters::new(
    "cross-rsdp-192-balanced",
    3,
    rsdp192,
    Tradeoff::balanced,
    [384, 321, 165],
    [3255, 8586],
);

/// cross-rsdp-192-fast.
pub(crate) const crossRSDP192Fast: Parameters = Parameters::new(
    "cross-rsdp-192-fast",
    3,
    rsdp192,
    Tradeoff::fast,
    [239, 125, 125],
    [2163, 5264],
);

/// cross-rsdp-192-small.
pub(crate) const crossRSDP192Small: Parameters = Parameters::new(
    "cross-rsdp-192-small",
    3,
    rsdp192,
    Tradeoff::small,
    [580, 527, 184],
    [4718, 12880],
);

/// cross-rsdp-256-balanced.
pub(crate) const crossRSDP256Balanced: Parameters = Parameters::new(
    "cross-rsdp-256-balanced",
    5,
    rsdp256,
    Tradeoff::balanced,
    [512, 427, 220],
    [4347, 10746],
);

/// cross-rsdp-256-fast.
pub(crate) const crossRSDP256Fast: Parameters = Parameters::new(
    "cross-rsdp-256-fast",
    5,
    rsdp256,
    Tradeoff::fast,
    [321, 167, 167],
    [2905, 8343],
);

/// cross-rsdp-256-small.
pub(crate) const crossRSDP256Small: Parameters = Parameters::new(
    "cross-rsdp-256-small",
    5,
    rsdp256,
    Tradeoff::small,
    [832, 762, 251],
    [6734, 18150],
);

/// cross-rsdpg-128-balanced.
pub(crate) const crossRSDPG128Balanced: Parameters = Parameters::new(
    "cross-rsdpg-128-balanced",
    1,
    rsdpg128,
    Tradeoff::balanced,
    [256, 220, 101],
    [2682, 4776],
);

/// cross-rsdpg-128-fast.
pub(crate) const crossRSDPG128Fast: Parameters = Parameters::new(
    "cross-rsdpg-128-fast",
    1,
    rsdpg128,
    Tradeoff::fast,
    [147, 76, 76],
    [1647, 3472],
);

/// cross-rsdpg-128-small.
pub(crate) const crossRSDPG128Small: Parameters = Parameters::new(
    "cross-rsdpg-128-small",
    1,
    rsdpg128,
    Tradeoff::small,
    [512, 484, 117],
    [5085, 9153],
);

/// cross-rsdpg-192-balanced.
pub(crate) const crossRSDPG192Balanced: Parameters = Parameters::new(
    "cross-rsdpg-192-balanced",
    3,
    rsdpg192,
    Tradeoff::balanced,
    [268, 196, 138],
    [2925, 6444],
);

/// cross-rsdpg-192-fast.
pub(crate) const crossRSDPG192Fast: Parameters = Parameters::new(
    "cross-rsdpg-192-fast",
    3,
    rsdpg192,
    Tradeoff::fast,
    [224, 119, 119],
    [2502, 5128],
);

/// cross-rsdpg-192-small.
pub(crate) const crossRSDPG192Small: Parameters = Parameters::new(
    "cross-rsdpg-192-small",
    3,
    rsdpg192,
    Tradeoff::small,
    [512, 463, 165],
    [5238, 9981],
);

/// cross-rsdpg-256-balanced.
pub(crate) const crossRSDPG256Balanced: Parameters = Parameters::new(
    "cross-rsdpg-256-balanced",
    5,
    rsdpg256,
    Tradeoff::balanced,
    [356, 258, 185],
    [3897, 8937],
);

/// cross-rsdpg-256-fast.
pub(crate) const crossRSDPG256Fast: Parameters = Parameters::new(
    "cross-rsdpg-256-fast",
    5,
    rsdpg256,
    Tradeoff::fast,
    [300, 153, 153],
    [3357, 7929],
);

/// cross-rsdpg-256-small.
pub(crate) const crossRSDPG256Small: Parameters = Parameters::new(
    "cross-rsdpg-256-small",
    5,
    rsdpg256,
    Tradeoff::small,
    [642, 575, 220],
    [6597, 15140],
);

/// Every set, in the order of liboqs.
#[cfg(test)]
pub(crate) const allSets: [&Parameters; 18] = [
    &crossRSDP128Balanced,
    &crossRSDP128Fast,
    &crossRSDP128Small,
    &crossRSDP192Balanced,
    &crossRSDP192Fast,
    &crossRSDP192Small,
    &crossRSDP256Balanced,
    &crossRSDP256Fast,
    &crossRSDP256Small,
    &crossRSDPG128Balanced,
    &crossRSDPG128Fast,
    &crossRSDPG128Small,
    &crossRSDPG192Balanced,
    &crossRSDPG192Fast,
    &crossRSDPG192Small,
    &crossRSDPG256Balanced,
    &crossRSDPG256Fast,
    &crossRSDPG256Small,
];

#[cfg(test)]
mod tests {
    use super::{Parameters, allSets, packedLength};
    use crate::{HashFunction, Problem, Tradeoff, TreeLayout};

    #[test]
    fn lengthsAreTheLengthsOfTheLiboqsHeader() {
        // `sig_cross.h` of liboqs: the public key, the secret key and the signature.
        let expected: [(&str, usize, usize, usize); 18] = [
            ("cross-rsdp-128-balanced", 77, 32, 13152),
            ("cross-rsdp-128-fast", 77, 32, 18432),
            ("cross-rsdp-128-small", 77, 32, 12432),
            ("cross-rsdp-192-balanced", 115, 48, 29853),
            ("cross-rsdp-192-fast", 115, 48, 41406),
            ("cross-rsdp-192-small", 115, 48, 28391),
            ("cross-rsdp-256-balanced", 153, 64, 53527),
            ("cross-rsdp-256-fast", 153, 64, 74590),
            ("cross-rsdp-256-small", 153, 64, 50818),
            ("cross-rsdpg-128-balanced", 54, 32, 9120),
            ("cross-rsdpg-128-fast", 54, 32, 11980),
            ("cross-rsdpg-128-small", 54, 32, 8960),
            ("cross-rsdpg-192-balanced", 83, 48, 22464),
            ("cross-rsdpg-192-fast", 83, 48, 26772),
            ("cross-rsdpg-192-small", 83, 48, 20452),
            ("cross-rsdpg-256-balanced", 106, 64, 40100),
            ("cross-rsdpg-256-fast", 106, 64, 48102),
            ("cross-rsdpg-256-small", 106, 64, 36454),
        ];
        for (parameters, (name, publicKey, secretKey, signature)) in allSets.iter().zip(expected) {
            let description = &parameters.description;
            assert_eq!(description.name, name);
            assert_eq!(
                (
                    description.publicKeyLength,
                    description.secretKeyLength,
                    description.signatureLength
                ),
                (publicKey, secretKey, signature),
                "{name}"
            );
        }
    }

    #[test]
    fn eachSetHasTheFactsOfItsLiboqsFile() {
        for parameters in allSets {
            let description = &parameters.description;
            let name = description.name;
            assert_eq!(
                description.algorithmVersion,
                "2.2 + PQClean and OQS patches"
            );
            assert!(description.isEUFCMASecure, "{name}");
            assert!(!description.isSUFCMASecure, "{name}");
            assert!(!description.supportsContext, "{name}");
            // The level of each set follows lambda: 1 for 128, 3 for 192 and 5 for 256.
            let level = match parameters.code.securityBits {
                128 => 1,
                192 => 3,
                _ => 5,
            };
            assert_eq!(description.claimedNISTLevel, level, "{name}");
            // The name states the problem, lambda and the trade-off.
            let problem = match parameters.problem() {
                Problem::rsdp => "rsdp",
                Problem::rsdpg => "rsdpg",
            };
            let tradeoff = match parameters.tradeoff {
                Tradeoff::balanced => "balanced",
                Tradeoff::fast => "fast",
                Tradeoff::small => "small",
            };
            assert_eq!(
                name,
                format!(
                    "cross-{problem}-{}-{tradeoff}",
                    parameters.code.securityBits
                )
            );
            assert_eq!(
                parameters.treeLayout,
                TreeLayout::new(parameters.roundCount)
            );
        }
    }

    #[test]
    fn eachLevelHashesWithTheFunctionOfItsSHA3Header() {
        // `sha3.h` of the category 1 sets uses SHAKE128, and of the others SHAKE256.
        for parameters in allSets {
            let expected = if parameters.code.securityBits == 128 {
                HashFunction::shake128
            } else {
                HashFunction::shake256
            };
            assert_eq!(parameters.hashFunction(), expected);
        }
    }

    #[test]
    fn packedLengthsAreTheDenselyPackedSizesOfTheCHeaders() {
        // ROUND_UP((N % 8) * B, 8) / 8 bytes after the whole groups of 8 values.
        assert_eq!(packedLength(127, 7), 112);
        assert_eq!(packedLength(51, 7), 45);
        assert_eq!(packedLength(127, 3), 48);
        assert_eq!(packedLength(55, 9), 62);
        assert_eq!(packedLength(19, 9), 22);
        assert_eq!(packedLength(25, 7), 22);
        assert_eq!(packedLength(40, 7), 35);
        assert_eq!(packedLength(8, 9), 9);
        assert_eq!(packedLength(1, 3), 1);
        assert_eq!(packedLength(0, 7), 0);
    }

    #[test]
    fn theSignatureFieldsFollowEachOtherInTheOrderOfTheCStructure() {
        let parameters: &Parameters = allSets[0];
        assert_eq!(parameters.saltRange(), 0..32);
        assert_eq!(parameters.commitmentDigestRange(), 32..64);
        assert_eq!(parameters.secondChallengeDigestRange(), 64..96);
        assert_eq!(parameters.pathRange(), 96..96 + 108 * 16);
        assert_eq!(parameters.proofRange(), 1824..1824 + 108 * 32);
        assert_eq!(parameters.commitmentResponsesRange(), 5280..5280 + 41 * 32);
        assert_eq!(parameters.responsesRange(), 6592..6592 + 41 * 160);
        assert_eq!(parameters.signatureLength(), 13152);
    }

    #[test]
    fn theDomainSeparatorsAreTheConstantsOfTheCCode() {
        let parameters = allSets[2];
        // T = 520 for cross-rsdp-128-small.
        assert_eq!(parameters.secretSeedDomain(), 1561);
        assert_eq!(parameters.publicSeedDomain(), 1562);
        assert_eq!(parameters.errorSeedDomain(), 1563);
        assert_eq!(parameters.firstChallengeDomain(), 1559);
        assert_eq!(parameters.secondChallengeDomain(), 1560);
        assert_eq!(parameters.roundDomain(0), 1039);
        assert_eq!(parameters.roundDomain(519), 1558);
    }

    #[test]
    fn theFastSetsStoreOneNodeForEachRevealedRound() {
        for parameters in allSets {
            if !parameters.tradeoff.usesTrees() {
                assert_eq!(
                    parameters.storedNodeCount, parameters.challengeWeight,
                    "{}",
                    parameters.description.name
                );
            }
        }
    }

    /// The most internal nodes of a subtree that have a hidden leaf below them, for each count
    /// of hidden leaves in the subtree up to a limit.
    fn coveredInternalNodes(
        layout: &TreeLayout,
        node: usize,
        level: usize,
        limit: usize,
    ) -> Vec<usize> {
        let position = node - layout.levelStart(level);
        if position >= layout.internalNodeCountOfLevel(level) {
            return vec![0, 0];
        }
        let left = layout.leftChild(node, level);
        let leftBest = coveredInternalNodes(layout, left, level + 1, limit);
        let rightBest = coveredInternalNodes(layout, left + 1, level + 1, limit);
        let largest = (leftBest.len() + rightBest.len() - 2).min(limit);
        let mut best = vec![0; largest + 1];
        for (count, entry) in best.iter_mut().enumerate().skip(1) {
            // The best split of the hidden leaves between the two children.
            let most = leftBest
                .iter()
                .enumerate()
                .take(count + 1)
                .filter_map(|(leftCount, left)| Some(left + rightBest.get(count - leftCount)?))
                .max()
                .unwrap_or(0);
            *entry = 1 + most;
        }
        best
    }

    #[test]
    fn theStoredNodeCountHoldsTheLongestPathAndProofOfAnyChallenge() {
        // A seed path holds the nodes outside the union S of the paths from the root to the
        // t - w hidden leaves whose parent is in S. The Merkle proof holds the same nodes. With
        // I internal nodes in S and h hidden leaves, that is I - h + 1 nodes. The largest I comes
        // from the most internal nodes that h leaves can cover.
        for parameters in allSets {
            if !parameters.tradeoff.usesTrees() {
                continue;
            }
            let hidden = parameters.responseCount();
            let best = coveredInternalNodes(&parameters.treeLayout, 0, 0, hidden);
            let longest = best[hidden] - hidden + 1;
            assert!(
                longest <= parameters.storedNodeCount,
                "{}: {longest} > {}",
                parameters.description.name,
                parameters.storedNodeCount
            );
        }
    }
}
