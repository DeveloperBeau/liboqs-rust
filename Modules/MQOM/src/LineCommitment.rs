use crate::extensionField::{lifted, nibble};
use crate::seedCipher::commitmentTweak;
use crate::{GGMTree, LineTerms, Parameters, PseudorandomGenerator, SeedCipher, XOF};
use alloc::vec;
use alloc::vec::Vec;

/// The batched line commitment of a signature and its secret state, as `BLC_Commit_default`
/// of `blc_default.c` computes them.
///
/// The default build of liboqs keeps only the root seeds and expands each tree again for the
/// opening. This type keeps the trees and the leaf commitments of the signature, which give the
/// same opening.
///
/// For each repetition e, the N leaves of a seed tree expand to shares of x and of the mask u.
/// With the evaluation point ω_i of leaf i, the Gray code of i, the lines are
/// `P_x(r) = x0 + r x` and `P_u(r) = u0 + r u1`, with x0 the sum of ω_i times the shares of x,
/// u0 the sum of ω_i times the shares of u and u1 the sum of the shares of u. The commitment
/// com1 binds the leaf commitments and the partial deltas of the τ repetitions.
pub(crate) struct LineCommitment {
    /// The commitment com1 of 2 λ / 8 bytes.
    pub(crate) commitment: Vec<u8>,
    /// The terms of the lines of each repetition.
    pub(crate) lines: LineTerms,
    /// The seed tree of each repetition.
    trees: Vec<GGMTree>,
    /// The commitment of 2 λ / 8 bytes of each leaf of each repetition.
    leafCommitments: Vec<Vec<u8>>,
    /// The bytes of x plus the sum of the shares of x, from byte λ / 8 on, of each repetition.
    partialDeltas: Vec<u8>,
}

/// The leaf commitments, the sum of the shares and the Gray code folds of one repetition.
type FoldedLeaves = (Vec<u8>, Vec<u8>, Vec<Vec<u8>>);

/// The evaluations of the line of x and of the line of u at the point of the hidden leaf of
/// each repetition.
type Evaluations = (Vec<Vec<u16>>, Vec<Vec<u16>>);

/// The index of the fold that takes the running sum after leaf `index`, as
/// `get_gray_code_bit_position` computes it: the bit that changes from the Gray code of the
/// leaf to the Gray code of the next leaf, with the code 0 after the last leaf.
fn foldIndex(index: usize, leafCount: usize) -> usize {
    let grayCode = |value: usize| value ^ (value >> 1);
    let next = if index + 1 < leafCount {
        grayCode(index + 1)
    } else {
        0
    };
    (grayCode(index) ^ next).trailing_zeros() as usize
}

/// The evaluation point of a leaf: its Gray code as an element of the extension field, as
/// `get_evaluation_point` gives it.
pub(crate) fn evaluationPoint(leaf: u16) -> u16 {
    leaf ^ (leaf >> 1)
}

impl LineCommitment {
    /// The commitments, the expansions and the folds of the leaves of one repetition, as the
    /// loop over the leaves of `BLC_Commit_default` and `BLC_Eval_default` computes them.
    ///
    /// The commitment of a leaf seed is its derived seed under the tweak of selector 0 and then
    /// under the same tweak with bit 0 of byte 0 flipped. Its share is the seed and its PRG
    /// output. The running sum of the shares after each leaf is added to the fold of
    /// `foldIndex`. A hidden leaf takes the opened commitment and the zero share.
    fn foldedLeaves(
        parameters: &Parameters,
        salt: &[u8],
        repetition: usize,
        leaves: &[u8],
        hiddenLeaf: Option<(usize, &[u8])>,
    ) -> FoldedLeaves {
        let seedLength = parameters.seedLength();
        let leafCount = parameters.leafCount();
        let generatorLength = parameters.leafGeneratorBytes();
        let shareLength = parameters.leafExpansionBytes();
        let firstKey = SeedCipher::tweaked(salt, commitmentTweak, repetition, 0);
        // The second key flips bit 0 of byte 0 of the first one. Four times the repetition
        // has its two low bits zero, so the flip is the tweak of selector 1.
        let secondKey = SeedCipher::tweaked(salt, commitmentTweak + 1, repetition, 0);
        let mut firstHalves = vec![0u8; leaves.len()];
        let mut secondHalves = vec![0u8; leaves.len()];
        firstKey.derive(leaves, &mut firstHalves);
        secondKey.derive(leaves, &mut secondHalves);
        let mut generated = vec![0u8; leafCount * generatorLength];
        PseudorandomGenerator::new(salt, repetition, generatorLength).fill(leaves, &mut generated);
        let mut commitments = Vec::with_capacity(2 * leaves.len());
        let mut sum = vec![0u8; shareLength];
        let mut folds = vec![vec![0u8; shareLength]; parameters.treeDepth];
        for leaf in 0..leafCount {
            let seed = &leaves[leaf * seedLength..(leaf + 1) * seedLength];
            let output = &generated[leaf * generatorLength..(leaf + 1) * generatorLength];
            match hiddenLeaf {
                Some((hidden, opened)) if hidden == leaf => {
                    commitments.extend_from_slice(opened);
                }
                _ => {
                    commitments.extend_from_slice(
                        &firstHalves[leaf * seedLength..(leaf + 1) * seedLength],
                    );
                    commitments.extend_from_slice(
                        &secondHalves[leaf * seedLength..(leaf + 1) * seedLength],
                    );
                    for (total, byte) in sum.iter_mut().zip(seed.iter().chain(output)) {
                        *total ^= byte;
                    }
                }
            }
            let fold = &mut folds[foldIndex(leaf, leafCount)];
            for (folded, total) in fold.iter_mut().zip(&sum) {
                *folded ^= total;
            }
        }
        (commitments, sum, folds)
    }

    /// The sum of ω_i times the shares of x over the leaves, from the folds: fold j holds the
    /// sum of the shares of the leaves whose Gray code has bit j set, so the sum is the sum of
    /// 2^j times fold j.
    fn weightedVariables(parameters: &Parameters, folds: &[Vec<u8>]) -> Vec<u16> {
        let field = parameters.extensionField;
        (0..parameters.variableCount)
            .map(|index| {
                folds.iter().enumerate().fold(0u16, |total, (bit, fold)| {
                    total ^ field.product(1 << bit, u16::from(lifted(nibble(fold, index))))
                })
            })
            .collect()
    }

    /// The sum of ω_i times the shares of u over the leaves, from the folds.
    fn weightedMasks(parameters: &Parameters, folds: &[Vec<u8>]) -> Vec<u16> {
        let field = parameters.extensionField;
        let variableBytes = parameters.variableBytes();
        let mut total = vec![0u16; parameters.eta];
        for (bit, fold) in folds.iter().enumerate() {
            let masks = field.decoded(&fold[variableBytes..]);
            for (sum, mask) in total.iter_mut().zip(masks) {
                *sum ^= field.product(1 << bit, mask);
            }
        }
        total
    }

    /// The commitment com1: the XOF of the byte 0x07, the hash of the leaf commitments of each
    /// repetition and the partial deltas.
    fn commitmentOf(
        parameters: &Parameters,
        leafCommitmentHashes: &[u8],
        partialDeltas: &[u8],
    ) -> Vec<u8> {
        let mut commitment = vec![0u8; parameters.digestLength()];
        XOF::hash(
            parameters,
            &[&[0x07], leafCommitmentHashes, partialDeltas],
            &mut commitment,
        );
        commitment
    }

    /// The hash of the leaf commitments of one repetition: the XOF of the byte 0x06 and the N
    /// commitments.
    fn leafCommitmentHash(parameters: &Parameters, commitments: &[u8], output: &mut [u8]) {
        XOF::hash(parameters, &[&[0x06], commitments], output);
    }

    /// Commits to the lines of a secret x of n / 2 bytes, with a root seed and a salt, as
    /// `BLC_Commit_default` does. The root seeds of the τ trees are the PRG output of the root
    /// seed with the zero salt and the repetition 0.
    pub(crate) fn committed(
        parameters: &Parameters,
        rootSeed: &[u8],
        salt: &[u8],
        variables: &[u8],
    ) -> Self {
        let seedLength = parameters.seedLength();
        let digestLength = parameters.digestLength();
        let repetitionCount = parameters.repetitionCount;
        let variableBytes = parameters.variableBytes();
        let zeroSalt = vec![0u8; seedLength];
        let rootSeeds =
            PseudorandomGenerator::new(&zeroSalt, 0, repetitionCount * seedLength).output(rootSeed);
        // delta, the first seed of x, is the sum of the leaves of each tree.
        let delta = &variables[..seedLength];
        let mut committed = LineCommitment {
            commitment: Vec::new(),
            lines: LineTerms {
                constantTermsOfX: Vec::with_capacity(repetitionCount),
                constantTermsOfU: Vec::with_capacity(repetitionCount),
                slopesOfU: Vec::with_capacity(repetitionCount),
            },
            trees: Vec::with_capacity(repetitionCount),
            leafCommitments: Vec::with_capacity(repetitionCount),
            partialDeltas: Vec::with_capacity(repetitionCount * parameters.partialDeltaBytes()),
        };
        let mut hashes = vec![0u8; repetitionCount * digestLength];
        for (repetition, (rootSeed, hash)) in rootSeeds
            .chunks_exact(seedLength)
            .zip(hashes.chunks_exact_mut(digestLength))
            .enumerate()
        {
            let tree = GGMTree::expanded(parameters, salt, rootSeed, delta, repetition);
            let (commitments, sum, folds) =
                Self::foldedLeaves(parameters, salt, repetition, tree.leaves(), None);
            let lines = &mut committed.lines;
            lines
                .constantTermsOfX
                .push(Self::weightedVariables(parameters, &folds));
            lines
                .constantTermsOfU
                .push(Self::weightedMasks(parameters, &folds));
            lines
                .slopesOfU
                .push(parameters.extensionField.decoded(&sum[variableBytes..]));
            // The partial delta is x plus the sum of the shares of x, without its first seed,
            // which is zero.
            committed.partialDeltas.extend(
                variables[seedLength..]
                    .iter()
                    .zip(&sum[seedLength..variableBytes])
                    .map(|(variable, share)| variable ^ share),
            );
            Self::leafCommitmentHash(parameters, &commitments, hash);
            committed.trees.push(tree);
            committed.leafCommitments.push(commitments);
        }
        committed.commitment = Self::commitmentOf(parameters, &hashes, &committed.partialDeltas);
        committed
    }

    /// The opening of the hidden leaf of each repetition, as `BLC_Open_default` writes it: the
    /// τ sibling paths, then the τ commitments of the hidden leaves, then the τ partial deltas.
    pub(crate) fn opening(&self, parameters: &Parameters, hiddenLeaves: &[u16]) -> Vec<u8> {
        let digestLength = parameters.digestLength();
        let mut opening = Vec::with_capacity(parameters.openingLength());
        for (tree, hidden) in self.trees.iter().zip(hiddenLeaves) {
            opening.extend_from_slice(&tree.path(usize::from(*hidden)));
        }
        for (commitments, hidden) in self.leafCommitments.iter().zip(hiddenLeaves) {
            let start = usize::from(*hidden) * digestLength;
            opening.extend_from_slice(&commitments[start..start + digestLength]);
        }
        opening.extend_from_slice(&self.partialDeltas);
        opening
    }

    /// The evaluations of the lines of x and of u at the evaluation point of the hidden leaf of
    /// each repetition, as `BLC_Eval_default` computes them from an opening of the right
    /// length. `None` when the commitment of the opening is not com1.
    pub(crate) fn evaluations(
        parameters: &Parameters,
        salt: &[u8],
        commitment: &[u8],
        opening: &[u8],
        hiddenLeaves: &[u16],
    ) -> Option<Evaluations> {
        let seedLength = parameters.seedLength();
        let digestLength = parameters.digestLength();
        let repetitionCount = parameters.repetitionCount;
        let field = parameters.extensionField;
        let variableBytes = parameters.variableBytes();
        let pathLength = parameters.treeDepth * seedLength;
        let commitmentsStart = repetitionCount * pathLength;
        let partialDeltas = &opening[repetitionCount * (pathLength + digestLength)..];
        let mut variableEvaluations = Vec::with_capacity(repetitionCount);
        let mut maskEvaluations = Vec::with_capacity(repetitionCount);
        let mut hashes = vec![0u8; repetitionCount * digestLength];
        for (repetition, ((hidden, hash), partialDelta)) in hiddenLeaves
            .iter()
            .zip(hashes.chunks_exact_mut(digestLength))
            .zip(partialDeltas.chunks_exact(parameters.partialDeltaBytes()))
            .enumerate()
        {
            let hidden = usize::from(*hidden);
            let path = &opening[repetition * pathLength..(repetition + 1) * pathLength];
            let opened = &opening[commitmentsStart + repetition * digestLength
                ..commitmentsStart + (repetition + 1) * digestLength];
            let leaves = GGMTree::partialLeaves(parameters, salt, path, repetition, hidden);
            let (commitments, sum, folds) = Self::foldedLeaves(
                parameters,
                salt,
                repetition,
                &leaves,
                Some((hidden, opened)),
            );
            let point = evaluationPoint(hidden as u16);
            // x_eval = x0' + r (the sum of the shares + delta), with zero for the first seed of
            // delta.
            let mut variables = Self::weightedVariables(parameters, &folds);
            for (index, variable) in variables.iter_mut().enumerate() {
                let delta = if index < 2 * seedLength {
                    0
                } else {
                    nibble(partialDelta, index - 2 * seedLength)
                };
                let total = nibble(&sum, index) ^ delta;
                *variable ^= field.product(point, u16::from(lifted(total)));
            }
            let mut masks = Self::weightedMasks(parameters, &folds);
            for (mask, share) in masks.iter_mut().zip(field.decoded(&sum[variableBytes..])) {
                *mask ^= field.product(point, share);
            }
            variableEvaluations.push(variables);
            maskEvaluations.push(masks);
            Self::leafCommitmentHash(parameters, &commitments, hash);
        }
        let recomputed = Self::commitmentOf(parameters, &hashes, partialDeltas);
        (recomputed == commitment).then_some((variableEvaluations, maskEvaluations))
    }
}

#[cfg(test)]
mod tests {
    use super::{LineCommitment, evaluationPoint, foldIndex};
    use crate::testInputs::{
        cAnswer, elementsDigest, everySet, sequenceBytes, sequenceHiddenLeaves,
    };
    use OQSNativeAlgorithmTests::OutputDigest;

    #[test]
    fn foldIndexIsTheBitThatTheGrayCodeChangesAfterTheLeaf() {
        // The Gray codes 0, 1, 3, 2, 6, 7, 5, 4 of eight leaves change the bits 0, 1, 0, 2, 0,
        // 1, 0, and the last code 4 = 0b100 changes bit 2 to reach 0.
        let indices: Vec<usize> = (0..8).map(|leaf| foldIndex(leaf, 8)).collect();
        assert_eq!(indices, vec![0, 1, 0, 2, 0, 1, 0, 2]);
        assert_eq!(foldIndex(2047, 2048), 10);
        assert_eq!(foldIndex(1023, 2048), 10);
        let points: Vec<u16> = (0..8).map(evaluationPoint).collect();
        assert_eq!(points, vec![0, 1, 3, 2, 6, 7, 5, 4]);
    }

    #[test]
    fn theCommitmentItsOpeningAndItsEvaluationsAreThoseOfTheCFunctions() {
        // `BLC_Commit_default` of a seeded root seed, salt and x, then `BLC_Open_default` of
        // seeded hidden leaves and `BLC_Eval_default` of the opening, which accepts it, and of
        // the opening with a bit of the last partial delta changed, which it refuses.
        for parameters in everySet() {
            let name = parameters.description.name;
            let seedLength = parameters.seedLength();
            let salt = sequenceBytes(seedLength, 12);
            let committed = LineCommitment::committed(
                parameters,
                &sequenceBytes(seedLength, 11),
                &salt,
                &sequenceBytes(parameters.variableBytes(), 13),
            );
            let lines = &committed.lines;
            assert_eq!(
                OutputDigest::of(&committed.commitment),
                cAnswer(name, "lineCommitment"),
                "{name}"
            );
            assert_eq!(
                elementsDigest(parameters, &lines.constantTermsOfX),
                cAnswer(name, "constantTermsOfX"),
                "{name}"
            );
            assert_eq!(
                elementsDigest(parameters, &lines.constantTermsOfU),
                cAnswer(name, "constantTermsOfU"),
                "{name}"
            );
            assert_eq!(
                elementsDigest(parameters, &lines.slopesOfU),
                cAnswer(name, "slopesOfU"),
                "{name}"
            );
            let hiddenLeaves = sequenceHiddenLeaves(parameters, 14);
            let mut opening = committed.opening(parameters, &hiddenLeaves);
            assert_eq!(opening.len(), parameters.openingLength());
            assert_eq!(
                OutputDigest::of(&opening),
                cAnswer(name, "opening"),
                "{name}"
            );
            let (variableEvaluations, maskEvaluations) = LineCommitment::evaluations(
                parameters,
                &salt,
                &committed.commitment,
                &opening,
                &hiddenLeaves,
            )
            .expect("the opening of the commitment");
            assert_eq!(cAnswer(name, "evaluationResult"), "0");
            assert_eq!(
                elementsDigest(parameters, &variableEvaluations),
                cAnswer(name, "variableEvaluations"),
                "{name}"
            );
            assert_eq!(
                elementsDigest(parameters, &maskEvaluations),
                cAnswer(name, "maskEvaluations"),
                "{name}"
            );
            *opening.last_mut().expect("an opening") ^= 0x10;
            assert_eq!(cAnswer(name, "changedOpeningResult"), "-1");
            assert!(
                LineCommitment::evaluations(
                    parameters,
                    &salt,
                    &committed.commitment,
                    &opening,
                    &hiddenLeaves
                )
                .is_none(),
                "{name}"
            );
        }
    }
}
