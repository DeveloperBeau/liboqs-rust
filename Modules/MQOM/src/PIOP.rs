use crate::extensionField::{lifted, nibble};
use crate::lineCommitment::evaluationPoint;
use crate::{BitPlanes, EquationSystem, ExtensionField, LineTerms, Parameters, XOF};
use alloc::vec;
use alloc::vec::Vec;

/// The polynomial proof of a signature of one parameter set, as `piop_bitslice.c` computes it.
///
/// For the lines `P_x(r) = x0 + r x` and `P_u(r) = u0 + r u1` of a repetition, the polynomial
/// of equation i is `P_z,i(r) = P_x(r)^T A_i P_x(r) + r b_i^T P_x(r) - r^2 y_i`. Its degree two
/// term is zero for the secret x of the key, so `P_z(r) = z0 + r z1`. The proof gives the line
/// `P_alpha(r) = alpha0 + r alpha1` with `P_alpha = P_z + P_u`, or for five rounds the product
/// of the challenge matrix Gamma with P_z, plus P_u. The τ repetitions run together in the
/// lanes of `BitPlanes`, with x in lane τ, as the C code runs them in its bitsliced lanes.
pub(crate) struct PIOP<'parameters> {
    parameters: &'parameters Parameters,
}

/// The constant terms and the slopes of a set of lines: for each repetition, one element for
/// each equation or for each of the η combinations.
type Lines = (Vec<Vec<u16>>, Vec<Vec<u16>>);

impl<'parameters> PIOP<'parameters> {
    /// Makes the proof of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        PIOP { parameters }
    }

    /// The constant terms z0 and the slopes z1 of P_z for each repetition, as
    /// `ComputePz_xTau_bitslice` computes them.
    fn quadraticLines<const BitCount: usize>(
        &self,
        constantTermsOfX: &[Vec<u16>],
        variables: &[u8],
        equations: &EquationSystem,
    ) -> Lines {
        let parameters = self.parameters;
        let repetitionCount = parameters.repetitionCount;
        let equationCount = parameters.equationCount();
        let liftedVariables: Vec<u16> = (0..parameters.variableCount)
            .map(|index| u16::from(lifted(nibble(variables, index))))
            .collect();
        // Lane e holds x0 of repetition e, and lane τ holds x.
        let planes: Vec<BitPlanes<BitCount>> = liftedVariables
            .iter()
            .enumerate()
            .map(|(index, variable)| {
                let mut planes = BitPlanes::fromLanes(
                    constantTermsOfX
                        .iter()
                        .map(|constantTerms| constantTerms[index]),
                );
                planes.insert(repetitionCount, *variable);
                planes
            })
            .collect();
        let multiples: Vec<[BitPlanes<BitCount>; BitCount]> =
            planes.iter().map(BitPlanes::basisMultiples).collect();
        let mut constantTerms = vec![vec![0u16; equationCount]; repetitionCount];
        let mut slopes = vec![vec![0u16; equationCount]; repetitionCount];
        for equation in 0..equationCount {
            let linearTerms = equations.linearTerms(equation);
            let mut constantTerm = BitPlanes::<BitCount>::zero;
            let mut slope = BitPlanes::<BitCount>::zero;
            for (row, ((planesOfRow, multiplesOfRow), linearTerm)) in
                planes.iter().zip(&multiples).zip(linearTerms).enumerate()
            {
                // t0 = A_i P_x, row by row: in lane e the row of A_i times x0, in lane τ the row
                // of A_i times x.
                let mut product = BitPlanes::<BitCount>::zero;
                for (element, columnMultiples) in
                    equations.row(equation, row).iter().zip(&multiples)
                {
                    product.addPublicProduct(*element, columnMultiples);
                }
                // t1 = A_i x + b_i, the slope of A_i P_x + r b_i.
                let t1 = product.lane(repetitionCount) ^ linearTerm;
                slope.addProduct(t1, multiplesOfRow);
                slope.addProduct(liftedVariables[row], &product.basisMultiples());
                constantTerm.add(&planesOfRow.times(&product));
            }
            for repetition in 0..repetitionCount {
                constantTerms[repetition][equation] = constantTerm.lane(repetition);
                slopes[repetition][equation] = slope.lane(repetition);
            }
        }
        (constantTerms, slopes)
    }

    /// The values `P_z(r)` at the evaluation point r of each repetition, as
    /// `ComputePzEval_xTau_bitslice` computes them from the evaluations of the lines of x.
    fn quadraticEvaluations<const BitCount: usize>(
        &self,
        points: &[u16],
        variableEvaluations: &[Vec<u16>],
        equations: &EquationSystem,
        image: &[u16],
    ) -> Vec<Vec<u16>> {
        let parameters = self.parameters;
        let equationCount = parameters.equationCount();
        let planes: Vec<BitPlanes<BitCount>> = (0..parameters.variableCount)
            .map(|index| {
                BitPlanes::fromLanes(variableEvaluations.iter().map(|values| values[index]))
            })
            .collect();
        let multiples: Vec<[BitPlanes<BitCount>; BitCount]> =
            planes.iter().map(BitPlanes::basisMultiples).collect();
        let pointPlanes = BitPlanes::<BitCount>::fromLanes(points.iter().copied());
        let pointMultiples = pointPlanes.basisMultiples();
        let squareMultiples = pointPlanes.times(&pointPlanes).basisMultiples();
        let mut values = vec![vec![0u16; equationCount]; parameters.repetitionCount];
        for (equation, imageElement) in image.iter().enumerate().take(equationCount) {
            let linearTerms = equations.linearTerms(equation);
            // v_z = v_t^T v_x - y_i r^2 with v_t = A_i v_x + r b_i.
            let mut value = BitPlanes::product(*imageElement, &squareMultiples);
            for (row, (planesOfRow, linearTerm)) in planes.iter().zip(linearTerms).enumerate() {
                let mut product = BitPlanes::product(*linearTerm, &pointMultiples);
                for (element, columnMultiples) in
                    equations.row(equation, row).iter().zip(&multiples)
                {
                    product.addPublicProduct(*element, columnMultiples);
                }
                value.add(&product.times(planesOfRow));
            }
            for (repetition, repetitionValues) in values.iter_mut().enumerate() {
                repetitionValues[equation] = value.lane(repetition);
            }
        }
        values
    }

    /// The challenge matrix Gamma of the five-round sets: the XOF of the byte 0x08 and com1,
    /// as `ExpandBatchingChallenge` reads it, η rows of m / µ elements.
    fn batchingMatrix(&self, commitment: &[u8]) -> Vec<Vec<u16>> {
        let parameters = self.parameters;
        let rowBytes = parameters.extensionBytes(parameters.equationCount());
        let mut stream = vec![0u8; parameters.eta * rowBytes];
        XOF::hash(parameters, &[&[0x08], commitment], &mut stream);
        stream
            .chunks_exact(rowBytes)
            .map(|row| parameters.extensionField.decoded(row))
            .collect()
    }

    /// The combinations of the values of the equations of a repetition: the product with Gamma
    /// for five rounds, and the values themselves for three rounds.
    fn combined(&self, matrix: &[Vec<u16>], values: &[u16]) -> Vec<u16> {
        let field = self.parameters.extensionField;
        if !self.parameters.hasBatching {
            return values.to_vec();
        }
        matrix
            .iter()
            .map(|row| {
                row.iter().zip(values).fold(0u16, |sum, (left, right)| {
                    sum ^ field.product(*left, *right)
                })
            })
            .collect()
    }

    /// The lines of P_alpha of the signer, alpha0 and alpha1 of each repetition, as
    /// `ComputePAlpha_bitslice` computes them from com1, the lines of the line commitment and
    /// the secret x.
    pub(crate) fn alphas(
        &self,
        commitment: &[u8],
        lines: &LineTerms,
        variables: &[u8],
        equations: &EquationSystem,
    ) -> Lines {
        let (constantTerms, slopes) = match self.parameters.extensionField {
            ExtensionField::gf256 => {
                self.quadraticLines::<8>(&lines.constantTermsOfX, variables, equations)
            }
            ExtensionField::gf65536 => {
                self.quadraticLines::<16>(&lines.constantTermsOfX, variables, equations)
            }
        };
        let matrix = if self.parameters.hasBatching {
            self.batchingMatrix(commitment)
        } else {
            Vec::new()
        };
        let sumWith = |values: &[u16], masks: &[u16]| -> Vec<u16> {
            self.combined(&matrix, values)
                .iter()
                .zip(masks)
                .map(|(value, mask)| value ^ mask)
                .collect()
        };
        let constantTerms = constantTerms
            .iter()
            .zip(&lines.constantTermsOfU)
            .map(|(values, masks)| sumWith(values, masks))
            .collect();
        let slopes = slopes
            .iter()
            .zip(&lines.slopesOfU)
            .map(|(values, masks)| sumWith(values, masks))
            .collect();
        (constantTerms, slopes)
    }

    /// The constant terms alpha0 of the verifier, as `RecomputePAlpha_bitslice` computes them:
    /// `alpha0 = P_alpha(r) + r alpha1`, with `P_alpha(r)` from the evaluations of the lines at
    /// the evaluation point r of the hidden leaf of each repetition.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recomputedConstantTerms(
        &self,
        commitment: &[u8],
        slopes: &[Vec<u16>],
        hiddenLeaves: &[u16],
        variableEvaluations: &[Vec<u16>],
        maskEvaluations: &[Vec<u16>],
        equations: &EquationSystem,
        image: &[u16],
    ) -> Vec<Vec<u16>> {
        let field = self.parameters.extensionField;
        let points: Vec<u16> = hiddenLeaves
            .iter()
            .map(|leaf| evaluationPoint(*leaf))
            .collect();
        let values = match field {
            ExtensionField::gf256 => {
                self.quadraticEvaluations::<8>(&points, variableEvaluations, equations, image)
            }
            ExtensionField::gf65536 => {
                self.quadraticEvaluations::<16>(&points, variableEvaluations, equations, image)
            }
        };
        let matrix = if self.parameters.hasBatching {
            self.batchingMatrix(commitment)
        } else {
            Vec::new()
        };
        values
            .iter()
            .zip(maskEvaluations)
            .zip(slopes.iter().zip(&points))
            .map(|((values, masks), (slope, point))| {
                self.combined(&matrix, values)
                    .iter()
                    .zip(masks)
                    .zip(slope)
                    .map(|((value, mask), slopeElement)| {
                        value ^ mask ^ field.product(*point, *slopeElement)
                    })
                    .collect()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::PIOP;
    use crate::testInputs::{
        cAnswer, elementsDigest, everySet, sequenceBytes, sequenceElements, sequenceHiddenLeaves,
        sequenceRows,
    };
    use crate::{EquationSystem, LineTerms};

    #[test]
    fn theLinesAndTheRecomputationAreThoseOfTheCFunctions() {
        // `ComputePAlpha_bitslice` of a seeded com1, seeded lines x0, u0 and u1, a seeded x and
        // the equations of a seeded seed, and `RecomputePAlpha_bitslice` of seeded slopes,
        // hidden leaves, evaluations and image. The inputs need not come from a key pair.
        for parameters in everySet() {
            let name = parameters.description.name;
            let repetitionCount = parameters.repetitionCount;
            let proof = PIOP::new(parameters);
            let commitment = sequenceBytes(parameters.digestLength(), 15);
            let lines = LineTerms {
                constantTermsOfX: sequenceRows(
                    parameters,
                    repetitionCount,
                    parameters.variableCount,
                    16,
                ),
                constantTermsOfU: sequenceRows(parameters, repetitionCount, parameters.eta, 17),
                slopesOfU: sequenceRows(parameters, repetitionCount, parameters.eta, 18),
            };
            let variables = sequenceBytes(parameters.variableBytes(), 19);
            let equations =
                EquationSystem::expanded(parameters, &sequenceBytes(parameters.digestLength(), 20));
            let (constantTerms, slopes) = proof.alphas(&commitment, &lines, &variables, &equations);
            assert_eq!(
                elementsDigest(parameters, &constantTerms),
                cAnswer(name, "alphaConstantTerms"),
                "{name}"
            );
            assert_eq!(
                elementsDigest(parameters, &slopes),
                cAnswer(name, "alphaSlopes"),
                "{name}"
            );
            let recomputed = proof.recomputedConstantTerms(
                &commitment,
                &sequenceRows(parameters, repetitionCount, parameters.eta, 21),
                &sequenceHiddenLeaves(parameters, 22),
                &sequenceRows(parameters, repetitionCount, parameters.variableCount, 23),
                &sequenceRows(parameters, repetitionCount, parameters.eta, 24),
                &equations,
                &sequenceElements(parameters, parameters.equationCount(), 25),
            );
            assert_eq!(
                elementsDigest(parameters, &recomputed),
                cAnswer(name, "recomputedConstantTerms"),
                "{name}"
            );
        }
    }
}
