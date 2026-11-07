use crate::{Parameters, PseudorandomGenerator, XOF};
use alloc::vec;
use alloc::vec::Vec;

/// The MQ system of a public key over the extension field, as `ExpandEquations` of
/// `expand_mq.c` expands it from the equation seed.
///
/// Equation i of the m / µ equations has its own seed, the XOF of the byte 0x01, the equation
/// seed and i as two little-endian bytes. The PRG of that seed with the zero salt and the
/// repetition 0 gives the lower triangular matrix A_i row by row, row j with its j + 1 first
/// elements, and then the vector b_i of n elements. A product with x is `x^T A_i x + b_i^T x`.
pub(crate) struct EquationSystem {
    variableCount: usize,
    /// The elements of each equation: the rows of A_i and then b_i.
    elements: Vec<u16>,
}

impl EquationSystem {
    /// The system of an equation seed of 2 λ / 8 bytes.
    pub(crate) fn expanded(parameters: &Parameters, equationSeed: &[u8]) -> Self {
        let seedLength = parameters.seedLength();
        let variableCount = parameters.variableCount;
        let equationCount = parameters.equationCount();
        let elementCount = Self::elementCount(variableCount);
        let streamLength = parameters.extensionBytes(elementCount);
        let mut seeds = vec![0u8; equationCount * seedLength];
        for (equation, seed) in seeds.chunks_exact_mut(seedLength).enumerate() {
            let index = (equation as u16).to_le_bytes();
            XOF::hash(parameters, &[&[0x01], equationSeed, &index], seed);
        }
        let zeroSalt = vec![0u8; seedLength];
        let mut streams = vec![0u8; equationCount * streamLength];
        PseudorandomGenerator::new(&zeroSalt, 0, streamLength).fill(&seeds, &mut streams);
        EquationSystem {
            variableCount,
            elements: parameters.extensionField.decoded(&streams),
        }
    }

    /// The number of elements of one equation: the n (n + 1) / 2 elements of the rows of A and
    /// the n elements of b.
    const fn elementCount(variableCount: usize) -> usize {
        variableCount * (variableCount + 1) / 2 + variableCount
    }

    /// Row j of A_i: its j + 1 first elements, the others being zero.
    pub(crate) fn row(&self, equation: usize, row: usize) -> &[u16] {
        let start = equation * Self::elementCount(self.variableCount) + row * (row + 1) / 2;
        &self.elements[start..start + row + 1]
    }

    /// The vector b_i of the linear terms of an equation.
    pub(crate) fn linearTerms(&self, equation: usize) -> &[u16] {
        let end = (equation + 1) * Self::elementCount(self.variableCount);
        &self.elements[end - self.variableCount..end]
    }
}

#[cfg(test)]
mod tests {
    use super::EquationSystem;
    use crate::testInputs::{cAnswer, elementsDigest, everySet, sequenceBytes};

    #[test]
    fn theEquationsAreTheEquationsOfTheCFunctionForEverySet() {
        // `ExpandEquations` of a seeded equation seed: the rows of A_i, each with its j + 1
        // first elements, then b_i, for each equation.
        for parameters in everySet() {
            let name = parameters.description.name;
            let system =
                EquationSystem::expanded(parameters, &sequenceBytes(parameters.digestLength(), 9));
            let mut elements = Vec::new();
            for equation in 0..parameters.equationCount() {
                for row in 0..parameters.variableCount {
                    elements.extend_from_slice(system.row(equation, row));
                }
                elements.extend_from_slice(system.linearTerms(equation));
            }
            assert_eq!(
                elementsDigest(parameters, &[elements]),
                cAnswer(name, "equations"),
                "{name}"
            );
        }
    }
}
