use crate::Parameters;
use crate::matrixRing::MatrixRing;
use crate::nibblePacking::NibblePacking;
use crate::parameters::publicSeedLength;
use OQSNativeSHA3::SHAKE256;
use alloc::vec;
use alloc::vec::Vec;

/// The part of the public map that the public seed gives, `map_group1` of `snova.h`: the
/// matrices P11, P12 and P21 of each equation, and the matrices A, B, Q1 and Q2 of each term of
/// each equation.
///
/// Each field holds its matrices one after the other, each in `l^2` elements row by row, in the
/// order of the arrays of the C code: P11 by equation, row and column of `v x v` blocks, P12 of
/// `v x o` blocks, P21 of `o x v` blocks, and A, B, Q1 and Q2 by equation and term.
pub(crate) struct PublicMap {
    /// The blocks P11, `m x v x v` matrices.
    pub(crate) p11: Vec<u8>,
    /// The blocks P12, `m x v x o` matrices.
    pub(crate) p12: Vec<u8>,
    /// The blocks P21, `m x o x v` matrices.
    pub(crate) p21: Vec<u8>,
    /// The matrices A, `m x alpha`, each invertible.
    pub(crate) a: Vec<u8>,
    /// The matrices B, `m x alpha`, each invertible.
    pub(crate) b: Vec<u8>,
    /// The matrices Q1, `m x alpha`, each an invertible element of F16[S].
    pub(crate) q1: Vec<u8>,
    /// The matrices Q2, `m x alpha`, each an invertible element of F16[S].
    pub(crate) q2: Vec<u8>,
}

/// The seed of the fixed matrices A, B, Q1 and Q2 of the ranks below 4, `gen_ABQ("SNOVA_ABQ")`.
const fixedMatrixSeed: &[u8] = b"SNOVA_ABQ";

impl PublicMap {
    /// The public map of a public seed, `gen_A_B_Q_P` of `snova_kernel.h`.
    ///
    /// The expansion of the seed gives P11, P12, P21, A and B as elements, in that order, and
    /// its last bytes give the `l` coefficients of each matrix Q1 and Q2. A matrix A or B with
    /// determinant zero becomes invertible by `MatrixRing::makeInvertible`. For a rank below 4,
    /// the fixed matrices of `fixedMatrices` replace A, B, Q1 and Q2.
    pub(crate) fn generated(
        parameters: &Parameters,
        ring: &MatrixRing,
        publicSeed: &[u8; publicSeedLength],
    ) -> PublicMap {
        let squaredRank = parameters.squaredRank();
        let (vinegarCount, oilCount) = (parameters.vinegarCount, parameters.oilCount);
        let termMatrixCount = oilCount * parameters.termCount();
        let elementCount = parameters.publicMapElementCount();
        let coefficientCount = parameters.coefficientCountOfQ();
        let bytes = parameters
            .publicKeyExpansion
            .expanded(publicSeed, elementCount.div_ceil(2));
        let elements = NibblePacking::unpacked(&bytes, elementCount - coefficientCount);
        let mut position = 0;
        let mut take = |matrixCount: usize| -> Vec<u8> {
            let start = position;
            position += matrixCount * squaredRank;
            elements[start..position].to_vec()
        };
        let p11 = take(oilCount * vinegarCount * vinegarCount);
        let p12 = take(oilCount * vinegarCount * oilCount);
        let p21 = take(oilCount * oilCount * vinegarCount);
        let mut a = take(termMatrixCount);
        let mut b = take(termMatrixCount);
        if parameters.hasFixedMatrices() {
            let (a, b, q1, q2) = Self::fixedMatrices(parameters, ring);
            return PublicMap {
                p11,
                p12,
                p21,
                a,
                b,
                q1,
                q2,
            };
        }
        let coefficients = NibblePacking::unpacked(
            &bytes[bytes.len() - coefficientCount.div_ceil(2)..],
            coefficientCount,
        );
        for matrix in a
            .chunks_exact_mut(squaredRank)
            .chain(b.chunks_exact_mut(squaredRank))
        {
            ring.makeInvertible(matrix);
        }
        let (q1, q2) = Self::matricesOfQ(parameters, ring, &coefficients);
        PublicMap {
            p11,
            p12,
            p21,
            a,
            b,
            q1,
            q2,
        }
    }

    /// The matrices Q1 and Q2 of their coefficients: `l` coefficients for each matrix, Q1 first.
    fn matricesOfQ(
        parameters: &Parameters,
        ring: &MatrixRing,
        coefficients: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let rank = parameters.rank;
        let squaredRank = parameters.squaredRank();
        let termMatrixCount = parameters.oilCount * parameters.termCount();
        let mut q = vec![0u8; 2 * termMatrixCount * squaredRank];
        for (matrix, coefficients) in q
            .chunks_exact_mut(squaredRank)
            .zip(coefficients.chunks_exact(rank))
        {
            ring.writeSumOfPowers(coefficients, matrix);
        }
        let q2 = q.split_off(termMatrixCount * squaredRank);
        (q, q2)
    }

    /// The fixed matrices A, B, Q1 and Q2 of a rank below 4, `gen_ABQ` of `snova.c`.
    ///
    /// SHAKE256 of the text `SNOVA_ABQ` gives the elements of A and B, each made invertible.
    /// The coefficients of Q1 and Q2 start at the byte `alpha l^2` of the same output, inside
    /// the bytes of A, as the C code reads them.
    fn fixedMatrices(
        parameters: &Parameters,
        ring: &MatrixRing,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let squaredRank = parameters.squaredRank();
        let termCount = parameters.termCount();
        let termMatrixCount = parameters.oilCount * termCount;
        let mut output = vec![0u8; termMatrixCount * (squaredRank + parameters.rank)];
        SHAKE256::hash(fixedMatrixSeed, &mut output);
        let mut a = NibblePacking::unpacked(&output, 2 * termMatrixCount * squaredRank);
        let mut b = a.split_off(termMatrixCount * squaredRank);
        for matrix in a
            .chunks_exact_mut(squaredRank)
            .chain(b.chunks_exact_mut(squaredRank))
        {
            ring.makeInvertible(matrix);
        }
        let coefficients = NibblePacking::unpacked(
            &output[termCount * squaredRank..],
            parameters.coefficientCountOfQ(),
        );
        let (q1, q2) = Self::matricesOfQ(parameters, ring, &coefficients);
        (a, b, q1, q2)
    }
}
