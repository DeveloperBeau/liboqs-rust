//! The products of matrices whose entries are packed vectors with matrices of elements, as
//! `generic_arithmetic.h` computes them. The public map holds m matrices P1_i, P2_i and P3_i.
//! The C code stores the entry at one place of all m matrices as one packed vector, so a matrix
//! of packed vectors stands for m matrices of elements, and one product covers all m.

use crate::Parameters;
use crate::packedVectors::{add, multiplyAdd, multiplyBins};
use alloc::vec;
use alloc::vec::Vec;

/// The packed vector at an index of a list of packed vectors.
fn entry(vectors: &[u64], index: usize, limbCount: usize) -> &[u64] {
    &vectors[index * limbCount..(index + 1) * limbCount]
}

/// The packed vector at an index of a list of packed vectors, for a change.
fn mutableEntry(vectors: &mut [u64], index: usize, limbCount: usize) -> &mut [u64] {
    &mut vectors[index * limbCount..(index + 1) * limbCount]
}

/// Adds the product of an upper triangular matrix of packed vectors of a size, its entries in
/// row order, with a matrix of elements to a matrix of packed vectors, as
/// `mul_add_m_upper_triangular_mat_x_mat` with `triangular` 1.
pub(crate) fn addUpperTriangularTimesMatrix(
    upper: &[u64],
    matrix: &[u8],
    accumulator: &mut [u64],
    size: usize,
    matrixColumns: usize,
    limbCount: usize,
) {
    let mut used = 0;
    for row in 0..size {
        for column in row..size {
            let vector = entry(upper, used, limbCount);
            for index in 0..matrixColumns {
                multiplyAdd(
                    vector,
                    matrix[column * matrixColumns + index],
                    mutableEntry(accumulator, row * matrixColumns + index, limbCount),
                );
            }
            used += 1;
        }
    }
}

/// Adds the product of an upper triangular matrix of packed vectors with the transpose of a
/// matrix of elements of `matrixRows` rows to a matrix of packed vectors, as
/// `mul_add_m_upper_triangular_mat_x_mat_trans` with `triangular` 1.
pub(crate) fn addUpperTriangularTimesTransposed(
    upper: &[u64],
    matrix: &[u8],
    accumulator: &mut [u64],
    size: usize,
    matrixRows: usize,
    limbCount: usize,
) {
    let mut used = 0;
    for row in 0..size {
        for column in row..size {
            let vector = entry(upper, used, limbCount);
            for index in 0..matrixRows {
                multiplyAdd(
                    vector,
                    matrix[index * size + column],
                    mutableEntry(accumulator, row * matrixRows + index, limbCount),
                );
            }
            used += 1;
        }
    }
}

/// Adds the product of the transpose of a matrix of elements with a matrix of packed vectors
/// to a matrix of packed vectors, as `mul_add_mat_trans_x_m_mat`.
pub(crate) fn addTransposedTimesMatrix(
    matrix: &[u8],
    vectors: &[u64],
    accumulator: &mut [u64],
    matrixRows: usize,
    matrixColumns: usize,
    vectorColumns: usize,
    limbCount: usize,
) {
    for row in 0..matrixColumns {
        for column in 0..matrixRows {
            let scalar = matrix[column * matrixColumns + row];
            for index in 0..vectorColumns {
                multiplyAdd(
                    entry(vectors, column * vectorColumns + index, limbCount),
                    scalar,
                    mutableEntry(accumulator, row * vectorColumns + index, limbCount),
                );
            }
        }
    }
}

/// Adds the product of a matrix of elements with a matrix of packed vectors to a matrix of
/// packed vectors, as `mul_add_mat_x_m_mat`.
pub(crate) fn addMatrixTimesMatrix(
    matrix: &[u8],
    vectors: &[u64],
    accumulator: &mut [u64],
    matrixRows: usize,
    matrixColumns: usize,
    vectorColumns: usize,
    limbCount: usize,
) {
    for row in 0..matrixRows {
        for column in 0..matrixColumns {
            let scalar = matrix[row * matrixColumns + column];
            for index in 0..vectorColumns {
                multiplyAdd(
                    entry(vectors, column * vectorColumns + index, limbCount),
                    scalar,
                    mutableEntry(accumulator, row * vectorColumns + index, limbCount),
                );
            }
        }
    }
}

/// Adds `(P1 + P1^T) O` to a matrix of packed vectors, as `P1P1t_times_O`: the diagonal of P1
/// cancels in the sum, and each other entry meets O twice.
pub(crate) fn addSymmetrizedTimesMatrix(
    upper: &[u64],
    matrix: &[u8],
    accumulator: &mut [u64],
    size: usize,
    matrixColumns: usize,
    limbCount: usize,
) {
    let mut used = 0;
    for row in 0..size {
        for column in row..size {
            if column != row {
                let vector = entry(upper, used, limbCount);
                for index in 0..matrixColumns {
                    multiplyAdd(
                        vector,
                        matrix[column * matrixColumns + index],
                        mutableEntry(accumulator, row * matrixColumns + index, limbCount),
                    );
                    multiplyAdd(
                        vector,
                        matrix[row * matrixColumns + index],
                        mutableEntry(accumulator, column * matrixColumns + index, limbCount),
                    );
                }
            }
            used += 1;
        }
    }
}

/// The upper triangle of a square matrix of packed vectors of a size, with the entry below the
/// diagonal added to each entry above it, in row order, as `m_upper`.
pub(crate) fn upperTriangle(square: &[u64], size: usize, limbCount: usize) -> Vec<u64> {
    let mut upper = Vec::with_capacity(size * (size + 1) / 2 * limbCount);
    for row in 0..size {
        for column in row..size {
            let start = upper.len();
            upper.extend_from_slice(entry(square, row * size + column, limbCount));
            if row != column {
                add(
                    entry(square, column * size + row, limbCount),
                    &mut upper[start..],
                );
            }
        }
    }
    upper
}

/// `P3 = O^T (P1 O + P2)`, as `compute_P3`. P2 becomes `P1 O + P2` in the process.
pub(crate) fn oilProducts(
    parameters: &Parameters,
    p1: &[u64],
    p2: &mut [u64],
    oil: &[u8],
) -> Vec<u64> {
    let (vinegarCount, oilCount) = (parameters.vinegarCount(), parameters.oilCount);
    let limbCount = parameters.limbCount();
    addUpperTriangularTimesMatrix(p1, oil, p2, vinegarCount, oilCount, limbCount);
    let mut p3 = vec![0u64; oilCount * oilCount * limbCount];
    addTransposedTimesMatrix(
        oil,
        p2,
        &mut p3,
        vinegarCount,
        oilCount,
        oilCount,
        limbCount,
    );
    p3
}

/// The products `V L` and `V P1 V^T` of the k vinegar vectors of a signature attempt, as
/// `compute_M_and_VPV`. Row i of `V L` is the matrix M_i of the MAYO specification.
pub(crate) fn vinegarProducts(
    parameters: &Parameters,
    vinegar: &[u8],
    l: &[u64],
    p1: &[u64],
) -> (Vec<u64>, Vec<u64>) {
    let (vinegarCount, oilCount) = (parameters.vinegarCount(), parameters.oilCount);
    let (vectorCount, limbCount) = (parameters.vectorCount, parameters.limbCount());
    let mut vinegarL = vec![0u64; vectorCount * oilCount * limbCount];
    addMatrixTimesMatrix(
        vinegar,
        l,
        &mut vinegarL,
        vectorCount,
        vinegarCount,
        oilCount,
        limbCount,
    );
    let mut p1Vinegar = vec![0u64; vinegarCount * vectorCount * limbCount];
    addUpperTriangularTimesTransposed(
        p1,
        vinegar,
        &mut p1Vinegar,
        vinegarCount,
        vectorCount,
        limbCount,
    );
    let mut vinegarP1Vinegar = vec![0u64; vectorCount * vectorCount * limbCount];
    addMatrixTimesMatrix(
        vinegar,
        &p1Vinegar,
        &mut vinegarP1Vinegar,
        vectorCount,
        vinegarCount,
        vectorCount,
        limbCount,
    );
    (vinegarL, vinegarP1Vinegar)
}

/// The k by k matrix `S P S^T` of the public map P = [[P1, P2], [0, P3]] and the k vectors of
/// a signature, as `mayo_generic_m_calculate_PS_SPS`: for each vector, the entries of P sorted
/// into 16 bins by the element of s that multiplies them, then one multiplication of each bin.
///
/// The C code of MAYO-2 computes `P S^T` for all vectors first, in
/// `mayo_generic_m_calculate_PS`. Both give the same products, because the arithmetic is exact.
pub(crate) fn quadraticForms(
    parameters: &Parameters,
    p1: &[u64],
    p2: &[u64],
    p3: &[u64],
    signature: &[u8],
) -> Vec<u64> {
    let (vinegarCount, oilCount) = (parameters.vinegarCount(), parameters.oilCount);
    let (vectorCount, limbCount) = (parameters.vectorCount, parameters.limbCount());
    let variableCount = parameters.variableCount;
    let binLength = 16 * limbCount;
    let mut forms = vec![0u64; vectorCount * vectorCount * limbCount];
    // The products `P s_j^T` of one vector j, at the places j to j + n - 1.
    let mut mapProducts = vec![0u64; (variableCount + vectorCount) * limbCount];
    let mut accumulator = vec![0u64; binLength * variableCount];
    for column in 0..vectorCount {
        accumulator.fill(0);
        let vector = &signature[column * variableCount..(column + 1) * variableCount];
        let bin = |row: usize, scalar: u8| (row * 16 + usize::from(scalar)) * limbCount;
        let mut p1Used = 0;
        for row in 0..vinegarCount {
            for scalar in &vector[row..vinegarCount] {
                let start = bin(row, *scalar);
                add(
                    entry(p1, p1Used, limbCount),
                    &mut accumulator[start..start + limbCount],
                );
                p1Used += 1;
            }
            for place in 0..oilCount {
                let start = bin(row, vector[vinegarCount + place]);
                add(
                    entry(p2, row * oilCount + place, limbCount),
                    &mut accumulator[start..start + limbCount],
                );
            }
        }
        let mut p3Used = 0;
        for row in vinegarCount..variableCount {
            for scalar in &vector[row..variableCount] {
                let start = bin(row, *scalar);
                add(
                    entry(p3, p3Used, limbCount),
                    &mut accumulator[start..start + limbCount],
                );
                p3Used += 1;
            }
        }
        for row in 0..variableCount {
            multiplyBins(
                &mut accumulator[row * binLength..(row + 1) * binLength],
                limbCount,
                mutableEntry(&mut mapProducts, row + column, limbCount),
            );
        }
        for row in 0..vectorCount {
            accumulator[..binLength].fill(0);
            for place in 0..variableCount {
                let start = usize::from(signature[row * variableCount + place]) * limbCount;
                add(
                    entry(&mapProducts, place + column, limbCount),
                    &mut accumulator[start..start + limbCount],
                );
            }
            multiplyBins(
                &mut accumulator[..binLength],
                limbCount,
                mutableEntry(&mut forms, row * vectorCount + column, limbCount),
            );
        }
    }
    forms
}

#[cfg(test)]
mod tests {
    use super::{oilProducts, upperTriangle, vinegarProducts};
    use crate::parameters::{Parameters, mayo1, mayo2, mayo3, mayo5};
    use crate::testInputs::{digest, inputNibbles, inputWords, seed};

    /// The digests that the C functions of the MAYO team give for the inputs 7 to 12 of each set:
    /// `V L` and `V P1 V^T` of `compute_M_and_VPV`, `P1 O + P2` and P3 of `compute_P3`, and the
    /// upper triangle of P3 of `m_upper`, each built for its set.
    const knownAnswers: [(&Parameters, [&str; 5]); 4] = [
        (
            &mayo1,
            [
                "243bf41ecf7be53394ae491ee95fcc96b45b2d68665fad9d61290d7aaa044f70",
                "e13d9d0f6e887a263e4dd7e8d3727b2538b8a74649687ab877717f6b267cac4d",
                "863bfae03fb3901b320d38c9f58bf71d17b8cd192bbcf0e1b94df99b281d1874",
                "23095c7c61761c1bc89c2e70b05e4cd5fd2ef1049d5e1ec4c80071fdbb2ac199",
                "c8d88b6927a421c0da3d7326fd02ec60b7954f5056df2647c09a03da156984c2",
            ],
        ),
        (
            &mayo2,
            [
                "4a973d720955643ef36db287653687c2e0e5a1cddd53b22a945771156d353413",
                "41edd70643dfa735f7c1d18758bd67db6cf8162b742f0669be0e5fc7dbbfd772",
                "cae5eb49a201bb860afd4c91a330b928bdf9529a9606fd07c9bd6f7782ff39b5",
                "8aa685ad4383d89fdbf019b31efb0348587e80a5ddaca2ee455d1b3f6f5ca372",
                "48e059fa06f9293633ec122f6224655fe3e6eea093866b68f0c0b4d52f65f1b5",
            ],
        ),
        (
            &mayo3,
            [
                "eaf89691c699ff7938d5a8654f4128ac970c9aa1983acf3879b3bdb023e99866",
                "eec036fcd0f04dff29ee0704eeb170f4f29664a68c1ffddabfc0fa0e1927e94d",
                "d2ad8c05581d7ea302001d0c8faac7688d42e71388d128d363823a38320db269",
                "75f70b9ece0d277e802b5f6a00daa15a0034f9501a0360dfce5ba8025d80eec3",
                "4ea965e7b346f446307fe4242b284b25a93d41d40acd187d97a7360e1bc2017a",
            ],
        ),
        (
            &mayo5,
            [
                "89fded8e9528061d685502f0162a43f9f670f7333fd3e3c120594b84120d762e",
                "db52f39c15f624ddd1fd2bef8223acca4825e8157e2babc657cfd9bdd5d19cf7",
                "4f0a417d07f30cc5f7fb7fabb0acaf4b7a59453687826af2f3f92f2c40d8e8c7",
                "9e5993c344b9cd62b1edbaf78df88cc72a8bfa2c9f76cf79d915e448e74cddee",
                "597fc4af81f760de8d1765d33356992700f002aea9be1430985483b606c5a648",
            ],
        ),
    ];

    #[test]
    fn productsGiveTheAnswersOfTheCFunctions() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let limbCount = parameters.limbCount();
            let (vinegarCount, oilCount) = (parameters.vinegarCount(), parameters.oilCount);
            let vectorCount = parameters.vectorCount;
            let seeds: Vec<u32> = (7..=12).map(|input| seed(parameters, input)).collect();
            let l = inputWords(seeds[0], vinegarCount * oilCount * limbCount);
            let p1 = inputWords(seeds[1], parameters.p1Count() * limbCount);
            let vinegar = inputNibbles(seeds[2], vectorCount * vinegarCount);
            let (vinegarL, vinegarP1Vinegar) = vinegarProducts(parameters, &vinegar, &l, &p1);
            assert_eq!(digest(&vinegarL), answers[0], "{name}, V L, {seeds:?}");
            assert_eq!(
                digest(&vinegarP1Vinegar),
                answers[1],
                "{name}, V P1 V^T, {seeds:?}"
            );

            let p1 = inputWords(seeds[3], parameters.p1Count() * limbCount);
            let mut p2 = inputWords(seeds[4], parameters.p2Count() * limbCount);
            let oil = inputNibbles(seeds[5], vinegarCount * oilCount);
            let p3 = oilProducts(parameters, &p1, &mut p2, &oil);
            assert_eq!(digest(&p2), answers[2], "{name}, P1 O + P2, {seeds:?}");
            assert_eq!(digest(&p3), answers[3], "{name}, P3, {seeds:?}");
            assert_eq!(
                digest(&upperTriangle(&p3, oilCount, limbCount)),
                answers[4],
                "{name}, upper P3, {seeds:?}"
            );
        }
    }
}
