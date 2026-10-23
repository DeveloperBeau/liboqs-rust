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
    use crate::testInputs::{digest, inputNibbles, inputWords};

    /// The digests that the C functions of the MAYO team give for the inputs of the labels:
    /// `V L` and `V P1 V^T` of `compute_M_and_VPV`, `P1 O + P2` and P3 of `compute_P3`, and the
    /// upper triangle of P3 of `m_upper`, each built for its set.
    const knownAnswers: [(&Parameters, [&str; 5]); 4] = [
        (
            &mayo1,
            [
                "c73be40e38c937632f8a1d568393c518c47adaac9b868714225e35215ebea8e8",
                "9355acbef1b5bf559ed0ac5c05a2931e5998d04a51d8135ba76543591dc5d673",
                "b6ea5adcc9deae1c7fc1d7517f0287b8634071c84d8ca2a972af573c587c2160",
                "686bfe465976bfcc5c5e4707ae359be84c384fba1f85b785f2a5e1fcc2264353",
                "fd11f040917b7191714e3e613b262b5168124b1296aa475cb4495bc3817d1454",
            ],
        ),
        (
            &mayo2,
            [
                "d5af1e275addfc149bf3a5f19ea5c10057de9e3f1b509bb478cb5c4563ef4109",
                "cea98206830c5ecee13f6097cbab087b07245d4c2f70118aed96fbdd066b062c",
                "05d1fc65afd9585002fd87988e31b5f9f8180961e3bd09e27ecbbb6d3cba5342",
                "e583561b1ed89c57c9940c2b54bc099afb3fdee24e874116189ed9149222c58d",
                "0accebbf845c1646533e0cc9af72704f7ea3996e4730351ed8199b8a2eed0e7a",
            ],
        ),
        (
            &mayo3,
            [
                "7df91d5b19f9b973316d11ce182d7ca0888a0990aae00d69633ff0d1f9c16b28",
                "ccc9db65c450c33f5dbb82345914f7f74a36118ebc9eaf72426a422478f8c8a3",
                "59b7efd66dc7bd38b66620450bf9616cbf952002561cf4f62edd9e24d27f9466",
                "52ffeafe3f29351ba8a1cad31a52289a6a03473b38b39b67267db96d2ba8320e",
                "9a77ec7861030daf430c88f0c6ad0eff7f430c55b4044352d947edc7b08c7ef7",
            ],
        ),
        (
            &mayo5,
            [
                "398b45272dd9531626c898522c7717ac755df476567be1dc09c8ebf6e1423d9a",
                "691307afbecb868b677c0d006ba34aeb44fdc66b410bdecfa43b8a6beb016dc8",
                "7c99ccc72fb81717691db1efcde54d54d2c0025cd7b59465d9c08eba505b361f",
                "41ed100b43af342f5bc44d530400ecccdc517739c05dc82ea0e48b52d5fc429f",
                "e8d4efa8320d4b73f7ce07f6f328d81a09fa2e19e35bb3ffa886b7b706ec1051",
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
            let l = inputWords(
                name,
                "vinegarProducts l",
                vinegarCount * oilCount * limbCount,
            );
            let p1 = inputWords(name, "vinegarProducts p1", parameters.p1Count() * limbCount);
            let vinegar = inputNibbles(name, "vinegarProducts v", vectorCount * vinegarCount);
            let (vinegarL, vinegarP1Vinegar) = vinegarProducts(parameters, &vinegar, &l, &p1);
            assert_eq!(digest(&vinegarL), answers[0], "{name}, V L");
            assert_eq!(digest(&vinegarP1Vinegar), answers[1], "{name}, V P1 V^T");

            let p1 = inputWords(name, "oilProducts p1", parameters.p1Count() * limbCount);
            let mut p2 = inputWords(name, "oilProducts p2", parameters.p2Count() * limbCount);
            let oil = inputNibbles(name, "oilProducts o", vinegarCount * oilCount);
            let p3 = oilProducts(parameters, &p1, &mut p2, &oil);
            assert_eq!(digest(&p2), answers[2], "{name}, P1 O + P2");
            assert_eq!(digest(&p3), answers[3], "{name}, P3");
            assert_eq!(
                digest(&upperTriangle(&p3, oilCount, limbCount)),
                answers[4],
                "{name}, upper P3"
            );
        }
    }
}
