use crate::parameters::triangleSize;
use crate::{FieldArithmetic, GeneratorPowers, OilMatrix, PaddedEntries};
use alloc::vec;
use alloc::vec::Vec;

/// The products of the batched matrices of `parallel_matrix_op.c` and `blas_matrix_ref.c`.
///
/// A batched matrix has a vector for each entry, with one element for each equation of the
/// public map. It stores the entries row after row. An upper triangular matrix stores the
/// entries of each row from the diagonal on, as `idx_of_trimat` indexes them. The functions
/// compute the same sums as the C functions, in another order where that is faster. The field
/// arithmetic is exact, so the order does not change a byte.
pub(crate) struct BatchedMatrix;

impl BatchedMatrix {
    /// The index of the entry (row, column) of an upper triangular matrix of a dimension, for
    /// a column at or after the row, as `idx_of_trimat` computes it.
    fn triangleIndex(row: usize, column: usize, dimension: usize) -> usize {
        (2 * dimension - row + 1) * row / 2 + column - row
    }

    /// Adds T O to a matrix C of v rows and o columns, for an upper triangular T of v rows:
    /// `C(i, j) += sum over k >= i of T(i, k) O(k, j)`, as `batch_trimat_madd` does.
    pub(crate) fn addTriangleProduct<F: FieldArithmetic>(
        target: &mut [u8],
        triangle: &[u8],
        oil: &OilMatrix<'_, F>,
        entryLength: usize,
    ) {
        let (height, width) = (oil.rowCount, oil.columnCount);
        let rowLength = width * entryLength;
        Self::checkShapes(target, triangle, oil, entryLength);
        let mut entries = triangle.chunks_exact(entryLength);
        for row in 0..height {
            let targetRow = &mut target[row * rowLength..][..rowLength];
            let mut sums = PaddedEntries::new(targetRow, entryLength);
            for (column, entry) in (row..height).zip(&mut entries) {
                let powers = GeneratorPowers::<F>::new(entry);
                for index in 0..width {
                    powers.addProduct(sums.entryMut(index), oil.element(column, index));
                }
            }
            sums.writeBytes(targetRow);
        }
    }

    /// Adds T^T O to a matrix C of v rows and o columns, for an upper triangular T of v rows:
    /// `C(i, j) += sum over k <= i of T(k, i) O(k, j)`, as `batch_trimatTr_madd` does.
    pub(crate) fn addTransposedTriangleProduct<F: FieldArithmetic>(
        target: &mut [u8],
        triangle: &[u8],
        oil: &OilMatrix<'_, F>,
        entryLength: usize,
    ) {
        let (height, width) = (oil.rowCount, oil.columnCount);
        let rowLength = width * entryLength;
        Self::checkShapes(target, triangle, oil, entryLength);
        for row in 0..height {
            let targetRow = &mut target[row * rowLength..][..rowLength];
            let mut sums = PaddedEntries::new(targetRow, entryLength);
            for other in 0..=row {
                let index = Self::triangleIndex(other, row, height);
                let powers =
                    GeneratorPowers::<F>::new(&triangle[index * entryLength..][..entryLength]);
                for column in 0..width {
                    powers.addProduct(sums.entryMut(column), oil.element(other, column));
                }
            }
            sums.writeBytes(targetRow);
        }
    }

    /// Adds (T + T^T) O to a matrix C of v rows and o columns, for an upper triangular T of v
    /// rows, as `batch_2trimat_madd` does: `C(i, j) += sum over k != i of T(k, i) O(k, j)`, where
    /// T(k, i) is the entry of the triangle at the lower and the higher of k and i. The diagonal
    /// of T + T^T is zero in a field of characteristic 2, and the C code leaves it out.
    pub(crate) fn addSymmetricProduct<F: FieldArithmetic>(
        target: &mut [u8],
        triangle: &[u8],
        oil: &OilMatrix<'_, F>,
        entryLength: usize,
    ) {
        let (height, width) = (oil.rowCount, oil.columnCount);
        let rowLength = width * entryLength;
        Self::checkShapes(target, triangle, oil, entryLength);
        for row in 0..height {
            let targetRow = &mut target[row * rowLength..][..rowLength];
            let mut sums = PaddedEntries::new(targetRow, entryLength);
            for other in (0..height).filter(|other| *other != row) {
                let index = Self::triangleIndex(other.min(row), other.max(row), height);
                let powers =
                    GeneratorPowers::<F>::new(&triangle[index * entryLength..][..entryLength]);
                for column in 0..width {
                    powers.addProduct(sums.entryMut(column), oil.element(other, column));
                }
            }
            sums.writeBytes(targetRow);
        }
    }

    /// The upper triangular matrix of o rows that folds M = O^T R, for a matrix R of v rows and
    /// o columns, as `batch_upper_matTr_x_mat` makes it: the entry (i, j) for i < j is
    /// `M(i, j) + M(j, i)`, and the entry (i, i) is `M(i, i)`.
    pub(crate) fn foldedTransposedProduct<F: FieldArithmetic>(
        oil: &OilMatrix<'_, F>,
        rectangle: &[u8],
        entryLength: usize,
    ) -> Vec<u8> {
        let (height, width) = (oil.rowCount, oil.columnCount);
        assert_eq!(
            rectangle.len(),
            height * width * entryLength,
            "the rectangle has v rows and o columns"
        );
        let mut product = PaddedEntries::zeroed(width * width, entryLength);
        for (index, entry) in rectangle.chunks_exact(entryLength).enumerate() {
            let (row, column) = (index / width, index % width);
            let powers = GeneratorPowers::<F>::new(entry);
            for productRow in 0..width {
                let productEntry = product.entryMut(productRow * width + column);
                powers.addProduct(productEntry, oil.element(row, productRow));
            }
        }
        let mut folded = vec![0u8; triangleSize(width) * entryLength];
        let mut entries = folded.chunks_exact_mut(entryLength);
        let mut sum = PaddedEntries::zeroed(1, entryLength);
        for row in 0..width {
            for (column, entry) in (row..width).zip(&mut entries) {
                let words = sum.entryMut(0);
                words.copy_from_slice(product.entry(row * width + column));
                if column > row {
                    for (word, mirror) in words.iter_mut().zip(product.entry(column * width + row))
                    {
                        *word ^= mirror;
                    }
                }
                sum.writeBytes(entry);
            }
        }
        folded
    }

    /// The quadratic form `sum over i <= k of x_i x_k T(i, k)` of an upper triangular T of a
    /// dimension at a point x, as `batch_quad_trimat_eval` computes it.
    pub(crate) fn quadraticForm<F: FieldArithmetic>(
        triangle: &[u8],
        point: &[u8],
        dimension: usize,
        entryLength: usize,
    ) -> Vec<u8> {
        assert_eq!(
            triangle.len(),
            entryLength * triangleSize(dimension),
            "the triangle has an entry for each pair of variables"
        );
        let mut result = vec![0u8; entryLength];
        let mut rowSum = vec![0u8; entryLength];
        let mut entries = triangle.chunks_exact(entryLength);
        for row in 0..dimension {
            rowSum.fill(0);
            for (column, entry) in (row..dimension).zip(&mut entries) {
                F::multiplyAdd(&mut rowSum, entry, F::element(point, column));
            }
            F::multiplyAdd(&mut result, &rowSum, F::element(point, row));
        }
        result
    }

    /// Checks that a target of v rows and o columns and a triangle of v rows fit the oil
    /// matrix, which a wrong length in the caller would break.
    fn checkShapes<F: FieldArithmetic>(
        target: &[u8],
        triangle: &[u8],
        oil: &OilMatrix<'_, F>,
        entryLength: usize,
    ) {
        assert_eq!(
            target.len(),
            oil.rowCount * oil.columnCount * entryLength,
            "the target has v rows and o columns"
        );
        assert_eq!(
            triangle.len(),
            entryLength * triangleSize(oil.rowCount),
            "the triangle has v rows"
        );
    }

    /// The sum of the columns of a matrix, each times its coefficient, as `gf16mat_prod` and
    /// `gf256mat_prod` compute it: `sum over i < count of b_i A_i`.
    pub(crate) fn linearCombination<F: FieldArithmetic>(
        columns: &[u8],
        columnLength: usize,
        coefficients: &[u8],
        count: usize,
    ) -> Vec<u8> {
        let mut result = vec![0u8; columnLength];
        for (index, column) in columns.chunks_exact(columnLength).take(count).enumerate() {
            F::multiplyAdd(&mut result, column, F::element(coefficients, index));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::BatchedMatrix;
    use crate::gf16::GF16;
    use crate::gf256::GF256;
    use crate::parameters::triangleSize;
    use crate::testInputs::{digest, sequence};
    use crate::{FieldArithmetic, OilMatrix};

    /// The digests of the C functions for one shape of the sets, from liboqs 0.16.0.
    struct Answers {
        triangle: &'static str,
        transposed: &'static str,
        symmetric: &'static str,
        folded: &'static str,
        quadratic: &'static str,
        longCombination: &'static str,
        shortCombination: &'static str,
    }

    /// Runs each function on the inputs of the C program for a shape of v vinegar and o oil
    /// variables, and compares the digests.
    fn checkShape<F: FieldArithmetic>(vinegarCount: usize, oilCount: usize, answers: &Answers) {
        let vinegarLength = F::byteLength(vinegarCount);
        let entryLength = F::byteLength(oilCount);
        let triangleLength = entryLength * triangleSize(vinegarCount);
        let rectangleLength = entryLength * vinegarCount * oilCount;
        let oilLength = vinegarLength * oilCount;
        let label = format!("v = {vinegarCount}, o = {oilCount}");

        // `batch_trimat_madd` with the sequences 1, 2 and 3.
        let mut target = sequence(rectangleLength, 1);
        let oilBytes = sequence(oilLength, 3);
        let oil = OilMatrix::<F>::new(&oilBytes, vinegarCount, oilCount);
        BatchedMatrix::addTriangleProduct(
            &mut target,
            &sequence(triangleLength, 2),
            &oil,
            entryLength,
        );
        assert_eq!(digest(&target), answers.triangle, "{label}");

        // `batch_trimatTr_madd` with the sequences 4, 5 and 6.
        let mut target = sequence(rectangleLength, 4);
        let oilBytes = sequence(oilLength, 6);
        let oil = OilMatrix::<F>::new(&oilBytes, vinegarCount, oilCount);
        BatchedMatrix::addTransposedTriangleProduct(
            &mut target,
            &sequence(triangleLength, 5),
            &oil,
            entryLength,
        );
        assert_eq!(digest(&target), answers.transposed, "{label}");

        // `batch_2trimat_madd` with the sequences 7, 8 and 9.
        let mut target = sequence(rectangleLength, 7);
        let oilBytes = sequence(oilLength, 9);
        let oil = OilMatrix::<F>::new(&oilBytes, vinegarCount, oilCount);
        BatchedMatrix::addSymmetricProduct(
            &mut target,
            &sequence(triangleLength, 8),
            &oil,
            entryLength,
        );
        assert_eq!(digest(&target), answers.symmetric, "{label}");

        // `batch_upper_matTr_x_mat` with the oil matrix 11 and the rectangle 12. The C program
        // filled its output with the sequence 10 first, and the function writes every entry.
        let oilBytes = sequence(oilLength, 11);
        let oil = OilMatrix::<F>::new(&oilBytes, vinegarCount, oilCount);
        let folded = BatchedMatrix::foldedTransposedProduct(
            &oil,
            &sequence(rectangleLength, 12),
            entryLength,
        );
        assert_eq!(folded.len(), entryLength * triangleSize(oilCount));
        assert_eq!(digest(&folded), answers.folded, "{label}");

        // `batch_quad_trimat_eval` with the triangle 13 at the point 14.
        let value = BatchedMatrix::quadraticForm::<F>(
            &sequence(triangleLength, 13),
            &sequence(vinegarLength, 14),
            vinegarCount,
            entryLength,
        );
        assert_eq!(digest(&value), answers.quadratic, "{label}");

        // `gf*mat_prod` of v columns of o entries with the sequences 15 and 16, and of o columns
        // of v elements with the sequences 17 and 18.
        let long = BatchedMatrix::linearCombination::<F>(
            &sequence(rectangleLength, 15),
            oilCount * entryLength,
            &sequence(vinegarLength, 16),
            vinegarCount,
        );
        assert_eq!(digest(&long), answers.longCombination, "{label}");
        let short = BatchedMatrix::linearCombination::<F>(
            &sequence(oilLength, 17),
            vinegarLength,
            &sequence(entryLength, 18),
            oilCount,
        );
        assert_eq!(digest(&short), answers.shortCombination, "{label}");
    }

    #[test]
    fn productsOfTheShapeOfOVIsGiveTheBytesOfTheCCode() {
        checkShape::<GF16>(
            96,
            64,
            &Answers {
                triangle: "844233ac90771c4c23ba8a9d391f9cecce832f15ae2fae60cb4dea561556101f",
                transposed: "5af516c7f3660890b68316075e3127da4f289e36a7fa134c85159a5613a04023",
                symmetric: "d70cde16da7974e9a5c9bbb864891e01352312d108908935409114adb3120bb4",
                folded: "9b3e5ad1b513ccedfbb594167947f79faa639695fcba8f4b28b9482e8790ba3e",
                quadratic: "736118e01549e2fe84038f46cfa4c4315684732a49ef4512e84d34898db95827",
                longCombination: "69f32d9bb79f938bbe43ddf3c0d74e99b2ae65e1945b5d7bf0c87afb81a25c28",
                shortCombination: "bb407c7c908a40e6016baf92f33e1b6b607e7c4dec3d677579e53c0da0bad6aa",
            },
        );
    }

    #[test]
    fn productsOfTheShapeOfOVIpGiveTheBytesOfTheCCode() {
        checkShape::<GF256>(
            68,
            44,
            &Answers {
                triangle: "c0494fdd83cdd5896863c07c1dde89d65719cb128e9fa53d8487d186c35b2798",
                transposed: "5deb38eff5e6d984123b0ae9b75c0fec9134bf5ae93714a603c005408fa0227b",
                symmetric: "c718f5075bf274d45c093911a392aa3370cb739d57f5f7caf24a72aea6b67a8b",
                folded: "67525d62fb0d2cb47013f69338bb56b3e8e36e61929a44008863783cc228fe58",
                quadratic: "4d02e8492604b9db3a60790a661a09a1d3fddd08f769ed7474bb6dd7b5791799",
                longCombination: "05f81f2627b461aa57e347ba443c44b80b4ded05179e8fd6b6fa2677183fd9a5",
                shortCombination: "6611f02e9b1d9ed8bb6543e321fe3674818710947c496a23233765686b545540",
            },
        );
    }

    #[test]
    fn productsOfTheShapeOfOVIIIGiveTheBytesOfTheCCode() {
        checkShape::<GF256>(
            112,
            72,
            &Answers {
                triangle: "340fb3ac39ec6c64b82657860f07cca0f3b728aea27013a42bfbda290d63eafc",
                transposed: "8905aaef05f6bfeceb8d6752028864da1b3b3e67862a9edf74b937cebf374db7",
                symmetric: "a71dd34fb9152ba7c73abf79b4e9f4a7287f257d91155eaed35c67a81842d224",
                folded: "173be76bdadd8a527ec39ac5a05d48ed3d776bc86a0b7f43ab3d03ce9810049b",
                quadratic: "4d1ba9555c15bc21305bbf458e2a39bc3c65237787d7edb864309342093b9c12",
                longCombination: "9c2b03ca152cc86e1242c1c3f52ab0106748df2ca3a450d699022a65a9f55b13",
                shortCombination: "aeab11fba20565e2c1828c2b8cc7649c148c9714a0c370361f9b99c9ffe0a0ac",
            },
        );
    }

    #[test]
    fn productsOfTheShapeOfOVVGiveTheBytesOfTheCCode() {
        checkShape::<GF256>(
            148,
            96,
            &Answers {
                triangle: "6e9fd75ec9ae68c7c57acac981fc14cc79750d32687094e5c44e635c24487e97",
                transposed: "c26bf20faaba5ba6990295107f33f5ba11b714ab14a1984fd9f351e669b2715f",
                symmetric: "fc2ceaa6d6c07509298fc18d7c45d30a9d4e94974a2d8f9dc9212f8bcaf6a9d8",
                folded: "d40fbef4094ed562a74590a42168a03f1b849e2f142a86da82173ba5cf4d3e0f",
                quadratic: "13328bcef5c02499ea1e8496b682dae9a1ed1332016ac754bde800560d5ee2e8",
                longCombination: "17f8833bcbc123498ec6b65cc49922ec9844889f6507db29f5964b6aa0e8000b",
                shortCombination: "cb164a1323c2fceb079557dc9bd0bc21bb3935a764e0a220a0e86111861019dc",
            },
        );
    }
}
