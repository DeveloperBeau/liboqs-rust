//! The solution of the linear system of a signature attempt, as `EF` of `echelon_form.h` and
//! `sample_solution` of `arithmetic.c` compute it. Both keep the constant-time form of the C
//! code: the row of each pivot is secret, so the steps choose rows with masks, not branches.
//!
//! The two procedures have the limits of the C code, and the port keeps them. The pivot of a
//! column is searched in at most 33 rows. The back substitution looks for the first entry of
//! a row in at most `32 / (m - row)` columns after the diagonal. A matrix that needs more gives
//! the solution of the C code, which is then not a solution of the system.

use crate::field;
use crate::packedVectors::{element, multiplyAdd};
use alloc::vec;
use alloc::vec::Vec;

/// All ones when two values differ and zero when they are equal, as `ct_compare_64`.
fn differenceMask(left: usize, right: usize) -> u64 {
    ((((left ^ right) as i64).wrapping_neg()) >> 63) as u64
}

/// All ones when the first value is greater than the second and zero otherwise, as
/// `ct_64_is_greater_than`.
fn greaterMask(left: usize, right: usize) -> u64 {
    ((right as i64 - left as i64) >> 63) as u64
}

/// The packed row of the elements of a matrix row, two to a byte, as `ef_pack_m_vec`.
fn packedRow(elements: &[u8], words: &mut [u64]) {
    for (wordIndex, word) in words.iter_mut().enumerate() {
        *word = elements
            .iter()
            .skip(16 * wordIndex)
            .take(16)
            .enumerate()
            // The elements fill disjoint nibbles, so `+` joins them.
            .fold(0, |sum, (place, value)| {
                sum + (u64::from(*value) << (4 * place))
            });
    }
}

/// Puts a matrix of elements, in row order, into row echelon form with ones at the pivots, as
/// `EF`. The rows are packed 16 elements to a word for the work.
pub(crate) fn echelonForm(matrix: &mut [u8], rowCount: usize, columnCount: usize) {
    let rowLength = columnCount.div_ceil(16);
    let mut packed = vec![0u64; rowLength * rowCount];
    for (elements, words) in matrix
        .chunks_exact(columnCount)
        .zip(packed.chunks_exact_mut(rowLength))
    {
        packedRow(elements, words);
    }
    let mut pivotRow = vec![0u64; rowLength];
    let mut scaledPivotRow = vec![0u64; rowLength];
    let mut pivotRowIndex = 0;
    for pivotColumn in 0..columnCount {
        let lowerBound = (pivotColumn + rowCount).saturating_sub(columnCount);
        let upperBound = (rowCount - 1).min(pivotColumn);
        pivotRow.fill(0);
        scaledPivotRow.fill(0);
        // The pivot row is the row of the index plus each row below it while the pivot is zero.
        let mut pivot = 0;
        let mut pivotIsZero = u64::MAX;
        for row in lowerBound..=(rowCount - 1).min(upperBound + 32) {
            let isPivotRow = !differenceMask(row, pivotRowIndex);
            let isBelowPivotRow = greaterMask(row, pivotRowIndex);
            // A row is never the pivot row and below it at once, so `+` joins the two masks.
            let mask = isPivotRow + (isBelowPivotRow & pivotIsZero);
            for (word, rowWord) in pivotRow
                .iter_mut()
                .zip(&packed[row * rowLength..(row + 1) * rowLength])
            {
                *word ^= mask & rowWord;
            }
            pivot = element(&pivotRow, pivotColumn);
            pivotIsZero = !differenceMask(usize::from(pivot), 0);
        }
        multiplyAdd(&pivotRow, field::inverse(pivot), &mut scaledPivotRow);
        for row in lowerBound..=upperBound {
            let doesCopy = !differenceMask(row, pivotRowIndex) & !pivotIsZero;
            for (word, scaledWord) in packed[row * rowLength..(row + 1) * rowLength]
                .iter_mut()
                .zip(&scaledPivotRow)
            {
                *word = (!doesCopy & *word) + (doesCopy & scaledWord);
            }
        }
        for row in lowerBound..rowCount {
            let isBelowPivot = u8::from(row > pivotRowIndex);
            let words = &mut packed[row * rowLength..(row + 1) * rowLength];
            let toEliminate = element(words, pivotColumn);
            multiplyAdd(&scaledPivotRow, isBelowPivot * toEliminate, words);
        }
        pivotRowIndex += (!pivotIsZero & 1) as usize;
    }
    for (elements, words) in matrix
        .chunks_exact_mut(columnCount)
        .zip(packed.chunks_exact(rowLength))
    {
        for (index, value) in elements.iter_mut().enumerate() {
            *value = element(words, index);
        }
    }
}

/// All ones when an element is not zero and zero otherwise, as `ct_compare_8` with zero.
fn nonZeroMask(value: u8) -> u8 {
    (((i32::from(value)).wrapping_neg() >> 31) & 0xFF) as u8
}

/// A solution x of `A x = y` with the randomizer r, as `sample_solution`, or `None` when the
/// echelon form of A has a last row of zeros.
///
/// The matrix has m rows of `k o + 1` elements and then zero rows up to a multiple of 8, as
/// `systemMatrix` gives it. The randomizer has `k o + 1` elements. The product `A r` reads the
/// last one after the last column of A is cleared, so the result does not depend on it, as in
/// the C code. The signature sets it to zero. The solution has `k o + 1` elements. It starts as
/// the k o unknowns of the randomizer and a zero, because `x <- r` of the C code copies only the
/// unknowns. The back substitution can change the element after the unknowns, as in the C code,
/// and the signature uses only the first k o.
pub(crate) fn sampledSolution(
    matrix: &mut [u8],
    target: &[u8],
    randomizer: &[u8],
    unknownCount: usize,
    rowCount: usize,
) -> Option<Vec<u8>> {
    let columnCount = unknownCount + 1;
    let mut solution = vec![0u8; columnCount];
    solution[..unknownCount].copy_from_slice(&randomizer[..unknownCount]);
    for row in 0..rowCount {
        matrix[row * columnCount + unknownCount] = 0;
    }
    let mut product = vec![0u8; rowCount];
    field::matrixTimesVector(&matrix[..rowCount * columnCount], randomizer, &mut product);
    for (row, (value, productValue)) in target.iter().zip(&product).enumerate() {
        matrix[row * columnCount + unknownCount] = value ^ productValue;
    }
    echelonForm(&mut matrix[..rowCount * columnCount], rowCount, columnCount);
    let lastRow = &matrix[(rowCount - 1) * columnCount..rowCount * columnCount - 1];
    if lastRow.iter().fold(0, |sum, value| sum | value) == 0 {
        return None;
    }
    for row in (0..rowCount).rev() {
        let mut isFinished = 0u8;
        let upperBound = (row + 32 / (rowCount - row)).min(unknownCount);
        for column in row..=upperBound {
            let isCorrectColumn = nonZeroMask(matrix[row * columnCount + column]) & !isFinished;
            let value = isCorrectColumn & matrix[row * columnCount + unknownCount];
            solution[column] ^= value;
            // The rows above, eight at a time: the elements of the column, one to a byte.
            for first in (0..row).step_by(8) {
                let columnBytes = u64::from_le_bytes(core::array::from_fn(|offset| {
                    matrix[(first + offset) * columnCount + column]
                }));
                let products = field::productsInBytes(value, columnBytes);
                for offset in 0..8 {
                    matrix[(first + offset) * columnCount + unknownCount] ^=
                        ((products >> (8 * offset)) & 0x0F) as u8;
                }
            }
            isFinished |= isCorrectColumn;
        }
    }
    Some(solution)
}

#[cfg(test)]
mod tests {
    use super::{differenceMask, echelonForm, greaterMask, nonZeroMask, sampledSolution};
    use crate::parameters::{Parameters, mayo1, mayo2, mayo3, mayo5};
    use crate::testInputs::{digestOfBytes, inputNibbles, seed};

    /// The cases of the C program, numbered from 1: seeded matrices, and matrices with a zero
    /// column, five zero columns, a first column that is zero in the 40 first rows, a lower half
    /// that repeats the upper half, all zeros, three zero rows at the end, and a first column
    /// whose first entry that is not zero is at the last row of the pivot search, row 32, or just
    /// after it. The last case is a seeded matrix whose randomizer has the element 9 after the
    /// k o unknowns, where a signature has zero.
    const cases: [&str; 10] = [
        "random",
        "zeroColumn",
        "fiveZeroColumns",
        "latePivot",
        "lowRank",
        "zero",
        "lastRowsZero",
        "pivotAtSearchEnd",
        "pivotPastSearch",
        "randomizerTail",
    ];

    /// The seed of an input of a case: the input 1 is the matrix, 2 the target and 3 the
    /// randomizer.
    fn caseSeed(parameters: &Parameters, caseIndex: usize, input: u32) -> u32 {
        let caseNumber = u32::try_from(caseIndex + 1).expect("a small case number");
        seed(parameters, 100 * caseNumber + input)
    }

    /// The matrix of a case, with zero rows up to a multiple of 8.
    fn craftedMatrix(parameters: &Parameters, caseIndex: usize) -> Vec<u8> {
        let (rows, columns) = (parameters.equationCount, parameters.systemColumnCount());
        let case = cases[caseIndex];
        let mut matrix = inputNibbles(caseSeed(parameters, caseIndex, 1), rows * columns);
        matrix.resize(rows.div_ceil(8) * 8 * columns, 0);
        match case {
            "zeroColumn" => (0..rows).for_each(|row| matrix[row * columns + 2] = 0),
            "fiveZeroColumns" => {
                for row in 0..rows {
                    matrix[row * columns..row * columns + 5].fill(0);
                }
            }
            "latePivot" => (0..40).for_each(|row| matrix[row * columns] = 0),
            "lowRank" => {
                for row in rows / 2..rows {
                    matrix.copy_within(
                        (row - rows / 2) * columns..(row - rows / 2 + 1) * columns,
                        row * columns,
                    );
                }
            }
            "zero" => matrix.fill(0),
            "lastRowsZero" => matrix[(rows - 3) * columns..rows * columns].fill(0),
            "pivotAtSearchEnd" => {
                (0..32).for_each(|row| matrix[row * columns] = 0);
                matrix[32 * columns] = 1;
            }
            "pivotPastSearch" => {
                (0..33).for_each(|row| matrix[row * columns] = 0);
                matrix[33 * columns] = 1;
            }
            _ => {}
        }
        matrix
    }

    /// The answers of `EF` and `sample_solution` of the C code of the MAYO team for one case:
    /// the digest of the echelon form, whether a solution was found, and the digests of the
    /// solution and of the whole matrix after the solution.
    type CaseAnswer = (&'static str, bool, &'static str, &'static str);

    /// The answers of each case for each set.
    const knownAnswers: [(&Parameters, [CaseAnswer; 10]); 4] = [
        (
            &mayo1,
            [
                (
                    "7b6c85bac3d754c43497eb0dac83f3f241d24cab958f4332ab67e9718c2f4d69",
                    true,
                    "675f75c425544329de7e01c3ac18b2b97e99d9fd54c06cbed3bf85d064a8a8d0",
                    "d6961d730e71f6e5fb770e1f1db9d42b372e8c8a451a18f6b00aaa3eaf621161",
                ),
                (
                    "b2a28adf76447886250c50937a94172adacdace1ca4e8dba8bd5c97bfa041b2b",
                    true,
                    "3f93d450a35bd80a0e1b3e511cb1460993be38c2fb7bc516a01d6230228036f9",
                    "a926013ddf5becde8358ea31ab3c06d989dfbf0c366888be2b67253a2830d1e8",
                ),
                (
                    "843ec4c870a0ff38b121e198c5f7a41d63133cd78cce5bca975d96ff25b41cef",
                    false,
                    "e90baca5afb039667604b65f7c51017fa3053ffbd4cc9188e1c4a5edd1904d4e",
                    "b7919e6d4b6cf09531eaf1459a51157244193b5d079056d8c0fbcd82bbaa4282",
                ),
                (
                    "0fba3ec7aa8eeb051c3992d9fb69aa006a69275f1ea2356be6928548658f9c3a",
                    true,
                    "7e44450eaf43ee31dc2a7c9e7997cc087840c308729f0428b791e9ed54dc79b5",
                    "c2fcb07eb3fd023189ae9a7dfc8144d98caa5dffd3d966bd3f4766d658de16d6",
                ),
                (
                    "46ab6f4521159c51cdcd08f4ba4dee1b01c605e74ba65af265066454181303d5",
                    false,
                    "be43e1a5b093995ab09f15484d5c1a08b1c4df90621f5a8b197e46e1aa1273f8",
                    "8462cabe81f774420265753918e7775b4623f4e249ff14b6832a6db313da7be7",
                ),
                (
                    "a9ad0432d0c0af74d67e511f6139bbe9dcc344807c555ccc944195c5ecb47008",
                    false,
                    "d20b4915ef016de86f9b6ce1e43e5e1218b35da93686218ec44845ed9c19919b",
                    "d7984ed0b5853884c594c2c4e89d4f4995986ec8df7c64bf79245cb6ab7ddac0",
                ),
                (
                    "4c9ec94ecead9e21cbc0bc1779d726076525e96a1d7e103317c157a1be2e24aa",
                    false,
                    "f8febd831b4d30be6c1fa791d102c9d1cdcc07404f3ae4638bbc0c2c481ab019",
                    "9c4b04755b8bc196365ac9f098c4aca0881342a80180ebd8fec306e1a28ad49f",
                ),
                (
                    "f735454a4358262bc9bf288d5bccdcf12778e981c024c1d5df7ba2692ae2cd5e",
                    true,
                    "dfe7eccc37e592dadb3b433ed8da09b6888df33f180c792277c230247fb2f721",
                    "edc00ec87564933285404689f1e9b23a014a0b332dceba6896e58728f0188ed6",
                ),
                (
                    "325ed574193d7a516e12a98ba7df4bf726ba0d3ee8b54de706034c458e02e854",
                    true,
                    "3062ecc351f1168f97cf797bc6198745616ebf1904e08de2d6cc71f51235986f",
                    "204f43ffb9195a81c3ec1cd37a872c829c394f37c4e36bc3b0c2a7c2951f5cbe",
                ),
                (
                    "9839dacdfa7cd55c4bb2a0231de01e2e0f0fe1e55f9a330abb98a02473aa921f",
                    true,
                    "70fb64e60d82dc7f3ca700b6cddb894d82f7e4cc4b425ab03d34f66661000393",
                    "865f26a9b6426be5cf7f5370401fe41f4c19698dfb1d5c744a5a64474592a00a",
                ),
            ],
        ),
        (
            &mayo2,
            [
                (
                    "97a0dc1b133fb6a055ba0b6d2707a37341a7976da3e554616bfb91b62ed65d03",
                    true,
                    "7e2e2852239a3be20ccdae95c8bcdd9a0b28ef88b45f53344cf1358441ed97c9",
                    "c965b7b1aba37eebe26925d82360a3d7eea244e0d8ad0fe54033fa26af3a80ca",
                ),
                (
                    "76c908c82f525748be9257d23b2df70757f21545212700c392d91cb113eeb373",
                    true,
                    "174cf43e414cc7800a7d8e635a76f52347f9e8d946861e70b652379c319086d0",
                    "7cc0b786bdbfa923793e250e9f994d27237d9c4c845c450af7022f3aac7d40c9",
                ),
                (
                    "19e2899b4b8126c7ba589bf1e7c4c2c6ebc4dbc0ea25da7c53adde5f550fcf8a",
                    false,
                    "e5a35dc63419249d2724fe3c61b11a43ac0d87c7f94cdbf0d7103c124c05bdd4",
                    "5ecea89fe4ae25dbf54c50ee02432f904ee8b62cede1f5b2493228031de9c468",
                ),
                (
                    "910c6dc60b6598dc93f355a8a90400d588737e9dadf245c25869c4f79077ebec",
                    true,
                    "2e2204a7f1e93418d5dd773e7bcdafbd268e92264d07ad6349e75784d5014767",
                    "02112b8bae9c4cc54c3457780aae907ffa6bd0b30b251244e5e043c4bff01240",
                ),
                (
                    "2ec33bb7d64b7310f0d6732d0187a7961f2162d0e16dc3b9e8a08d22721aee6b",
                    false,
                    "3e3295c76eb02258bf0bb9fb1c69c2e25d2f57879bcf91f7221e1ccc598bb1ea",
                    "be3a5a879db3ec7fbfb26c9a9b8b00e52cb89f8f128a87578301e64dca7ff949",
                ),
                (
                    "f6569a151e4060126aac0b8f40aaa8bfba863cbd5798c3b85edf26bd740d4ce5",
                    false,
                    "b7c61258bd8654e50df62cb3de2eda7319b85def34956988ce5a4f297552611b",
                    "3334fc7b020c147880401b0a30b7b378a1f6b1a98b8fa41f1a7d116af8fe713d",
                ),
                (
                    "64f14d4925ce1b93078222df5f1fa87b6de7d1207c9318a36e4301f9e83ded8b",
                    false,
                    "fb0c30a2dcd13850390e5d07e872faece80c428c4cd155f5da1a985d21e15b2a",
                    "8f4b7e86fdcd62b93da960624a3ac1d26f1ecf985207c6f4ed9785a5aa9a6b77",
                ),
                (
                    "6824f14d00b3403719f2fb474452028ddf9809f548b1daf283b108249f20a260",
                    true,
                    "c69749ef3fd645c4b4b14eda4fafd86e54466a73bc7de6711cb23bdc36a1babd",
                    "df0449400b5d02d5306c4e6eaa4867a610e7e5f42b78538d84281d97ebd8f234",
                ),
                (
                    "1e9bd04715fd28933d667fa1054e2880828f951080deb41ee5e21c2661726cf3",
                    true,
                    "46c495f5b987c1e7317fa9687ed849139e2224afd8791a89f58cecec32c19112",
                    "69a8967fda040e52d88c68db9408ee705e4e45132f1533b5294b1b1956bdec90",
                ),
                (
                    "0949c055219e1147f11af8b5010d7551fd931c802cb26cda2aa6a94073dde319",
                    true,
                    "5d08f8e535d78a86912ee98ca5c9967a2d4b19a1d331a4505a0fb47074804834",
                    "4e93d7da4cbbb0bd6afeaf87d72a871c404b231e2def8f6acde2e65b4bf109dc",
                ),
            ],
        ),
        (
            &mayo3,
            [
                (
                    "d381f8e12fdd3aa335ac4066839d6195178a6dc6607cb5617dfee0dafbe14fe2",
                    true,
                    "e2aad92d2a0bfff88f6226705f16db96b6d26cf72951141292e071c033fdfbbb",
                    "95d9b7180ef5a9730769d67b2e5da2e39703cddb06070a2dc74ff5e04ebcccce",
                ),
                (
                    "bdeeb87fd30c3522967c0bb0ac9ad9bc4553ae85afe412561b4a2c0937b7732e",
                    true,
                    "c1fad91b4e77452d82651d96fe097d453186e43912dc1e5f88aea31aa7e856f1",
                    "c4de0dd2cd398cb43e8b2229bd599fe870a1d456dffb42904e306fb382b90cde",
                ),
                (
                    "487a3ee990e06d47b155eee4ce5f2e4fe71998acec86abaf8ae7e23e09f1acf2",
                    false,
                    "51f3c302efc82ae4883f54826ffca4f9fb94aa9729c88c6bd5b5e6c6212408ef",
                    "c5ff02924a7d60dd98aaea5a78da433f88d50d3b63021ef21c9cdf8f71673bf2",
                ),
                (
                    "a6f4e0b1b875267f127817e7dc88ff65a1ae88138eba3f47b4b3f545b6e3b4ad",
                    true,
                    "2cc064d0f5c09c1f2d7bac4c90c782f96cd2d8be5dbece78370fdc77c8bd8fbd",
                    "3d5ca06b3aaada2e78df310730b8fe1ab18d84a289737c48d3e4ede935f0884c",
                ),
                (
                    "6e6a84eac3f6b382cdd0ecb37017e85450af021feb27910d2a3d5e33279f78a6",
                    false,
                    "761abbd61b40de1c47ebac2a696da6cf90a0ce9a0fb9c633f34ef9845760eac3",
                    "4d6c4d1ea731c838d565cce6a08691dedc8f89b01e87da14127762283831ba52",
                ),
                (
                    "bf8aefeae2c787c40dc17b0732af49a54d9cfccec5477a2602c531f53629a1cd",
                    false,
                    "bf06af7b5ef9918ea855b7b8551bc0595bf0e70d0f06888fe0ae765f29bae56b",
                    "b1bf38357dfdcd4d3855769aafa02646c81e8044514355be4a5387a30ec6433e",
                ),
                (
                    "41deed4179b4ad79563f80a53d40e0321a3e3e8a50a129de591db1ed70d161f0",
                    false,
                    "620bb719f502d2dd18584573f9145bab0882d37bd8995e0b93620d262f8dc6c3",
                    "d20d1fad9edb7a6f2f8f5333635d4076428749a7b11f6b8348e4d818c8e272fd",
                ),
                (
                    "f993129c73b916956a9451e2543a8648a767e10a1f8f898be63a9b1fe1d9cbdd",
                    true,
                    "d439d12a47e2fc8db4db2809eeb53b57c940d4848b1f55baefa439e35397642c",
                    "a607e5d329f53d8ab53742a0c1d3487a485ba50347365f35c67cec1903f3e390",
                ),
                (
                    "707084d314deec56253626146d42d5db3efe31ca6d4d8eb21d4657923ffbf88f",
                    true,
                    "d5d1457dad7f0144c444c8a44919efae54d2402ec1679adbeaa0b310fc733e29",
                    "8a6378e3a9c758acb2c42a774915b4c79bd00d7d0a8f99a11deda3d9824f6788",
                ),
                (
                    "670595ca561ac6d35d920c65791fa723cb00a496e1558b02ca87352bb654b506",
                    true,
                    "d6a2c04e0d9a8692246d5ab681b4bfc8e57fd0a81589d555bb66b40765d07d55",
                    "5b54b285eb87dae3473b73c762f308be950a02ee257a481fcc239dffa949bbfb",
                ),
            ],
        ),
        (
            &mayo5,
            [
                (
                    "1ce86dbe9775eef4c887aa8c8b9446171284594561df4392898b59494bfc221d",
                    true,
                    "1777c6e90db83e3837bfb26069325b5fd9d871590ba1e8ac313f43e000cb9eb6",
                    "9851df24f12e27fc904d68c790419ee9e33c4f415c41ddf914c2d0376e25a51b",
                ),
                (
                    "f60907620b657dd9bec305ca7a6c7f89d93dddab5e9e7aeb3eb31431b0493e26",
                    true,
                    "bed4a2052968c73cd69df0ec98c05b549284e605f7020474f1d97acc0a4b4f89",
                    "3c44ca5e47673163b23ffb3d02ad58a9d9548db47e809f3a8d218cf546bba264",
                ),
                (
                    "f77d975183bd4cc67c84fda5de31ae20564f648b754a63b579570126b7e7a583",
                    false,
                    "ba586825849042e7cc58b6455899d38d90deb9483203377ef66486cce6d935c8",
                    "a3114e60b8496579827c5333df9f18870facfaa7c9a424ce84cd4978a3741c49",
                ),
                (
                    "0aad9cf1942053c6a82fcc6b3d579a23664b231c6e12c1ba6b6a922641c6ba8a",
                    true,
                    "39924df15feb45238d88bd872a24ed483f9985ef88dba4dc08c79567caa65763",
                    "c1f405a88fc31de12db6c830673f89dde39279e7c79b3702fb32288689cf71f2",
                ),
                (
                    "5b61a83603985d2a47fb6ea26d72d32a7b136fc44fd41b0ba32623291c9fe055",
                    false,
                    "74ac3dfe9b09952144715faf8e41ccd29bae49793a24536bd25cf0dd87fa91ae",
                    "c09a7733c41abd2a6a628670bdbf862a82e728b219b38ec0e1982ef35791635a",
                ),
                (
                    "876abb60441fa9a318b4bbd1964365ae99ec7234b301fefa4294e7a1a03b6d9e",
                    false,
                    "2d8b1eca89c450a0a81ca74b1d7e03ea92a050025390ee880efd3374b5ac3ed7",
                    "eb9d03ca6a4d33374b645a8d90b6898906b77d635cb02cd096e8cc6c0d395adb",
                ),
                (
                    "896552a30f5652158450de5095ae349cfd9fa536f27c16b99594f14ce8a5965d",
                    false,
                    "41bee50a216cd885af04cb203c0723bea75735b23b414aa9f57bdf20d9ead233",
                    "8818ece5109bcf3f5023f9ce14f04b56af77c2f3653d57f4ee081ef82534277b",
                ),
                (
                    "1766ce9d5da91b0a3435ca394c8bbf1de060ae27f1508387371dfa31661e6c99",
                    true,
                    "1fc194bc58c57ef1c570661913c22eb294aee0a64216caba2f48e18f1f473bdc",
                    "a0b4ca3d32019c139feab743339f9d37260314b9239998d87c12507877a6a416",
                ),
                (
                    "17a696ad8a9afc94731e45cfad01a9641cc39d8bbb51eb6929aece4f99b6db5c",
                    true,
                    "1195a4f0f9868a5a8bdb815d940d23f7e730f970d6d0936c6d3313be8f2adcf9",
                    "26c6fcd34aa3eba6a183dbd934a05c6393d2fa69da8a11c2e6ab310813d58442",
                ),
                (
                    "87e3d0f72b1b10b034d9594fcd96a9bf29d477bf48a75e6db6e650c2959cfbae",
                    true,
                    "47e767a62d2abc5226b58e07c765d8044021437cada29de443ab6be527463610",
                    "59bc355b9f09f6f9c8b2fa6de8acbea88bc23ae4ef16137d9884cbbf6e0ed042",
                ),
            ],
        ),
    ];

    #[test]
    fn echelonFormGivesTheMatrixOfTheCCode() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let (rows, columns) = (parameters.equationCount, parameters.systemColumnCount());
            for (caseIndex, (case, answer)) in cases.iter().zip(answers).enumerate() {
                let mut matrix = craftedMatrix(parameters, caseIndex);
                echelonForm(&mut matrix[..rows * columns], rows, columns);
                assert_eq!(
                    digestOfBytes(&matrix[..rows * columns]),
                    answer.0,
                    "{name}, {case}, seed {}",
                    caseSeed(parameters, caseIndex, 1)
                );
            }
        }
    }

    #[test]
    fn solutionGivesTheSolutionOfTheCCodeOrNone() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let unknownCount = parameters.vectorCount * parameters.oilCount;
            for (caseIndex, (case, answer)) in cases.iter().zip(answers).enumerate() {
                let seeds = [1, 2, 3].map(|input| caseSeed(parameters, caseIndex, input));
                let mut matrix = craftedMatrix(parameters, caseIndex);
                let target = inputNibbles(seeds[1], parameters.equationCount);
                let mut randomizer = inputNibbles(seeds[2], unknownCount);
                randomizer.push(if *case == "randomizerTail" { 9 } else { 0 });
                let solution = sampledSolution(
                    &mut matrix,
                    &target,
                    &randomizer,
                    unknownCount,
                    parameters.equationCount,
                );
                assert_eq!(solution.is_some(), answer.1, "{name}, {case}, {seeds:?}");
                // When no solution is found, the C program prints its x, which then holds the
                // k o unknowns of the randomizer and the zero that the program put after them.
                let solution =
                    solution.unwrap_or_else(|| [&randomizer[..unknownCount], &[0]].concat());
                assert_eq!(
                    digestOfBytes(&solution),
                    answer.2,
                    "{name}, {case}, {seeds:?}"
                );
                assert_eq!(
                    digestOfBytes(&matrix),
                    answer.3,
                    "{name}, {case}, {seeds:?}"
                );
            }
        }
    }

    #[test]
    fn masksAreAllOnesOrZeroAsTheComparisonsOfTheCCode() {
        assert_eq!(differenceMask(3, 3), 0);
        assert_eq!(differenceMask(3, 4), u64::MAX);
        assert_eq!(differenceMask(0, 159), u64::MAX);
        assert_eq!(greaterMask(5, 4), u64::MAX);
        assert_eq!(greaterMask(4, 4), 0);
        assert_eq!(greaterMask(3, 4), 0);
        assert_eq!(nonZeroMask(0), 0);
        for value in 1..16 {
            assert_eq!(nonZeroMask(value), 0xFF);
        }
    }
}
