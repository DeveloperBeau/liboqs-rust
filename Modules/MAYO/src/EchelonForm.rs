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
            let mask = isPivotRow | (isBelowPivotRow & pivotIsZero);
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
/// `systemMatrix` gives it. The randomizer has `k o + 1` elements, the last one zero. The
/// solution has `k o + 1` elements: the back substitution can change the one after the k o
/// unknowns, as in the C code, and the signature uses only the first k o.
pub(crate) fn sampledSolution(
    matrix: &mut [u8],
    target: &[u8],
    randomizer: &[u8],
    unknownCount: usize,
    rowCount: usize,
) -> Option<Vec<u8>> {
    let columnCount = unknownCount + 1;
    let mut solution = randomizer.to_vec();
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
                let mut columnBytes = 0u64;
                for offset in 0..8 {
                    columnBytes ^=
                        u64::from(matrix[(first + offset) * columnCount + column]) << (8 * offset);
                }
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
    use crate::testInputs::{digestOfBytes, inputNibbles};

    /// The cases of the C program: seeded matrices, and matrices with a zero column, five zero
    /// columns, a first column that is zero in the 40 first rows, a lower half that repeats the
    /// upper half, all zeros, three zero rows at the end, and a first column whose first entry
    /// that is not zero is at the last row of the pivot search, row 32, or just after it.
    const cases: [&str; 9] = [
        "random",
        "zeroColumn",
        "fiveZeroColumns",
        "latePivot",
        "lowRank",
        "zero",
        "lastRowsZero",
        "pivotAtSearchEnd",
        "pivotPastSearch",
    ];

    /// The matrix of a case, with zero rows up to a multiple of 8.
    fn craftedMatrix(parameters: &Parameters, case: &str) -> Vec<u8> {
        let name = parameters.description.name;
        let (rows, columns) = (parameters.equationCount, parameters.systemColumnCount());
        let mut matrix = inputNibbles(name, &format!("matrix {case}"), rows * columns);
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
    const knownAnswers: [(&Parameters, [CaseAnswer; 9]); 4] = [
        (
            &mayo1,
            [
                (
                    "e5e4a167237b564bf9383be2c2dd63c6f1828e0db31c83b6514fd3c208bdc9bf",
                    true,
                    "be5816926d82f7b8da56ca9d5efc3825db77513476008cc3db56a0865ea0f969",
                    "d62acfed52d892b89388f10da799be9a43ba58c38188107aa0878eddd411f038",
                ),
                (
                    "5ad02e0c1378b9c9f7d140f9f0c54f180ba2a0d07e8a333a9e08be6d0baa906a",
                    true,
                    "c7613e11ca08143cd9229925d4a6149e6c8040c26920f8eec466bb088db85f3a",
                    "873b96e24fa273082ee7b9c53453a2c405905fa4bfb14d200928442f9a76977f",
                ),
                (
                    "dd0292337f868f6752b8fb9a2642249b2d633b6828c01e373480a8e15ff4a7b7",
                    false,
                    "6025d88f775c7b8b29e92fb1e9dd440a0b66612d7a7c7af588140bd4938bc03f",
                    "0c1ecd88c09a6956fb2e6582124f073e51da4885a83db39860aed7f9b60d2a9d",
                ),
                (
                    "bdc1d526ae8f23a9185a6ac41f78de709317f4b05bd96dd5029a6c6a23de2954",
                    true,
                    "5fcc2d0e7c4c3c8185711f79a681764c834f312107576f93b9345b585238d3d1",
                    "e4795837a335c2ee3b302e248ccdbf288f05752d53eb315dd95a745d1319e429",
                ),
                (
                    "8a0d5d484a161ee692e3099c9f84d2a02578ff44fa8408c47d93058852e17c5d",
                    false,
                    "cbf0479e976595e0b572ae52e2598c77cbca21a5eec1cabf7c8f787f02d88f18",
                    "8f27cf714ca1c4e40486c2306238b999837ceff830a847dab44f8d9c3e6df018",
                ),
                (
                    "b7f64835cd0d969d818a1b4a6e46de704092360d77914cb5edc36a94439df357",
                    false,
                    "7248f89f8431db1fb9bc85748e7228084fd2161d2f023ba92d3d8426d3afc354",
                    "79c2091cc044a5a7bcfea2ce5916d68b0f2f2ed9c36eec8d30ca0001f42d9a99",
                ),
                (
                    "68c96c5d7dfcba52e0f5092f10626402a4c0fe4ec44ce63be3f85facf72cfebd",
                    false,
                    "58e8fafec0b507f1c187dc25d08438450adbe93c9355ab180865dcf7afff2ae4",
                    "41591c6a4bbed89afac73d095086ba45d98f6bb670ff86f226c05975d0ce87cd",
                ),
                (
                    "97f85e1ec470259a61f0d03a9246824588b2a9af174c7b89890f02213ddb7ed1",
                    true,
                    "56e42c3888fa5f52f7f14aa92209b1f783578209bc1e90e947d2e10a1dfd27dd",
                    "6b9d7f69dbb35308cb245aabffc8867e7a0b2df596ab6c25a2fdfa8fc776c23f",
                ),
                (
                    "aae4c885771ef9e48af56e704e2b5fe6b9aeed4bba1155ed62b6b00f2c035589",
                    true,
                    "1ecd06658d7dedf329841e14df0cfa80100b1f40df1bd0a40697a86d5fa3c74a",
                    "96c18949f3510bfb79037c681cd605eb520e6f974a963694665806ebd8296841",
                ),
            ],
        ),
        (
            &mayo2,
            [
                (
                    "ba6e7877a7f509f358e92b7ebe328f17d6af50904c97fd9a28c43ad090d797ca",
                    true,
                    "8cee330083a557ae656c0148395524fa0fbc10f05fa4353f2c74c65ebf590902",
                    "2f789263c4e8b013e1a17f6c5ee953052e95632091a3fe10ce36a414d3f4a299",
                ),
                (
                    "5a2de714eb7c9ad49ddec80f20370892234674de3a991ffa8cc58516b1ae72eb",
                    true,
                    "29dadc2168dc5067d91084ed09338debc7329630082a8845d8b644eb81af4224",
                    "1571f2ae732f258dca7abdb69a88de96f88282070fa5f201852c6743de4dad20",
                ),
                (
                    "5e664348803aca2db5a759f1ced8011798b272b76f66d5a9e60cc784559794da",
                    false,
                    "dbba005ac791b9d780d39aed89907d32013f88e31ce31332b1641a9b68a125f4",
                    "e579779895e58911453d8ebc98ab2296efd4a9f245a24f161283a986f24487d7",
                ),
                (
                    "f6e81255db47273e508ea8cfafa629b0da85e7399ff1cde34805530bdfbf361d",
                    true,
                    "0fe16b39db6b0a9d9f518a6359d00d6b46552c04462ae1d1e3efed44f018ba86",
                    "05799a151031fef84a51bf7908f0edf937c453493e4c39a1380297888ba2d013",
                ),
                (
                    "acc6e2a2d411fb2ff69be783905833cbe31e55c0b2d324fe02117da636730c43",
                    false,
                    "8a1f5eef4764406cf4b8a70e288330f9bc07d4fe76dcfd7dc67f7be628485c0a",
                    "091cdacaa6ecd06f099e7e7659016d18ac905c63c99f89bd0a52465147decbba",
                ),
                (
                    "85a1b228efb67e33968d00c50c423b07787140de5382a1b1ca19375c4e6d3ce5",
                    false,
                    "9ddccf1cebc705bbc4169428670bdcbc8748764877c0a70c2f60b70d292032a1",
                    "d2506b45efc0e34a964e6c526f1777b5f2179350a864f39ed92244e0a7f2815e",
                ),
                (
                    "29eece11c9edc8be3564058755ecfcbee2871fac5caef8a6c4153b4c2951fa86",
                    false,
                    "382e803243859474d8ee21e82cc5184c913a447c9206b8881f090d697a9d48a3",
                    "ce6777a5f7b6a594f0f2d069a4fa538bb6d67045b81e27682b55758eb32e9244",
                ),
                (
                    "9429fa53c30fd6f2e7c974cab59d7b732c6de1d44431a4e5bb171a7d2b109341",
                    true,
                    "3f6e8ebf2e47e6a32402f7dd4956c88ea1ddfdf142c7e768e938676811a2f251",
                    "d30e630d9ff4ad3b98f02539261c956fe8e5b4463aca5561525a16d1d8b43a10",
                ),
                (
                    "a4a5a37fa79cd27625e0730977eb90e35c0bfc5f7e9bba29e9027ca554c048c4",
                    true,
                    "823ce6b14ca059c31383f332218d8d91b1563103a1aadb1149b638b920908310",
                    "bcd1c92be30c82102f9f9de48f7e893404c8f6ab0795311b540f63a9ad7b0ea3",
                ),
            ],
        ),
        (
            &mayo3,
            [
                (
                    "a347f31b706852433b0e81192057a3048836585d9fde1d78bca143c362a67bbc",
                    true,
                    "c7e9268d8c46d33a33cd993dfdb6988ed439e32b55d28b98043212095440ce16",
                    "3902cd8797e4c3f32a2ac1e34d37738e1588719ab7ac03f7d3a1e6aa8be9ffd2",
                ),
                (
                    "660aa933753e20f52a30cd06dea309442f7f09a56340e960bd30e7dbda1b052d",
                    true,
                    "8706b0dca78b75e93e5b7b9a2adc6d743aa09b00893eb554385e42106a9b913b",
                    "db7f71cd2ac66cdacbd2db99ffede2496846fbbbc1b78d600584699d543d8691",
                ),
                (
                    "4e5d8290f897c9985bc559001a6afb19d0edc9e71beb77de1c363aed245c0055",
                    false,
                    "34045b06ab35567c62f10a30a4ca6a49356d967e93c0a73f1033f21fb30fecad",
                    "910b1124a7b540d20fb9d7b5489fa28986ecc32b8f527b7887dc8c557484dc0e",
                ),
                (
                    "235a52038cf8b815ef5088198543e5f3518adb63e150e5b77533635093c43145",
                    true,
                    "d3411ac0b4c1bb5895f039a4529763d0e950a458c32a01e2ff6b774ff28926bc",
                    "4f428137189e2d652a2d955420b259a846401b3eeea49a5e6f4fada379675808",
                ),
                (
                    "b80fb8150aa3293d4f15402f855a751954acc919523c63c953bbd2a58877372f",
                    false,
                    "2e33b5191718c5dc8ff12988dc2b2cfa174b13dc145690c09c440c7d77aa21de",
                    "247e1bdd6321e1a406399321c242f51016d68a07910759bfaf07cb4784d94d10",
                ),
                (
                    "28e891812fd86cd379007ff5de73825db680b29b7dcca6a27c5f2e2e96b983ce",
                    false,
                    "e26c86c15d87b2ef8853088a8cf2c4805c4b5d2254b745fa0ba57691d6bf607a",
                    "42e741af6a6b2f613af657448f30f1e1a783fd0e5cc85861ccbac8f44dbf2242",
                ),
                (
                    "11a293c940f7f4e21ca63ded8e669728c41fa3d339cc5942908a7c28594715d2",
                    false,
                    "c865fe8ac9774a9467f2d6e8233d217c26aeec8f248b55b8925725ba0f949833",
                    "75d25c34251919705694a801d90161378b3c0bf89460197e713a003323c29409",
                ),
                (
                    "3d2dd8ce6a8032d74f2228f9bdc9a26989f6a0cda05b5de01b0902bef331ab45",
                    true,
                    "bbdd36eb5d1843169ab87cb4a818bdd9bfbef4d39b19358e720254c3476ac4e8",
                    "4c82cdb2fd908d2f9669bb63bc268e13b131795df0633e8e1d71def833aec20d",
                ),
                (
                    "83641f0a7b396ab58d1e459c6c4d19839137ed754da400aba9397b0c71d0a67e",
                    true,
                    "4af209095d29406eb3319bcc1ecd8c1cc15968dbb95a2101266bc0336bdb5795",
                    "592cf095b6f74bf8134d66c1d00a103459e5aff5241b5402cdedf1c31d13cea2",
                ),
            ],
        ),
        (
            &mayo5,
            [
                (
                    "305806a087ff6b7688b689738d251962cb795e51d286260a6f31136eaad15188",
                    true,
                    "c61739e8f692edbcb7d34945436e6c1e100086dff21a6f6811effc2bbad3299f",
                    "5c3bd8d7d7e7b87e1e6a913db9ffb65caaab4586f177c1ce0181298fbb265dc7",
                ),
                (
                    "306685edfc28676df5524cb6ec8112566e404992caf6964dcacfb5efa8f0f2c4",
                    true,
                    "02a47b7ae93480f155beb2d715e035f5244328417521061893e1c441a8c1e99d",
                    "9844f5e4e6ac4e4b4deed543ff8a082974182f86e2688e0cad60301b8a48764f",
                ),
                (
                    "c1cd7dc9c10121a6c972f131d2f5b748275b2d8a22beec872b8390d0753758c5",
                    false,
                    "0d658ac5b8960ecf4336d07d372d7e025f805cd9c6d59d0e77d5b38c9e8f12e2",
                    "5442e89e92825b00dc363cbae2a0c67f4647703f268910c6545177a8d81b4d4d",
                ),
                (
                    "b1742dbbb8123c465cd0e42d1ab647f9e8431d9430ed1ff5050c9c30627a4f56",
                    true,
                    "fd0f862143bbf505d36f60df055fd3301bdd86f2c23b8dab230875af3a23cf3a",
                    "5afd7135877834756c04be27ee29ae5f9bfbdd972ce07e3260e5545d1b954ad7",
                ),
                (
                    "0abed12800f10d628fa5990e47ac2f4b8503d4b098f18d48852d3ac5d613619d",
                    false,
                    "e7d535dddbd1b2d3ee36a850ae53f68d50b81b7af74326a35b1d2d96a4485f45",
                    "e33fa5a123530e5fa50afbcc948ac973ddc74a52cf1bcea888d0d7fe7097c866",
                ),
                (
                    "0d66a6e8c57aaa2907c642adfc56597fcea0ee3a8db9817af19651af59d863a9",
                    false,
                    "05f04c88ef2eca23a7ebd3fe9eabec0a2752d67612d3020b4bd55530e6829797",
                    "dd2a709f2aea81925c2ed09ae1f2aa9c949f9716e2fd6bb7a808a23fe4469e19",
                ),
                (
                    "372fdd93c805dec33bb4a25f5c6c38d3742a036911da5b009db5e3a6a8b064dd",
                    false,
                    "1e119a7c0d32f63ee3b844c3e33a5ca6f849e50c070b1e08a4ae4d849e4b72e3",
                    "f2eeebcee5dce7909b0828150b7287eadb15a1810835cec73ba4c5209f4a504d",
                ),
                (
                    "63875a3049bb2b90a1e1d55c21fcc44f2e13f1c28a8662224b430e3b86ff4701",
                    true,
                    "8132056e0c6abfae9b0d431e60481a56b717e25aa6a43ca87237c11009dfd1ef",
                    "ca635d2e66b6c861b97eb24c8b992ec1175339f6f3c548b07664b3027a7a70c0",
                ),
                (
                    "8b91f6c270c72213bc782c31fc8d0a03c3fc3d91091dd3811271abbaa4ef42ee",
                    true,
                    "39b6ec55e1d5d52586b5a4324fe9d6af85fb5b22e4a27703dea56253be3c14b1",
                    "0419d3f62c10b984ce76430b59fc49570299c343268ccb800042cf5d362bec83",
                ),
            ],
        ),
    ];

    #[test]
    fn echelonFormGivesTheMatrixOfTheCCode() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let (rows, columns) = (parameters.equationCount, parameters.systemColumnCount());
            for (case, answer) in cases.iter().zip(answers) {
                let mut matrix = craftedMatrix(parameters, case);
                echelonForm(&mut matrix[..rows * columns], rows, columns);
                assert_eq!(
                    digestOfBytes(&matrix[..rows * columns]),
                    answer.0,
                    "{name}, {case}"
                );
            }
        }
    }

    #[test]
    fn solutionGivesTheSolutionOfTheCCodeOrNone() {
        for (parameters, answers) in knownAnswers {
            let name = parameters.description.name;
            let unknownCount = parameters.vectorCount * parameters.oilCount;
            for (case, answer) in cases.iter().zip(answers) {
                let mut matrix = craftedMatrix(parameters, case);
                let target = inputNibbles(
                    name,
                    &format!("solution y {case}"),
                    parameters.equationCount,
                );
                let mut randomizer =
                    inputNibbles(name, &format!("solution r {case}"), unknownCount);
                randomizer.push(0);
                let solution = sampledSolution(
                    &mut matrix,
                    &target,
                    &randomizer,
                    unknownCount,
                    parameters.equationCount,
                );
                assert_eq!(solution.is_some(), answer.1, "{name}, {case}");
                // The C program prints the randomizer as the solution when none is found.
                let solution = solution.unwrap_or(randomizer);
                assert_eq!(digestOfBytes(&solution), answer.2, "{name}, {case}");
                assert_eq!(digestOfBytes(&matrix), answer.3, "{name}, {case}");
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
