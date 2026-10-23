use crate::FieldArithmetic;
use crate::fieldArithmetic::{loadWord, storeWord};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

/// The bytes of each row of the C code after the constant, which keep a row at a whole number
/// of 32-bit words.
const rowPadding: usize = 3;

/// A square linear system over the field, which `eliminate` brings to row echelon form as
/// `gf16mat_gaussian_elim_ref` and `gf256mat_gaussian_elim_ref` do, and `solution` solves as
/// `gf16mat_back_substitute_ref` and `gf256mat_back_substitute_ref` do.
///
/// Each row holds the elements of a row of the matrix, then the constant element in a byte of
/// its own, then three zero bytes, as the C code lays it out.
pub(crate) struct LinearSystem<F> {
    rows: Vec<u8>,
    size: usize,
    matrixLength: usize,
    rowLength: usize,
    field: PhantomData<F>,
}

impl<F: FieldArithmetic> LinearSystem<F> {
    /// The system of a square matrix, given as `size` columns of `size` elements each as the
    /// signature lays out its linear map, and of a constant vector of `size` elements.
    pub(crate) fn new(columns: &[u8], constant: &[u8], size: usize) -> Self {
        let matrixLength = F::byteLength(size);
        let rowLength = matrixLength + 1 + rowPadding;
        assert_eq!(
            columns.len(),
            size * matrixLength,
            "the matrix has a column of each size"
        );
        let mut rows = vec![0u8; size * rowLength];
        for (index, row) in rows.chunks_exact_mut(rowLength).enumerate() {
            for (column, columnBytes) in columns.chunks_exact(matrixLength).enumerate() {
                F::setElement(row, column, F::element(columnBytes, index));
            }
            row[matrixLength] = F::element(constant, index);
        }
        LinearSystem {
            rows,
            size,
            matrixLength,
            rowLength,
            field: PhantomData,
        }
    }

    /// Brings the matrix to row echelon form with ones on the diagonal, with no branch on an
    /// element, and returns true when the matrix is nonsingular, as
    /// `gf16mat_gauss_elim_row_echolen` and `gf256mat_gauss_elim_row_echolen` do.
    ///
    /// While the pivot of a row is zero, each later row is added to it. A pivot that stays zero
    /// marks the matrix as singular. Each operation starts at the byte of the pivot, as in the
    /// C code.
    pub(crate) fn eliminate(&mut self) -> bool {
        let rowLength = self.rowLength;
        let mut isNonsingular = 1u8;
        for index in 0..self.size {
            let start = index / F::elementsPerByte;
            let (above, below) = self.rows.split_at_mut((index + 1) * rowLength);
            let pivotRow = &mut above[index * rowLength..];
            for other in below.chunks_exact(rowLength) {
                let isPivotZero = 1 - F::isNonzero(F::element(pivotRow, index));
                Self::conditionalAdd(&mut pivotRow[start..], &other[start..], isPivotZero);
            }
            let pivot = F::element(pivotRow, index);
            isNonsingular &= F::isNonzero(pivot);
            F::scale(&mut pivotRow[start..], F::inverse(pivot));
            for other in below.chunks_exact_mut(rowLength) {
                let factor = F::element(other, index);
                F::multiplyAdd(&mut other[start..], &pivotRow[start..], factor);
            }
        }
        isNonsingular == 1
    }

    /// Adds a vector to an accumulator when a condition is 1, and leaves the accumulator when
    /// it is 0, with no branch, as `gf256v_conditional_add` does.
    fn conditionalAdd(accumulator: &mut [u8], vector: &[u8], condition: u8) {
        let mask = 0u64.wrapping_sub(u64::from(condition));
        for (target, source) in accumulator.chunks_mut(8).zip(vector.chunks(8)) {
            storeWord(target, loadWord(target) ^ (loadWord(source) & mask));
        }
    }

    /// The solution of an eliminated nonsingular system, by back substitution: from the last
    /// row up, each solved element times its column leaves the constants of the rows above it.
    pub(crate) fn solution(&self) -> Vec<u8> {
        let mut solution = vec![0u8; self.matrixLength];
        for (index, row) in self.rows.chunks_exact(self.rowLength).enumerate() {
            F::setElement(&mut solution, index, row[self.matrixLength]);
        }
        for column in (1..self.size).rev() {
            let value = F::element(&solution, column);
            for (index, row) in self
                .rows
                .chunks_exact(self.rowLength)
                .take(column)
                .enumerate()
            {
                let term = F::product(F::element(row, column), value);
                let updated = F::element(&solution, index) ^ term;
                F::setElement(&mut solution, index, updated);
            }
        }
        solution
    }

    /// The matrix and the constant as the C function leaves them: the rows of the matrix one
    /// after the other, then the constant vector.
    #[cfg(test)]
    pub(crate) fn echelonForm(&self) -> Vec<u8> {
        let mut form = Vec::with_capacity((self.size + 1) * self.matrixLength);
        let mut constant = vec![0u8; self.matrixLength];
        for (index, row) in self.rows.chunks_exact(self.rowLength).enumerate() {
            form.extend_from_slice(&row[..self.matrixLength]);
            F::setElement(&mut constant, index, row[self.matrixLength]);
        }
        form.extend_from_slice(&constant);
        form
    }
}

#[cfg(test)]
mod tests {
    use super::LinearSystem;
    use crate::FieldArithmetic;
    use crate::gf16::GF16;
    use crate::gf256::GF256;
    use crate::testInputs::{digest, sequence};

    /// The answers of the C program for the seeds 20 to 29 of a shape: the result of
    /// `gf*mat_gaussian_elim`, the digest of the matrix and the constant after it, and the
    /// digest of the solution of `gf*mat_back_substitute` for a nonsingular matrix.
    type Answers = [(bool, &'static str, Option<&'static str>); 10];

    /// The product of the matrix of the columns with a vector, for a check of a solution
    /// against the system.
    fn product<F: FieldArithmetic>(columns: &[u8], vector: &[u8], size: usize) -> Vec<u8> {
        let length = F::byteLength(size);
        let mut result = vec![0u8; length];
        for (column, columnBytes) in columns.chunks_exact(length).enumerate() {
            F::multiplyAdd(&mut result, columnBytes, F::element(vector, column));
        }
        result
    }

    fn checkSeeds<F: FieldArithmetic>(size: usize, answers: &Answers) {
        let length = F::byteLength(size);
        for (offset, (isNonsingular, echelonDigest, solutionDigest)) in answers.iter().enumerate() {
            let seed = 20 + offset as u32;
            let columns = sequence(size * length, seed);
            let constant = sequence(length, seed + 100);
            let mut system = LinearSystem::<F>::new(&columns, &constant, size);
            assert_eq!(
                system.eliminate(),
                *isNonsingular,
                "size {size}, seed {seed}"
            );
            assert_eq!(
                digest(&system.echelonForm()),
                *echelonDigest,
                "size {size}, seed {seed}"
            );
            if let Some(solutionDigest) = solutionDigest {
                let solution = system.solution();
                assert_eq!(
                    digest(&solution),
                    *solutionDigest,
                    "size {size}, seed {seed}"
                );
                assert_eq!(product::<F>(&columns, &solution, size), constant);
            }
        }
    }

    /// The answers of the C program for the four crafted systems of a shape, from the columns
    /// of the seeds 40 to 43 and the constants of the seeds 140 to 143: a zero first column, a
    /// zero element (0, 0), a last column that is the sum of the first two, and the identity.
    fn checkCraftedSystems<F: FieldArithmetic>(size: usize, answers: [(&str, Option<&str>); 4]) {
        let length = F::byteLength(size);
        for (kind, (echelonDigest, solutionDigest)) in answers.into_iter().enumerate() {
            let mut columns = sequence(size * length, 40 + kind as u32);
            let constant = sequence(length, 140 + kind as u32);
            match kind {
                0 => columns[..length].fill(0),
                1 => F::setElement(&mut columns, 0, 0),
                2 => {
                    let (first, rest) = columns.split_at_mut(length);
                    let (second, rest) = rest.split_at_mut(length);
                    let last = &mut rest[(size - 3) * length..];
                    for ((last, first), second) in last.iter_mut().zip(&*first).zip(&*second) {
                        *last = first ^ second;
                    }
                }
                _ => {
                    columns.fill(0);
                    for column in 0..size {
                        F::setElement(&mut columns[column * length..], column, 1);
                    }
                }
            }
            // The first element of the zero pivot is zero, so the elimination must add a row.
            if kind == 1 {
                assert_eq!(F::element(&columns, 0), 0);
                assert_ne!(F::element(&columns, 1), 0);
            }
            let mut system = LinearSystem::<F>::new(&columns, &constant, size);
            assert_eq!(system.eliminate(), solutionDigest.is_some(), "kind {kind}");
            assert_eq!(digest(&system.echelonForm()), echelonDigest, "kind {kind}");
            if let Some(solutionDigest) = solutionDigest {
                let solution = system.solution();
                assert_eq!(digest(&solution), solutionDigest, "kind {kind}");
                assert_eq!(
                    product::<F>(&columns, &solution, size),
                    constant,
                    "kind {kind}"
                );
            }
        }
    }

    #[test]
    fn craftedSystemsOfGF16AreSolvedOrRefusedAsTheCCodeDecides() {
        checkCraftedSystems::<GF16>(
            64,
            [
                (
                    "15490535cbd124940f4c6a36f7f35080542d6974b16336e0571ddaf82e2294c7",
                    None,
                ),
                (
                    "7d37b2bc7f4e1860bb976a662bcc33e70524f52b06ee4f1a4e5c1b54459d560d",
                    Some("e9e852aba5e03ca108b86af3679be950ad398f356a73eb22ccd30bfdd4148484"),
                ),
                (
                    "703feb3bc88bfc3fcb0793ecf462c536515637ada7a99ca3852b43bc6440f2ec",
                    None,
                ),
                (
                    "4d919cf90a2fbbc8662507e3bf1c28ad71d9f7f0153fcad68b04197301f09310",
                    Some("d69e6ed6a5572647d2547aa5867bbe3756840cf55c3d33fa9813a28ae847ead7"),
                ),
            ],
        );
    }

    #[test]
    fn craftedSystemsOfGF256AreSolvedOrRefusedAsTheCCodeDecides() {
        checkCraftedSystems::<GF256>(
            44,
            [
                (
                    "70aa41ea1b31180ded8037df2687aa6a5153ac2a77eb3bd81adfd7992a2416e8",
                    None,
                ),
                (
                    "22adbf98972f2643eb146b0048437f682c19339fd458cb6a7d46904ffb73eb26",
                    Some("975e1860260c94ebb15000a053c9e7b94f136aeaf94cbd64cb8e248b79ff2389"),
                ),
                (
                    "cfe5563cf0a9ad7f7683afc9a279d348b98f7adae14b874fb53dd577e05bb116",
                    None,
                ),
                (
                    "ccf4b7a101be3c75288e6862d4a396e22f7d710e8cce4a9096840ca29241830c",
                    Some("a149121bedcde4837345e848d7276f63c70a6d3b47b01e5e18ed1a232e0d4cd0"),
                ),
            ],
        );
    }

    #[test]
    fn theIdentityGivesTheConstantAsTheSolution() {
        let constant = sequence(44, 143);
        let mut columns = vec![0u8; 44 * 44];
        for column in 0..44 {
            columns[column * 44 + column] = 1;
        }
        let mut system = LinearSystem::<GF256>::new(&columns, &constant, 44);
        assert!(system.eliminate());
        assert_eq!(system.solution(), constant);
    }

    #[test]
    fn systemsOfTheShapeOfOVIsGiveTheEchelonFormsAndSolutionsOfTheCCode() {
        checkSeeds::<GF16>(
            64,
            &[
                (
                    true,
                    "35950afcae847f9005eb71697baa82698d704582e2e84fd6716f06c6e486e786",
                    Some("1ef909bf3d86939d2b3bdecf053826f135f36ca91a3ae46b6f8f3e3f9ae39634"),
                ),
                // The random matrix of the seed 21 is singular.
                (
                    false,
                    "28933f10469337c167628ea95902ccc6311079ce2b2a8e5dd61f1b04d46fe53a",
                    None,
                ),
                (
                    true,
                    "2e4e1f80ffaeb6a1e00f1bec0d52e406ec29f1301c0d2ba4e371ab9015db54b6",
                    Some("5c59e4b0da88cea640bfdf9af65dcaf8514faaa87d6fde3e1b3a1666646cdd0e"),
                ),
                (
                    true,
                    "fa4fa354db919b19750d30f01373ba87128e83f5eb19726f1ef8e0ece17adfde",
                    Some("9deec606030899845bbe7c3f87c1ebd9edf86f86a3826a7ea5247340d5e05d77"),
                ),
                (
                    true,
                    "05fa707ee0caef15a83be399e654eee01e2bd1a0eaf16949571349a7fcea0c07",
                    Some("b7d88fcc3cda0b935e5283079fd67601e8f8ae45001a00fa96d0fd2d97f69045"),
                ),
                (
                    true,
                    "1b25c730520ebfa4745534b7267054c04ffbe163a26149bfc44016678ad41e62",
                    Some("c0e347c03b8fc03cfc242c164bab13a0422d6ff9e83942a7bdffc923c8665de3"),
                ),
                (
                    true,
                    "4960a94e3d457a8014e264ba42a2aef27ee9d4d8f262bb8759212898de90ea7d",
                    Some("656ddfca9d7b13e544909eca6bc6872aececd18cfc169e1f4b65ccf6006d1f19"),
                ),
                (
                    true,
                    "d80bdb256e121f094d095d9a5f922f0ede166b59cbcc1865e5d1d5581be6af85",
                    Some("526f99c80a42c50026646fd0fd2ae08af4b5b8c9ac6c683866e080c2b166dadf"),
                ),
                (
                    true,
                    "67bb303989564cc6f41b91a9c3f4a2f5a77f10fde214eb9c3c3dad381beb0770",
                    Some("f5f56da3f3f6947e174980ab38d83d44a9c15b2c8c30cd95e5d1929faacec488"),
                ),
                (
                    true,
                    "fc2d0fe3230227d2ba4d053d0a985e63536393074fffd5e4fa937a0d19920d84",
                    Some("26fd742293c63d79b02a81006b74a97a754c432a3bbca033e06641e3986851e4"),
                ),
            ],
        );
    }

    #[test]
    fn systemsOfTheShapeOfOVIpGiveTheEchelonFormsAndSolutionsOfTheCCode() {
        checkSeeds::<GF256>(
            44,
            &[
                (
                    true,
                    "b606de5108ed751254f7b6daa967ad4e315ba3addabdcedc656d7062f909ad30",
                    Some("280e00ceadcba5311c248a54dd81aaed7c7bc3e9dc1e5d440607dad26997821f"),
                ),
                (
                    true,
                    "c12883bae8e0903ca281a30de4ed726c4dab77fabcb41dc6e46f1a90e3223c2a",
                    Some("38931837653170984e529990baa2008e34596f6d7eb0eeca53727d709f6a8fa7"),
                ),
                (
                    true,
                    "619160f75f4b59e36531ebeb36d622314ab3eb09ebbc248be18fb7bf38525c89",
                    Some("1de1742edea659427a1cf75b0d0da5f2d8d858cfe3dbbe54ae31fb65b24c81f2"),
                ),
                (
                    true,
                    "3c2e5dc25426f7b97fea15361ccf53e6e6bddf793ebc52cf114a880af2b1075a",
                    Some("36effe3a7fa01444aa8a135448e53c1d89d2d58fa9ac57c40b1384b3b1e868a3"),
                ),
                (
                    true,
                    "d0258d1c7dcf974467873ee5a5210394ab285d76e40021d67d2c5904350a2520",
                    Some("bafbac84e3e369ab75b4a527e49ab0f621966246e8e43551c460047f52adb5fc"),
                ),
                (
                    true,
                    "426dfb67d5b152bcd6607964ac4bcf9addc9176cd56b08a4251b4475f8a2ddda",
                    Some("b875e1cb72e0a1dc676ef4055b6806a8145b1bffb8cb4127a00aa76e6cffa3bf"),
                ),
                (
                    true,
                    "c4ff646ef07ef3cf003ef291e8d1ac6876554d892d3e892f9e7bde5382bbbeaa",
                    Some("889cde403d4fb53789c7f05320bd6c9863ef294bf96ffb0db5a28b8a7ce0e9d1"),
                ),
                (
                    true,
                    "205c62f5dbcfbc6e7badc655602981fc71651d928e7579a936350bee6c76db95",
                    Some("9534dd92d2222abd0c28753a7ce70d5d1da930b78cd0a5794f88cd8297c69f21"),
                ),
                (
                    true,
                    "2103a50c37319dd9d94f6f512fa0a9ddd7fff3999a87c8d825ad35ba5b3b9865",
                    Some("30944259012a741e17ad7e1cb66e1b422961909cad8cbb4d81410d402446d760"),
                ),
                (
                    true,
                    "39957b04df91b393794f3646b6c8b8aca489d88343c7f134045f9efaaff2dbef",
                    Some("1b68d2d4e78481c06df3db268061548293ebe860d428cb15f989b386ea93c59f"),
                ),
            ],
        );
    }
}
