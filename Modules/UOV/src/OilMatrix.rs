use crate::FieldArithmetic;
use core::marker::PhantomData;

/// The secret oil matrix O of v rows and o columns, `sk->O` of the reference code, read where
/// the secret key holds it: column after column, each column the v elements of a vector.
pub(crate) struct OilMatrix<'key, F> {
    bytes: &'key [u8],
    /// The rows v, one for each vinegar variable.
    pub(crate) rowCount: usize,
    /// The columns o, one for each oil variable.
    pub(crate) columnCount: usize,
    columnLength: usize,
    field: PhantomData<F>,
}

impl<'key, F: FieldArithmetic> OilMatrix<'key, F> {
    /// The matrix of the bytes of a secret key part, with a number of rows and of columns.
    pub(crate) fn new(bytes: &'key [u8], rowCount: usize, columnCount: usize) -> Self {
        let columnLength = F::byteLength(rowCount);
        assert_eq!(
            bytes.len(),
            columnLength * columnCount,
            "the oil matrix has a column of v elements for each oil variable"
        );
        OilMatrix {
            bytes,
            rowCount,
            columnCount,
            columnLength,
            field: PhantomData,
        }
    }

    /// The element at a row and a column.
    #[inline(always)]
    pub(crate) fn element(&self, row: usize, column: usize) -> u8 {
        F::element(&self.bytes[column * self.columnLength..], row)
    }
}

#[cfg(test)]
mod tests {
    use super::OilMatrix;
    use crate::gf16::GF16;
    use crate::gf256::GF256;

    #[test]
    fn elementsAreReadColumnByColumn() {
        // Two columns of four GF(16) elements: 1, 2, 3, 4 and 5, 6, 7, 8.
        let bytes = [0x21, 0x43, 0x65, 0x87];
        let matrix = OilMatrix::<GF16>::new(&bytes, 4, 2);
        assert_eq!((matrix.element(0, 0), matrix.element(3, 0)), (1, 4));
        assert_eq!((matrix.element(0, 1), matrix.element(3, 1)), (5, 8));
        let matrix = OilMatrix::<GF256>::new(&bytes, 2, 2);
        assert_eq!(matrix.element(1, 0), 0x43);
        assert_eq!(matrix.element(0, 1), 0x65);
    }

    #[test]
    #[should_panic(expected = "the oil matrix has a column of v elements for each oil variable")]
    fn bytesOfAnotherShapeAreRefused() {
        let _ = OilMatrix::<GF256>::new(&[0u8; 5], 2, 2);
    }
}
