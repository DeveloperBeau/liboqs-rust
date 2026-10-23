/// The field of a parameter set: the `_USE_GF16` choice of `params.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    /// GF(16), with two elements in a byte.
    gf16,
    /// GF(256), with one element in a byte.
    gf256,
}

impl Field {
    /// The elements of a byte.
    pub(crate) const fn elementsPerByte(self) -> usize {
        match self {
            Field::gf16 => 2,
            Field::gf256 => 1,
        }
    }
}
