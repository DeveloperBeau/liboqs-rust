use crate::solverFailure::SolverFailure;

/// The reason why the key generator refuses a candidate pair `f` and `g`, after which `keygen`
/// of `keygen.c` draws the next pair from the same stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyRefusal {
    /// A coefficient of `f` or `g` does not fit the encoding of the secret key.
    coefficientOutOfRange,
    /// The squared norm of `(g, -f)` is at or above the bound.
    normAboveBound,
    /// The squared norm of the orthogonalized vector is at or above the bound.
    orthogonalizedNormAboveBound,
    /// `f` is not invertible modulo `q`, so the public key `g / f` does not exist.
    notInvertible,
    /// The NTRU equation has no small solution.
    noSolution(SolverFailure),
}
