/// The step at which the solver of the NTRU equation finds no small solution, after which
/// `solve_NTRU` of `keygen.c` returns 0 and the key generator draws a new pair `f` and `g`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SolverFailure {
    /// The resultants of `f` and `g` with `X^N + 1` are not both odd and coprime, or their
    /// Bezout coefficients times `q` do not fit, in `solve_NTRU_deepest`.
    deepest,
    /// The reduction of `F` and `G` at a depth from 2 up goes out of range, in
    /// `solve_NTRU_intermediate`.
    intermediate,
    /// The reduction of `F` and `G` at depth 1 goes out of range, in
    /// `solve_NTRU_binary_depth1`. No known pair `f` and `g` reaches this step. Only deeper
    /// values that no deeper level gives reach it.
    depthOne,
    /// A coefficient of `F` is outside the limit.
    bigFOutOfRange,
    /// A coefficient of `G` is outside the limit.
    bigGOutOfRange,
    /// `f G - g F = q` does not hold modulo the first small prime.
    equationNotSatisfied,
}
