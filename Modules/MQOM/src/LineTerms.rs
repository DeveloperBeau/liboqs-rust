use alloc::vec::Vec;

/// The terms of the lines of a line commitment, for each repetition: `P_x(r) = x0 + r x` and
/// `P_u(r) = u0 + r u1`, as `BLC_Commit_default` gives them in its arrays x0, u0 and u1.
///
/// The slope x of P_x is the secret of the key, so the terms hold only x0, u0 and u1.
pub(crate) struct LineTerms {
    /// The constant term x0 of the line of x of each repetition: n extension elements.
    pub(crate) constantTermsOfX: Vec<Vec<u16>>,
    /// The constant term u0 of the line of u of each repetition: η extension elements.
    pub(crate) constantTermsOfU: Vec<Vec<u16>>,
    /// The slope u1 of the line of u of each repetition: η extension elements.
    pub(crate) slopesOfU: Vec<Vec<u16>>,
}
