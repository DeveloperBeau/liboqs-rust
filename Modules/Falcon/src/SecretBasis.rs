/// The secret basis `[[g, -f], [G, -F]]` of a Falcon key: the four small polynomials `f`, `g`,
/// `F` and `G`, with `f G - g F = q mod X^N + 1`.
pub(crate) struct SecretBasis<'key> {
    /// The polynomial `f`.
    pub(crate) f: &'key [i8],
    /// The polynomial `g`.
    pub(crate) g: &'key [i8],
    /// The polynomial `F`.
    pub(crate) bigF: &'key [i8],
    /// The polynomial `G`.
    pub(crate) bigG: &'key [i8],
}
