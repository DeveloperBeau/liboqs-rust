/// The hash functions that instantiate a parameter set of SLH-DSA, FIPS 205, Section 11.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HashFamily {
    /// SHAKE256 for every function, FIPS 205, Section 11.1.
    shake,
    /// SHA-256 and HMAC-SHA-256 for security category 1, and SHA-512 and HMAC-SHA-512 for the
    /// message functions, `H` and `T_l` of categories 3 and 5, FIPS 205, Sections 11.2.1 and
    /// 11.2.2.
    sha2,
}
