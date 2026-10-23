/// The fixed facts of one stateful signature scheme, as the liboqs `OQS_SIG_STFL` structure
/// gives them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatefulSignatureDescription {
    /// The object identifier of the parameter set in its standard.
    pub objectIdentifier: u32,
    /// The liboqs name of the algorithm, such as `XMSS-SHA2_10_256`.
    pub name: &'static str,
    /// The version of the specification that the implementation follows.
    pub algorithmVersion: &'static str,
    /// True when the scheme claims existential unforgeability (EUF-CMA).
    pub isEUFCMASecure: bool,
    /// True when the scheme claims strong unforgeability (SUF-CMA).
    pub isSUFCMASecure: bool,
    /// The length of a public key in bytes.
    pub publicKeyLength: usize,
    /// The length of a secret key in bytes.
    pub secretKeyLength: usize,
    /// The length of a signature in bytes.
    pub signatureLength: usize,
}
