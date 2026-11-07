/// The fixed facts of one signature scheme, as the liboqs `OQS_SIG` structure gives them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureDescription {
    /// The liboqs name of the algorithm, such as `ML-DSA-65`.
    pub name: &'static str,
    /// The version of the specification that the implementation follows.
    pub algorithmVersion: &'static str,
    /// The NIST security level that the designers claim, from 1 to 5.
    pub claimedNISTLevel: u8,
    /// True when the scheme claims existential unforgeability (EUF-CMA).
    pub isEUFCMASecure: bool,
    /// True when the scheme claims strong unforgeability (SUF-CMA).
    pub isSUFCMASecure: bool,
    /// True when the scheme signs with a context string.
    pub supportsContext: bool,
    /// The length of a public key in bytes.
    pub publicKeyLength: usize,
    /// The length of a secret key in bytes.
    pub secretKeyLength: usize,
    /// The largest length of a signature in bytes.
    pub signatureLength: usize,
}
