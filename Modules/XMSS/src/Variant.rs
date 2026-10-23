/// The two constructions of RFC 8391: XMSS, with one tree, and XMSS^MT, with a hypertree of
/// layers of trees.
///
/// Each construction has its own table of object identifiers in `params.c`, so the same number
/// names one set of XMSS and another set of XMSS^MT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Variant {
    /// XMSS, whose object identifiers `xmss_parse_oid` reads.
    xmss,
    /// XMSS^MT, whose object identifiers `xmssmt_parse_oid` reads.
    xmssmt,
}
