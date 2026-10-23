use crate::Problem;

/// The code of a CROSS problem at one security level, from `parameters.h`: the lengths of the
/// code and of the subgroup, and the random bits of the samplers of the key material and of the
/// vectors of a round. The three trade-offs of a problem and a level share it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CodeParameters {
    /// RSDP or RSDP(G).
    pub(crate) problem: Problem,
    /// The security parameter lambda in bits, `SEC_MARGIN_LAMBDA`.
    pub(crate) securityBits: usize,
    /// The length n of the code, `N`.
    pub(crate) length: usize,
    /// The dimension k of the code, `K`.
    pub(crate) dimension: usize,
    /// The dimension m of the subgroup G of RSDP(G), `M`, and 0 for RSDP.
    pub(crate) subgroupDimension: usize,
    /// The random bits of n elements of the field, `BITS_N_FP_CT_RNG`.
    pub(crate) fieldVectorRandomBits: usize,
    /// The random bits of the matrix V, `BITS_V_CT_RNG`.
    pub(crate) parityMatrixRandomBits: usize,
    /// The random bits of a restricted vector: of n exponents for RSDP, `BITS_N_FZ_CT_RNG`, and
    /// of m exponents for RSDP(G), `BITS_M_FZ_CT_RNG`.
    pub(crate) restrictedVectorRandomBits: usize,
    /// The random bits of the matrix W of RSDP(G), `BITS_W_CT_RNG`, and 0 for RSDP.
    pub(crate) subgroupMatrixRandomBits: usize,
}
