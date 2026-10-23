/// The two kinds of NTRU parameter sets, `NTRU_HPS` and `NTRU_HRSS` of `params.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Variant {
    /// NTRU-HPS: `g` and the message `m` have a fixed type, with `q / 16 - 1` coefficients 1
    /// and as many coefficients -1, and decryption checks the type of `m`.
    hps,
    /// NTRU-HRSS: `f` and `g` have independent coefficients with a nonnegative correlation, the
    /// message `m` has independent coefficients, and `g` has the factor `x - 1`.
    hrss,
}
