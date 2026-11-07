/// The method of `poly_Rq_mul` in `poly_rq_mul.c` of a parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MultiplicationMethod {
    /// Toom-Cook in four parts with two layers of Karatsuba below, `toom4_k2x2_mul`. The
    /// interpolation divides by 2, 4 and 8, so the 16-bit result is exact modulo `2^13` and the
    /// bits above are the bits of this method.
    toomCook,
    /// Four layers of Karatsuba, `k2x4_mul`, for the modulus `2^14` of NTRU-HRSS-1373. The
    /// 16-bit result is the exact product modulo `2^16`.
    karatsuba,
}
