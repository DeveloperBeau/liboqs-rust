/// The hard problem of a CROSS parameter set, with the arithmetic of its two rings.
///
/// RSDP works in F_127 with the restricted group of the powers of 2, which has the order 7.
/// RSDP(G) works in F_509 with the restricted group of the powers of 16, which has the order
/// 127. A restricted element is stored as its exponent, an integer modulo the order of the
/// group. The functions are the macros of `fp_arith.h` and `restr_arith.h` of the C code. Where
/// a modulus is a Mersenne number `2^b - 1`, the C code reduces with a fold of the high bits, and
/// the result keeps `2^b - 1` as a second form of zero until a normalization replaces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Problem {
    /// The restricted syndrome decoding problem, `RSDP`: p = 127 and z = 7.
    rsdp,
    /// The restricted syndrome decoding problem in a subgroup, `RSDPG`: p = 509 and z = 127.
    rsdpg,
}

/// The powers of 2 in F_127, `RESTR_G_TABLE` of RSDP: byte `e` holds `2^e`. Byte 7 holds
/// `2^7 = 1`, so the second form of a zero exponent needs no reduction.
const rsdpPowerTable: u64 = 0x0140_2010_0804_0201;

/// The squares `16^(2^i)` modulo 509 for i from 0 to 6, `RESTR_G_GEN_1` to `RESTR_G_GEN_64`
/// of RSDP(G).
const rsdpgGeneratorSquares: [u32; 7] = [16, 256, 384, 355, 302, 93, 505];

/// The value `16^e` in F_509 of each exponent of 7 bits, as `RESTR_TO_VAL` of RSDP(G) computes
/// it.
const rsdpgPowers: [u16; 128] = rsdpgPowerTable();

/// The factor of one bit of an exponent in `RESTR_TO_VAL` of RSDP(G), `FP_ELEM_CMOV`: the
/// square of the bit when the bit is set, and 1 when it is not.
const fn rsdpgFactor(exponent: usize, bit: usize) -> u32 {
    if (exponent >> bit) & 1 == 1 {
        rsdpgGeneratorSquares[bit]
    } else {
        1
    }
}

/// The table of `rsdpgPowers`, with the products and the two intermediate reductions of
/// `RESTR_TO_VAL` of RSDP(G).
const fn rsdpgPowerTable() -> [u16; 128] {
    let mut table = [0u16; 128];
    let mut exponent = 0;
    while exponent < 128 {
        let first = rsdpgFactor(exponent, 0) * rsdpgFactor(exponent, 1);
        let second = rsdpgFactor(exponent, 2) * rsdpgFactor(exponent, 3);
        let third = rsdpgFactor(exponent, 4) * rsdpgFactor(exponent, 5);
        let fourth = rsdpgFactor(exponent, 6);
        let low = Problem::rsdpgReduced(first * second);
        let high = Problem::rsdpgReduced(third * fourth);
        table[exponent] = Problem::rsdpgReduced(low * high) as u16;
        exponent += 1;
    }
    table
}

/// The number of bits of a value, `BITS_TO_REPRESENT` of `parameters.h`: 1 for zero.
pub(crate) const fn bitLength(value: usize) -> u32 {
    if value == 0 {
        1
    } else {
        usize::BITS - value.leading_zeros()
    }
}

impl Problem {
    /// The prime p of the field, `P`.
    pub(crate) const fn prime(self) -> u32 {
        match self {
            Problem::rsdp => 127,
            Problem::rsdpg => 509,
        }
    }

    /// The order z of the restricted group, `Z`: the modulus of the exponents.
    pub(crate) const fn restrictedOrder(self) -> u32 {
        match self {
            Problem::rsdp => 7,
            Problem::rsdpg => 127,
        }
    }

    /// The bits of a packed element of the field, `BITS_TO_REPRESENT(P - 1)`.
    pub(crate) const fn fieldBits(self) -> u32 {
        bitLength(self.prime() as usize - 1)
    }

    /// The bits of a packed exponent, `BITS_TO_REPRESENT(Z - 1)`.
    pub(crate) const fn restrictedBits(self) -> u32 {
        bitLength(self.restrictedOrder() as usize - 1)
    }

    /// The bits of a candidate of the first challenge, `BITS_TO_REPRESENT(P - 2)`.
    pub(crate) const fn challengeBits(self) -> u32 {
        bitLength(self.prime() as usize - 2)
    }

    /// `FPRED_SINGLE` of RSDP: the fold of the bits above 7 onto the low bits, which keeps the
    /// value modulo 127.
    pub(crate) const fn rsdpReducedOnce(value: u32) -> u32 {
        (value & 0x7F) + (value >> 7)
    }

    /// `FPRED_DOUBLE` of RSDP: two folds, which bring a value below 2^14 to at most 127.
    pub(crate) const fn rsdpReduced(value: u32) -> u32 {
        Self::rsdpReducedOnce(Self::rsdpReducedOnce(value))
    }

    /// `FPRED_SINGLE` of RSDP(G): the exact remainder modulo 509 of any 32-bit value, by the
    /// multiplication of Hacker's Delight, Figure 10-4, in 64 bits.
    pub(crate) const fn rsdpgReduced(value: u32) -> u32 {
        let wide = value as u64;
        (wide - ((wide * 2_160_140_723) >> 40) * 509) as u32
    }

    /// One reduction step modulo p, `FPRED_SINGLE`.
    pub(crate) const fn reducedOnce(self, value: u32) -> u32 {
        match self {
            Problem::rsdp => Self::rsdpReducedOnce(value),
            Problem::rsdpg => Self::rsdpgReduced(value),
        }
    }

    /// The reduction modulo p of a sum of products, `FPRED_DOUBLE`.
    pub(crate) const fn reduced(self, value: u32) -> u32 {
        match self {
            Problem::rsdp => Self::rsdpReduced(value),
            Problem::rsdpg => Self::rsdpgReduced(value),
        }
    }

    /// The negation modulo p of a reduced value, `FPRED_OPPOSITE`: `127 - x` by an exclusive
    /// or for RSDP, and `509 - x` reduced for RSDP(G).
    pub(crate) const fn negated(self, value: u32) -> u32 {
        match self {
            Problem::rsdp => value ^ 0x7F,
            Problem::rsdpg => Self::rsdpgReduced(509 - value),
        }
    }

    /// The canonical form of a reduced value, `FP_DOUBLE_ZERO_NORM`: 127 becomes 0 for RSDP. The
    /// field of RSDP(G) has one form of zero, so its values stay as they are.
    pub(crate) const fn normalized(self, value: u32) -> u32 {
        match self {
            Problem::rsdp => (value + ((value + 1) >> 7)) & 0x7F,
            Problem::rsdpg => value,
        }
    }

    /// The field element `g^e` of an exponent e, `RESTR_TO_VAL`. The exponents of RSDP have 3
    /// bits and those of RSDP(G) have 7 bits, the bits that the C code reads.
    pub(crate) const fn restrictedValue(self, exponent: u8) -> u32 {
        match self {
            Problem::rsdp => ((rsdpPowerTable >> (8 * (exponent & 0x07) as u32)) & 0xFF) as u32,
            Problem::rsdpg => rsdpgPowers[(exponent & 0x7F) as usize] as u32,
        }
    }

    /// One reduction step of an exponent modulo z, `FZRED_SINGLE`: the fold of the bits above
    /// 3 for RSDP and above 7 for RSDP(G).
    pub(crate) const fn exponentReducedOnce(self, value: u32) -> u32 {
        (value & self.restrictedOrder()) + (value >> self.restrictedBits())
    }

    /// The reduction of a sum of products of exponents modulo z, `FZRED_DOUBLE`.
    pub(crate) const fn exponentReduced(self, value: u32) -> u32 {
        self.exponentReducedOnce(self.exponentReducedOnce(value))
    }

    /// The negation of a reduced exponent modulo z, `FZRED_OPPOSITE`: `z - e` by an exclusive or.
    pub(crate) const fn exponentNegated(self, value: u32) -> u32 {
        value ^ self.restrictedOrder()
    }

    /// The canonical form of a reduced exponent, `FZ_DOUBLE_ZERO_NORM`: z becomes 0.
    pub(crate) const fn exponentNormalized(self, value: u32) -> u32 {
        (value + ((value + 1) >> self.restrictedBits())) & self.restrictedOrder()
    }
}

#[cfg(test)]
mod tests {
    use super::{Problem, bitLength, rsdpgPowers};

    /// The power of a base modulo a prime by repeated multiplication.
    fn power(base: u64, exponent: u32, prime: u64) -> u64 {
        (0..exponent).fold(1, |product, _| product * base % prime)
    }

    #[test]
    fn eachProblemHasTheConstantsOfItsParameterHeader() {
        // `parameters.h` of RSDP and of RSDP(G), and the bit widths of BITS_TO_REPRESENT.
        assert_eq!(
            (
                Problem::rsdp.prime(),
                Problem::rsdp.restrictedOrder(),
                Problem::rsdp.fieldBits(),
                Problem::rsdp.restrictedBits(),
                Problem::rsdp.challengeBits()
            ),
            (127, 7, 7, 3, 7)
        );
        assert_eq!(
            (
                Problem::rsdpg.prime(),
                Problem::rsdpg.restrictedOrder(),
                Problem::rsdpg.fieldBits(),
                Problem::rsdpg.restrictedBits(),
                Problem::rsdpg.challengeBits()
            ),
            (509, 127, 9, 7, 9)
        );
    }

    #[test]
    fn bitLengthIsTheBitsToRepresentOfTheCHeader() {
        // BITS_TO_REPRESENT gives 1 for zero and the length of the binary form otherwise.
        let expected = [
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 3),
            (6, 3),
            (7, 3),
            (8, 4),
            (126, 7),
            (127, 7),
            (128, 8),
            (255, 8),
            (256, 9),
            (508, 9),
            (511, 9),
            (512, 10),
            (831, 10),
        ];
        for (value, bits) in expected {
            assert_eq!(bitLength(value), bits, "{value}");
        }
    }

    #[test]
    fn theRestrictedValuesArePowersOfTheGeneratorOfEachGroup() {
        // RSDP: g = 2 of order 7 in F_127, so exponent 7 is a second form of zero.
        for exponent in 0..8u8 {
            assert_eq!(
                u64::from(Problem::rsdp.restrictedValue(exponent)),
                power(2, u32::from(exponent), 127),
                "{exponent}"
            );
        }
        assert_eq!(Problem::rsdp.restrictedValue(7), 1);
        // RSDP(G): g = 16 of order 127 in F_509, so exponent 127 is a second form of zero.
        for exponent in 0..128u8 {
            assert_eq!(
                u64::from(Problem::rsdpg.restrictedValue(exponent)),
                power(16, u32::from(exponent), 509),
                "{exponent}"
            );
        }
        assert_eq!(Problem::rsdpg.restrictedValue(127), 1);
        assert_eq!(power(16, 127, 509), 1);
        assert_ne!(power(16, 1, 509), 1);
        // The precomputed squares of the comment of `fp_arith.h` for the exponents 2^i.
        let squares: Vec<u16> = [0usize, 1, 2, 4, 8, 16, 32, 64]
            .iter()
            .map(|exponent| rsdpgPowers[*exponent])
            .collect();
        assert_eq!(squares, vec![1, 16, 256, 384, 355, 302, 93, 505]);
    }

    #[test]
    fn theRSDPGReductionIsTheRemainderOfEveryThirtyTwoBitValue() {
        // Hacker's Delight states the multiplication for every 32-bit value. The test checks
        // each remainder near zero, near the multiples of the edges, and seeded values.
        let mut state = 0x4352_4F53_u64;
        let seeded = (0..200_000).map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (state >> 32) as u32
        });
        let edges = (0..5000u32)
            .chain(u32::MAX - 5000..=u32::MAX)
            .chain((1..50u32).flat_map(|multiple| {
                let base = multiple * 509 * 170_000;
                [base - 1, base, base + 1]
            }));
        for value in edges.chain(seeded) {
            assert_eq!(Problem::rsdpgReduced(value), value % 509, "{value}");
        }
    }

    #[test]
    fn theRSDPFoldsKeepTheValueModulo127AndReachAtMost127() {
        for value in 0..(1u32 << 14) {
            let once = Problem::rsdpReducedOnce(value);
            let twice = Problem::rsdpReduced(value);
            assert_eq!(once % 127, value % 127, "{value}");
            assert_eq!(twice % 127, value % 127, "{value}");
            assert!(twice <= 127, "{value}");
        }
        // 127 is the second form of zero, and the fold keeps it.
        assert_eq!(Problem::rsdpReduced(127), 127);
        assert_eq!(Problem::rsdpReduced(254), 127);
        assert_eq!(Problem::rsdpReduced(16_256), 127);
        assert_eq!(Problem::rsdpReduced(128), 1);
    }

    #[test]
    fn normalizationReplacesOnlyTheSecondFormOfZero() {
        for value in 0..127 {
            assert_eq!(Problem::rsdp.normalized(value), value);
        }
        assert_eq!(Problem::rsdp.normalized(127), 0);
        for value in [0, 1, 126, 127, 508] {
            assert_eq!(Problem::rsdpg.normalized(value), value);
        }
        for value in 0..7 {
            assert_eq!(Problem::rsdp.exponentNormalized(value), value);
        }
        assert_eq!(Problem::rsdp.exponentNormalized(7), 0);
        for value in 0..127 {
            assert_eq!(Problem::rsdpg.exponentNormalized(value), value);
        }
        assert_eq!(Problem::rsdpg.exponentNormalized(127), 0);
    }

    #[test]
    fn negationIsTheOppositeModuloTheFieldAndTheGroupOrder() {
        for problem in [Problem::rsdp, Problem::rsdpg] {
            let prime = problem.prime();
            for value in 0..prime {
                let negated = problem.negated(value);
                assert_eq!((value + negated) % prime, 0, "{problem:?} {value}");
                assert_eq!(problem.reducedOnce(value + negated) % prime, 0);
            }
            let order = problem.restrictedOrder();
            for value in 0..order {
                assert_eq!(
                    (value + problem.exponentNegated(value)) % order,
                    0,
                    "{problem:?} {value}"
                );
            }
        }
        // The exclusive or of RSDP gives 127 for 0, the second form of zero, and the
        // reduction of RSDP(G) gives 0 for 0.
        assert_eq!(Problem::rsdp.negated(0), 127);
        assert_eq!(Problem::rsdpg.negated(0), 0);
        assert_eq!(Problem::rsdpg.negated(508), 1);
        assert_eq!(Problem::rsdp.exponentNegated(0), 7);
    }

    #[test]
    fn theExponentFoldsKeepTheValueModuloTheGroupOrder() {
        for problem in [Problem::rsdp, Problem::rsdpg] {
            let order = problem.restrictedOrder();
            // The largest value that the products of `fz_inf_w_by_fz_matrix` reach.
            for value in 0..(127 + 127 * 126 + 1) {
                assert_eq!(
                    problem.exponentReducedOnce(value) % order,
                    value % order,
                    "{problem:?} {value}"
                );
            }
            // A difference of two exponents, `a + (z - b)`, needs one fold.
            for first in 0..order {
                for second in 0..order {
                    let folded =
                        problem.exponentReducedOnce(first + problem.exponentNegated(second));
                    assert!(folded <= order && folded >= 1, "{problem:?}");
                    assert_eq!(folded % order, (first + order - second) % order);
                }
            }
        }
        for value in 0..(127 + 127 * 126 + 1) {
            assert!(Problem::rsdpg.exponentReduced(value) <= 127, "{value}");
        }
        assert_eq!(Problem::rsdp.exponentReducedOnce(13), 6);
        // 127 * 127 is zero modulo 127, and the folds give its second form.
        assert_eq!(Problem::rsdpg.exponentReduced(16_129), 127);
        assert_eq!(Problem::rsdpg.exponentReduced(16_130), 1);
    }

    #[test]
    fn eachOperationOfTheFieldTakesTheFormOfItsProblem() {
        // 300 is above 127, so each problem reduces it in its own way.
        assert_eq!(Problem::rsdp.reducedOnce(300), (300 & 0x7F) + (300 >> 7));
        assert_eq!(Problem::rsdpg.reducedOnce(300), 300);
        assert_eq!(Problem::rsdp.reduced(16_256), 127);
        assert_eq!(Problem::rsdpg.reduced(16_256), 16_256 % 509);
        assert_eq!(Problem::rsdpg.reducedOnce(1018), 0);
    }
}
