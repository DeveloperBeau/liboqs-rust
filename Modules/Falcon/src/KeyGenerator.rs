use crate::encoding::{largePolynomialBits, smallPolynomialBits};
use crate::floatingPoint::FloatingPoint;
use crate::fourierTransform::FourierTransform;
use crate::keyRefusal::KeyRefusal;
use crate::modularPolynomial::ModularPolynomial;
use crate::ntruSolver::NTRUSolver;
use OQSNativeSHA3::SHAKEReader;
use alloc::vec::Vec;

/// The generation of a Falcon key from a SHAKE256 stream, `keygen` of `keygen.c` of the Falcon
/// code of PQClean.
///
/// The generator draws `f` and `g` from a discrete Gaussian distribution and keeps them when
/// their coefficients fit the encoding, when the norms of `(g, -f)` and of its orthogonalized
/// vector are within the bound `1.17 sqrt(q)`, when `f` is invertible modulo `q` and when the
/// NTRU equation has a small solution `F`. Each refused candidate draws the next bytes of the
/// same stream, as the C code does.
pub(crate) struct KeyGenerator;

/// The discrete Gaussian distribution of standard deviation `1.17 sqrt(q / 2048)`,
/// `gauss_1024_12289` of `keygen.c`: `P(x = 0)` and then `P(x >= k + 1 | x > 0)`, scaled by
/// `2^63`.
const gaussianTable: [u64; 27] = [
    1_283_868_770_400_643_928,
    6_416_574_995_475_331_444,
    4_078_260_278_032_692_663,
    2_353_523_259_288_686_585,
    1_227_179_971_273_316_331,
    575_931_623_374_121_527,
    242_543_240_509_105_209,
    91_437_049_221_049_666,
    30_799_446_349_977_173,
    9_255_276_791_179_340,
    2_478_152_334_826_140,
    590_642_893_610_164,
    125_206_034_929_641,
    23_590_435_911_403,
    3_948_334_035_941,
    586_753_615_614,
    77_391_054_539,
    9_056_793_210,
    940_121_950,
    86_539_696,
    7_062_824,
    510_971,
    32764,
    1862,
    94,
    4,
    0,
];

/// `q = 12289`.
const modulus: FloatingPoint = FloatingPoint::fromBits(4_667_981_563_525_332_992);

/// The bound `16822.4121 = 1.17^2 q` of the squared norm of the orthogonalized vector.
const orthogonalizedNormBound: FloatingPoint = FloatingPoint::fromBits(4_670_353_323_383_631_276);

/// The polynomials of a key: `f`, `g`, `F` and the public key `h`.
type KeyPolynomials = (Vec<i8>, Vec<i8>, Vec<i8>, Vec<u16>);

/// The bound of the squared norm of `(g, -f)`, an integer: `1.17^2 q` rounded up.
const squaredNormBound: u32 = 16823;

impl KeyGenerator {
    /// The polynomials `f`, `g` and `F` and the public key `h = g / f mod q` of a key of
    /// degree `2^logn`, from a finalized SHAKE256 stream.
    pub(crate) fn generatedKey(reader: &mut SHAKEReader, logn: u32) -> KeyPolynomials {
        loop {
            if let Ok(key) = Self::candidateKey(reader, logn) {
                return key;
            }
        }
    }

    /// The key of the next candidate pair `f` and `g` of the stream, or the reason why the
    /// generator refuses the pair, as one turn of the loop of `keygen` decides.
    fn candidateKey(reader: &mut SHAKEReader, logn: u32) -> Result<KeyPolynomials, KeyRefusal> {
        // The Gaussian sampler makes each resultant with X^N + 1 odd.
        let f = Self::gaussianPolynomial(reader, logn);
        let g = Self::gaussianPolynomial(reader, logn);
        if !Self::fitsSecretKeyEncoding(&f, &g, logn) {
            return Err(KeyRefusal::coefficientOutOfRange);
        }
        if !Self::isNormBelowBound(&f, &g) {
            return Err(KeyRefusal::normAboveBound);
        }
        if !Self::isOrthogonalizedNormBelowBound(&f, &g, logn) {
            return Err(KeyRefusal::orthogonalizedNormAboveBound);
        }
        let publicKey =
            ModularPolynomial::publicKey(&f, &g, logn).ok_or(KeyRefusal::notInvertible)?;
        let limit = (1i32 << (largePolynomialBits[logn as usize] - 1)) - 1;
        let bigF = NTRUSolver::solution(&f, &g, logn, limit).map_err(KeyRefusal::noSolution)?;
        Ok((f, g, bigF, publicKey))
    }

    /// True when every coefficient of `f` and `g` fits the trimmed encoding of the secret key:
    /// within `-(2^(bits - 1) - 1)..=2^(bits - 1) - 1` for the width of the degree.
    fn fitsSecretKeyEncoding(f: &[i8], g: &[i8], logn: u32) -> bool {
        let limit = 1i32 << (smallPolynomialBits[logn as usize] - 1);
        f.iter()
            .chain(g)
            .all(|value| (-limit + 1..limit).contains(&i32::from(*value)))
    }

    /// True when the squared norm of `(g, -f)` is below the bound. The norm saturates at
    /// `2^32 - 1` when a part of it reaches `2^31`, as in `keygen`.
    fn isNormBelowBound(f: &[i8], g: &[i8]) -> bool {
        let (fNorm, gNorm) = (Self::squaredNorm(f), Self::squaredNorm(g));
        let norm = fNorm.wrapping_add(gNorm) | ((fNorm | gNorm) >> 31).wrapping_neg();
        norm < squaredNormBound
    }

    /// True when the squared norm of the orthogonalized vector
    /// `(q adj(f), q adj(g)) / (f adj(f) + g adj(g))` is below the bound, computed in the
    /// emulated floating point of the C code.
    fn isOrthogonalizedNormBelowBound(f: &[i8], g: &[i8], logn: u32) -> bool {
        let n = 1usize << logn;
        let mut rt1: Vec<FloatingPoint> = f
            .iter()
            .map(|value| FloatingPoint::of(i64::from(*value)))
            .collect();
        let mut rt2: Vec<FloatingPoint> = g
            .iter()
            .map(|value| FloatingPoint::of(i64::from(*value)))
            .collect();
        let mut rt3 = alloc::vec![FloatingPoint::zero; n];
        FourierTransform::transform(&mut rt1, logn);
        FourierTransform::transform(&mut rt2, logn);
        FourierTransform::inverseNorm(&mut rt3, &rt1, &rt2, logn);
        FourierTransform::adjoint(&mut rt1, logn);
        FourierTransform::adjoint(&mut rt2, logn);
        FourierTransform::multiplyByConstant(&mut rt1, modulus, logn);
        FourierTransform::multiplyByConstant(&mut rt2, modulus, logn);
        FourierTransform::multiplyByAutoAdjoint(&mut rt1, &rt3, logn);
        FourierTransform::multiplyByAutoAdjoint(&mut rt2, &rt3, logn);
        FourierTransform::inverseTransform(&mut rt1, logn);
        FourierTransform::inverseTransform(&mut rt2, logn);
        let mut orthogonalizedNorm = FloatingPoint::zero;
        for (first, second) in rt1.iter().zip(&rt2) {
            orthogonalizedNorm = orthogonalizedNorm + first.squared();
            orthogonalizedNorm = orthogonalizedNorm + second.squared();
        }
        orthogonalizedNorm.isLessThan(orthogonalizedNormBound)
    }

    /// The next little-endian 64-bit value of the stream, as `get_rng_u64` does.
    fn nextWord(reader: &mut SHAKEReader) -> u64 {
        let mut bytes = [0u8; 8];
        reader.squeeze(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// One value of the discrete Gaussian distribution of the degree, as `mkgauss` does: the
    /// sum of `2^(10 - logn)` values of the table for degree 1024.
    fn gaussianValue(reader: &mut SHAKEReader, logn: u32) -> i32 {
        let mut total = 0i32;
        for _ in 0..1u32 << (10 - logn) {
            // The first word gives the sign and whether the value is zero, and the second word
            // the value, with no branch.
            let word = Self::nextWord(reader);
            let isNegative = (word >> 63) as u32;
            let word = word & !(1 << 63);
            let mut isFound = (word.wrapping_sub(gaussianTable[0]) >> 63) as u32;
            let mut value = 0u32;
            let word = Self::nextWord(reader) & !(1 << 63);
            for (index, threshold) in gaussianTable.iter().enumerate().skip(1) {
                let isBelow = ((word.wrapping_sub(*threshold) >> 63) as u32) ^ 1;
                value |= (index as u32) & (isBelow & (isFound ^ 1)).wrapping_neg();
                isFound |= isBelow;
            }
            value = (value ^ isNegative.wrapping_neg()).wrapping_add(isNegative);
            total = total.wrapping_add(value as i32);
        }
        total
    }

    /// A polynomial of Gaussian coefficients in `-127..=127` whose coefficients have an odd
    /// sum, so that its resultant with `X^N + 1` is odd, as `poly_small_mkgauss` does.
    fn gaussianPolynomial(reader: &mut SHAKEReader, logn: u32) -> Vec<i8> {
        let n = 1usize << logn;
        let mut polynomial = Vec::with_capacity(n);
        let mut parity = 0u32;
        while polynomial.len() < n {
            let value = Self::gaussianValue(reader, logn);
            if !(-127..=127).contains(&value) {
                continue;
            }
            let bit = (value & 1) as u32;
            if polynomial.len() == n - 1 {
                if parity ^ bit == 0 {
                    continue;
                }
            } else {
                parity ^= bit;
            }
            polynomial.push(value as i8);
        }
        polynomial
    }

    /// The squared norm of a small polynomial, saturated at `2^32 - 1` once it reaches `2^31`,
    /// as `poly_small_sqnorm` does.
    fn squaredNorm(polynomial: &[i8]) -> u32 {
        let mut norm = 0u32;
        let mut overflow = 0u32;
        for value in polynomial {
            let value = i32::from(*value);
            norm = norm.wrapping_add((value * value) as u32);
            overflow |= norm;
        }
        norm | (overflow >> 31).wrapping_neg()
    }
}

#[cfg(test)]
mod tests {
    use super::KeyGenerator;
    use crate::keyRefusal::KeyRefusal;
    use crate::modularPolynomial::ModularPolynomial;
    use crate::solverFailure::SolverFailure;
    use OQSNativeSHA3::SHAKE256;

    /// The FNV-1a hash of bytes, the digest that the C program of the known answers prints.
    fn digest(bytes: impl IntoIterator<Item = u8>) -> u64 {
        bytes
            .into_iter()
            .fold(0xCBF2_9CE4_8422_2325u64, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01B3)
            })
    }

    /// Known answers of `keygen` of the C library for the stream SHAKE256("K" || logn) at each
    /// degree: the digests of f, g, F, G and h. The degrees 2 and 4 take the general solver down
    /// to the top level, and the others the binary code of the two top levels.
    const keyDigests: [(u32, [u64; 5]); 10] = [
        (
            1,
            [
                0x0ABF_E107_B717_3F68,
                0x0AD0_4407_B724_A7D4,
                0x0843_3B07_B4F9_6049,
                0x09A5_3E07_B626_A2BA,
                0x95C1_1B59_E3F3_B22A,
            ],
        ),
        (
            2,
            [
                0x3B20_602B_FC52_13F6,
                0x5A21_87B0_F23E_694A,
                0xF3CF_7F47_7FE6_0BE0,
                0x7312_9587_E303_9E3B,
                0x85FD_9F16_0709_E81C,
            ],
        ),
        (
            3,
            [
                0x173D_F687_40AC_CBCC,
                0x090A_28AE_F20A_93FE,
                0xA0DA_C9AC_7BB1_8EDC,
                0xEBC2_B65B_3CE2_B827,
                0x36AB_84AB_4577_605B,
            ],
        ),
        (
            4,
            [
                0xBFBC_3836_FD6D_AFF6,
                0xA056_1D71_4DB3_9102,
                0xFDBA_CFCC_6C4B_67B9,
                0x6474_ED9D_7D22_4582,
                0x540B_07B3_1637_81CC,
            ],
        ),
        (
            5,
            [
                0x8559_6066_E3FD_4818,
                0x2747_3FB7_05C1_4410,
                0xAF1B_9073_1E54_0B81,
                0x04F0_6CF8_918C_52AC,
                0x68F3_14A3_79F7_7B16,
            ],
        ),
        (
            6,
            [
                0x9D0D_2739_04F4_67FA,
                0x6288_80E0_95ED_5F1E,
                0xAF03_93C1_92FE_079D,
                0xB9BA_E9F4_BFEA_D8BE,
                0x00AC_9B91_DBBC_0BA8,
            ],
        ),
        (
            7,
            [
                0xC78D_AB4A_6F38_2A62,
                0x6577_4769_8203_E7A0,
                0xACE7_B1E2_566F_4150,
                0x4182_AB7C_FB68_E203,
                0x8D00_EBA1_CF86_901C,
            ],
        ),
        (
            8,
            [
                0x171B_0439_500D_2150,
                0xFE5B_4315_BF63_E252,
                0xDD19_B931_2163_245D,
                0xF317_6C9B_03C4_B19A,
                0xB63A_8972_3F8D_F4D5,
            ],
        ),
        (
            9,
            [
                0x582E_4136_933E_235E,
                0x03E1_3CB5_F3B3_7F5C,
                0x682F_27F3_3D6E_FAFD,
                0xE14D_C6B1_8444_6A8C,
                0xE1FD_FC42_AB31_F18E,
            ],
        ),
        (
            10,
            [
                0xB47C_99F7_61A8_3A3E,
                0x38EE_A3B4_DBDE_D3DE,
                0x08BF_5CC5_1715_6CD9,
                0xDEE0_3E16_C8FA_3CCC,
                0xBD13_7DE1_4FE9_8548,
            ],
        ),
    ];

    #[test]
    fn keysOfEveryDegreeAreTheKeysOfTheCCode() {
        for (logn, [fDigest, gDigest, bigFDigest, bigGDigest, publicDigest]) in keyDigests {
            let mut reader = SHAKE256::absorbOnce(&[b'K', logn as u8]);
            let (f, g, bigF, publicKey) = KeyGenerator::generatedKey(&mut reader, logn);
            let bytes = |values: &[i8]| digest(values.iter().map(|value| *value as u8));
            assert_eq!(bytes(&f), fDigest, "f, logn {logn}");
            assert_eq!(bytes(&g), gDigest, "g, logn {logn}");
            assert_eq!(bytes(&bigF), bigFDigest, "F, logn {logn}");
            let bigG = ModularPolynomial::completedSecretPolynomial(&f, &g, &bigF, logn)
                .expect("G of a generated key");
            assert_eq!(bytes(&bigG), bigGDigest, "G, logn {logn}");
            assert_eq!(
                digest(publicKey.iter().flat_map(|value| value.to_le_bytes())),
                publicDigest,
                "h, logn {logn}"
            );
        }
    }

    /// The decisions of the loop of `keygen` of the C library for the streams
    /// SHAKE256("K" || logn || index), one letter for each candidate pair, then the digests of
    /// F and h of the accepted key. The letters are `R` for a coefficient out of range, `N`
    /// for the norm, `O` for the orthogonalized norm, `P` for an `f` that is not invertible, a
    /// digit for the step of `solve_NTRU` that fails, and `A` for the accepted pair. The steps
    /// are 1 for the deepest level, 2 for an intermediate level, 3 for depth 1, 5 for F out of
    /// range, 6 for G out of range and 7 for the equation. Depth 0 has no failure.
    const decisionSequences: [(u32, u8, &str, u64, u64); 10] = [
        (
            1,
            12,
            "O5OONN1NNA",
            0x0AA9_BB07_B702_EFCC,
            0xC1A6_61BC_152F_EC03,
        ),
        (
            1,
            78,
            "N6NNOA",
            0x0821_C107_B4DD_5D95,
            0xAA15_9D51_F36B_33ED,
        ),
        (
            2,
            49,
            "ONNPON1NNOA",
            0x7262_EFAD_EF19_96F3,
            0xA959_CCBE_D346_BBC3,
        ),
        (4, 7, "PNA", 0x5DDA_8E0F_B490_4173, 0x8D93_3CBD_81EB_045E),
        (5, 4, "NON2NA", 0x9E08_3809_E7C9_7BF7, 0xE36F_D6F1_1A34_9ADF),
        (
            9,
            24,
            "OONN2NOONONPA",
            0x17DC_8CE9_951C_E1E2,
            0xC5CC_90F4_C047_6687,
        ),
        (
            9,
            100,
            "N1NNNONONOONA",
            0xF6DC_ABF6_986F_CA1E,
            0x0504_7D59_7512_C8AF,
        ),
        (
            9,
            193,
            "NNN26NOOOONNNNNOOA",
            0x3980_6A1E_8EBA_8789,
            0xD2F5_B7E3_A56B_DC6F,
        ),
        (
            10,
            42,
            "ONNNO5A",
            0xF3EC_0368_DE8D_4C93,
            0x9CE3_4200_07AC_8067,
        ),
        (
            10,
            166,
            "ONNNRNNOOA",
            0x9948_3E2C_DAE4_521B,
            0x6805_2D35_C6D4_DAB9,
        ),
    ];

    /// The letter of `decisionSequences` for a decision of the generator.
    fn letter<Key>(decision: &Result<Key, KeyRefusal>) -> char {
        match decision {
            Ok(_) => 'A',
            Err(KeyRefusal::coefficientOutOfRange) => 'R',
            Err(KeyRefusal::normAboveBound) => 'N',
            Err(KeyRefusal::orthogonalizedNormAboveBound) => 'O',
            Err(KeyRefusal::notInvertible) => 'P',
            Err(KeyRefusal::noSolution(SolverFailure::deepest)) => '1',
            Err(KeyRefusal::noSolution(SolverFailure::intermediate)) => '2',
            Err(KeyRefusal::noSolution(SolverFailure::depthOne)) => '3',
            Err(KeyRefusal::noSolution(SolverFailure::bigFOutOfRange)) => '5',
            Err(KeyRefusal::noSolution(SolverFailure::bigGOutOfRange)) => '6',
            Err(KeyRefusal::noSolution(SolverFailure::equationNotSatisfied)) => '7',
        }
    }

    #[test]
    fn eachCandidateIsRefusedOrAcceptedAsTheCCodeDecides() {
        for (logn, index, decisions, bigFDigest, publicDigest) in decisionSequences {
            let seed = [b'K', logn as u8, index];
            let mut reader = SHAKE256::absorbOnce(&seed);
            let mut letters = String::new();
            let (_, _, bigF, publicKey) = loop {
                let decision = KeyGenerator::candidateKey(&mut reader, logn);
                letters.push(letter(&decision));
                if let Ok(key) = decision {
                    break key;
                }
            };
            assert_eq!(letters, decisions, "logn {logn}, index {index}");
            let bytes = |values: &[i8]| digest(values.iter().map(|value| *value as u8));
            assert_eq!(bytes(&bigF), bigFDigest, "F, logn {logn}, index {index}");
            assert_eq!(
                digest(publicKey.iter().flat_map(|value| value.to_le_bytes())),
                publicDigest,
                "h, logn {logn}, index {index}"
            );
            let (_, _, generated, _) =
                KeyGenerator::generatedKey(&mut SHAKE256::absorbOnce(&seed), logn);
            assert_eq!(generated, bigF, "logn {logn}, index {index}");
        }
    }

    #[test]
    fn coefficientsFitTheEncodingUpToOneBelowTheLimitOfTheirWidth() {
        // The widths are 8 bits up to degree 32, then 7, 7, 6, 6 and 5 bits.
        for (logn, largest) in [(1u32, 127i8), (5, 127), (6, 63), (8, 31), (9, 31), (10, 15)] {
            let n = 1usize << logn;
            let mut f = vec![0i8; n];
            let mut g = vec![0i8; n];
            f[0] = largest;
            f[n - 1] = -largest;
            g[1] = largest;
            assert!(
                KeyGenerator::fitsSecretKeyEncoding(&f, &g, logn),
                "logn {logn}"
            );
            if largest < 127 {
                f[0] = largest + 1;
                assert!(
                    !KeyGenerator::fitsSecretKeyEncoding(&f, &g, logn),
                    "logn {logn}"
                );
                f[0] = largest;
                g[1] = -largest - 1;
                assert!(
                    !KeyGenerator::fitsSecretKeyEncoding(&f, &g, logn),
                    "logn {logn}"
                );
            } else {
                g[1] = -128;
                assert!(
                    !KeyGenerator::fitsSecretKeyEncoding(&f, &g, logn),
                    "logn {logn}"
                );
            }
        }
    }

    #[test]
    fn theNormOfThePairIsBelowTheBoundUpTo16822() {
        // 127^2 + 26^2 + 4^2 + 1^2 = 16822, in f alone or across f and g.
        assert!(KeyGenerator::isNormBelowBound(&[127, 26, 4, 1], &[0; 4]));
        assert!(KeyGenerator::isNormBelowBound(
            &[127, 0, 0, 0],
            &[26, -4, 1, 0]
        ));
        assert!(!KeyGenerator::isNormBelowBound(
            &[127, 26, 4, 1],
            &[1, 0, 0, 0]
        ));
        assert!(!KeyGenerator::isNormBelowBound(
            &[-127, -127, 0, 0],
            &[0; 4]
        ));
        // A saturated part gives a saturated norm, though the sum of the parts wraps to 0.
        let saturated = vec![-128i8; 1 << 17];
        let mut small = vec![0i8; 1 << 17];
        small[0] = 1;
        assert_eq!(KeyGenerator::squaredNorm(&saturated), u32::MAX);
        assert!(!KeyGenerator::isNormBelowBound(&saturated, &small));
        assert!(!KeyGenerator::isNormBelowBound(&small, &saturated));
    }

    #[test]
    fn gaussianPolynomialsHaveAnOddSumAndSmallSquaredNorms() {
        for logn in [1u32, 5, 9, 10] {
            let mut reader = SHAKE256::absorbOnce(b"Gaussian");
            for _ in 0..4 {
                let polynomial = KeyGenerator::gaussianPolynomial(&mut reader, logn);
                assert_eq!(polynomial.len(), 1 << logn);
                let sum: i32 = polynomial.iter().map(|value| i32::from(*value)).sum();
                assert_eq!(sum.rem_euclid(2), 1, "logn {logn}");
            }
        }
        assert_eq!(KeyGenerator::squaredNorm(&[3, -4, 0, 1]), 26);
        // 512 coefficients of -127 give 8258048, and 2^31 or more saturates.
        assert_eq!(KeyGenerator::squaredNorm(&[-127; 512]), 512 * 127 * 127);
        assert_eq!(KeyGenerator::squaredNorm(&vec![-128i8; 1 << 17]), u32::MAX);
    }
}
