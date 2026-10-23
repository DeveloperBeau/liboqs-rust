use core::ops::{Add, Div, Mul, Neg, Sub};

/// A binary64 floating-point value whose arithmetic uses integer operations only.
///
/// This is the `fpr` type of the Falcon code of PQClean, `fpr.h` and `fpr.c`. The value keeps
/// the IEEE-754 binary64 layout in a 64-bit word: the sign in bit 63, the biased exponent in
/// bits 52 to 62 and the mantissa in the low 52 bits. Each operation rounds to the nearest
/// value, with ties to even, as the C code does, so a key and a signature are the same as with
/// the C library. A result that would be subnormal is zero, and no operation makes an infinity
/// or a NaN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FloatingPoint {
    bits: u64,
}

/// The mask of the 52 mantissa bits.
const mantissaMask: u64 = (1 << 52) - 1;

/// The mask of every bit but the sign bit.
const magnitudeMask: u64 = (1 << 63) - 1;

impl FloatingPoint {
    /// Zero.
    pub(crate) const zero: FloatingPoint = FloatingPoint::fromBits(0);
    /// One.
    pub(crate) const one: FloatingPoint = FloatingPoint::fromBits(4_607_182_418_800_017_408);
    /// Two.
    pub(crate) const two: FloatingPoint = FloatingPoint::fromBits(4_611_686_018_427_387_904);
    /// One half.
    pub(crate) const oneHalf: FloatingPoint = FloatingPoint::fromBits(4_602_678_819_172_646_912);
    /// `2^31`.
    pub(crate) const twoTo31: FloatingPoint = FloatingPoint::fromBits(4_746_794_007_248_502_784);
    /// `2^31 - 1`.
    pub(crate) const twoTo31MinusOne: FloatingPoint =
        FloatingPoint::fromBits(4_746_794_007_244_308_480);
    /// `-(2^31 - 1)`.
    pub(crate) const minusTwoTo31MinusOne: FloatingPoint =
        FloatingPoint::fromBits(13_970_166_044_099_084_288);
    /// `2^63 - 1`, which rounds to `2^63`.
    pub(crate) const twoTo63MinusOne: FloatingPoint =
        FloatingPoint::fromBits(4_890_909_195_324_358_656);
    /// `-(2^63 - 1)`, which rounds to `-2^63`.
    pub(crate) const minusTwoTo63MinusOne: FloatingPoint =
        FloatingPoint::fromBits(14_114_281_232_179_134_464);
    /// `2^63`.
    pub(crate) const twoTo63: FloatingPoint = FloatingPoint::fromBits(4_890_909_195_324_358_656);

    /// The value of a binary64 bit pattern.
    pub(crate) const fn fromBits(bits: u64) -> Self {
        FloatingPoint { bits }
    }

    /// The binary64 bit pattern of the value.
    #[cfg(test)]
    pub(crate) const fn bits(self) -> u64 {
        self.bits
    }

    /// The value of an integer, rounded to the nearest value, as `fpr_of` does. The integer
    /// must not be `-2^63`.
    pub(crate) fn of(integer: i64) -> Self {
        Self::scaled(integer, 0)
    }

    /// The value `integer * 2^scale`, rounded to the nearest value, as `fpr_scaled` does. The
    /// integer must not be `-2^63`.
    pub(crate) fn scaled(integer: i64, scale: i32) -> Self {
        // The sign and the absolute value: -i = 1 + !i.
        let sign = ((integer as u64) >> 63) as u32;
        let absolute = (integer ^ -i64::from(sign)).wrapping_add(i64::from(sign));
        let mut mantissa = absolute as u64;
        let mut exponent = 9 + scale;
        normalize64(&mut mantissa, &mut exponent);
        // Divide by 512, and keep each dropped bit in the sticky bit.
        mantissa |= u64::from(((mantissa as u32) & 0x1FF) + 0x1FF);
        mantissa >>= 9;
        // A zero integer makes the steps above wrong, so the value is cleared.
        let isNotZero = ((absolute | absolute.wrapping_neg()) as u64 >> 63) as u32;
        mantissa &= u64::from(isNotZero).wrapping_neg();
        exponent &= -(isNotZero as i32);
        Self::packed(sign, exponent, mantissa)
    }

    /// The value `(-1)^sign * mantissa * 2^exponent`, with `2^54 <= mantissa < 2^55` or a zero
    /// mantissa, rounded from its two low bits, as the `FPR` function of `fpr.h` does. The lowest
    /// bit of the mantissa is a sticky bit. An exponent below `-1076` gives zero.
    fn packed(sign: u32, exponent: i32, mantissa: u64) -> Self {
        let mut exponent = exponent.wrapping_add(1076);
        let isBelowRange = (exponent as u32) >> 31;
        let mantissa = mantissa & u64::from(isBelowRange).wrapping_sub(1);
        // A zero mantissa gives a zero exponent, and keeps the sign.
        let hasTopBit = (mantissa >> 54) as u32;
        exponent &= -(hasTopBit as i32);
        // The top bit of the mantissa increments the exponent by one, which is wanted.
        let bits = ((u64::from(sign) << 63) | (mantissa >> 2))
            .wrapping_add(u64::from(exponent as u32) << 52);
        // The low three bits 011, 110 and 111 round up, which rounds to nearest with ties to
        // even. A carry into the exponent is correct.
        let roundingBits = (mantissa as u32) & 7;
        FloatingPoint {
            bits: bits.wrapping_add(u64::from((0xC8u32 >> roundingBits) & 1)),
        }
    }

    /// The nearest integer, with ties to even, as `fpr_rint` does. The value must lie in
    /// `-(2^63 - 1)..=2^63 - 1`.
    pub(crate) fn roundedToNearest(self) -> i64 {
        let x = self.bits;
        // The mantissa as a 63-bit integer, then shifted right as the exponent needs.
        let mut mantissa = ((x << 10) | (1 << 62)) & magnitudeMask;
        let mut shift = 1085 - (((x >> 52) as i32) & 0x7FF);
        // A shift of 64 bits or more gives zero, which also covers a zero value.
        mantissa &= u64::from(((shift - 64) as u32) >> 31).wrapping_neg();
        shift &= 63;
        // The dropped bits and the lowest kept bit, folded into three bits with a sticky bit.
        let dropped = leftShift(mantissa, 63 - shift);
        let low = (dropped as u32) | (((dropped >> 32) as u32) & 0x1FFF_FFFF);
        let roundingBits = ((dropped >> 61) as u32) | ((low | low.wrapping_neg()) >> 31);
        mantissa = unsignedRightShift(mantissa, shift) + u64::from((0xC8u32 >> roundingBits) & 1);
        let sign = (x >> 63) as u32;
        ((mantissa as i64) ^ -i64::from(sign)).wrapping_add(i64::from(sign))
    }

    /// The largest integer that is not above the value, as `fpr_floor` does. The value must lie
    /// in `-(2^63 - 1)..=2^63 - 1`. Negative zero gives `-1`, as in the C code.
    pub(crate) fn roundedDown(self) -> i64 {
        let x = self.bits;
        let exponent = ((x >> 52) as i32) & 0x7FF;
        let sign = (x >> 63) as i64;
        let mut integer = (((x << 10) | (1 << 62)) & magnitudeMask) as i64;
        integer = (integer ^ -sign).wrapping_add(sign);
        let shift = 1085 - exponent;
        // An arithmetic shift rounds toward minus infinity for both signs.
        integer = signedRightShift(integer, shift & 63);
        // A shift of 64 bits or more gives 0 or -1.
        integer ^= (integer ^ -sign) & -i64::from(((63 - shift) as u32) >> 31);
        integer
    }

    /// The integer part, rounded toward zero, as `fpr_trunc` does. The value must lie in
    /// `-(2^63 - 1)..=2^63 - 1`.
    pub(crate) fn roundedTowardZero(self) -> i64 {
        let x = self.bits;
        let exponent = ((x >> 52) as i32) & 0x7FF;
        let mut magnitude = ((x << 10) | (1 << 62)) & magnitudeMask;
        let shift = 1085 - exponent;
        magnitude = unsignedRightShift(magnitude, shift & 63);
        // A shift of 64 bits or more gives zero, which also covers a zero value.
        magnitude &= u64::from(((shift - 64) as u32) >> 31).wrapping_neg();
        let sign = x >> 63;
        ((magnitude ^ sign.wrapping_neg()).wrapping_add(sign)) as i64
    }

    /// The value divided by two, as `fpr_half` does. Zero stays zero.
    pub(crate) fn halved(self) -> Self {
        let bits = self.bits.wrapping_sub(1 << 52);
        let isZero = ((((bits >> 52) as u32) & 0x7FF) + 1) >> 11;
        FloatingPoint {
            bits: bits & u64::from(isZero).wrapping_sub(1),
        }
    }

    /// The square of the value.
    pub(crate) fn squared(self) -> Self {
        self * self
    }

    /// One divided by the value.
    pub(crate) fn inverse(self) -> Self {
        Self::one / self
    }

    /// The square root of a value that is not negative, as `fpr_sqrt` does.
    pub(crate) fn squareRoot(self) -> Self {
        let x = self.bits;
        let mut mantissa = (x & mantissaMask) | (1 << 52);
        let biasedExponent = ((x >> 52) & 0x7FF) as i32;
        let mut exponent = biasedExponent - 1023;
        // An odd exponent doubles the mantissa. The exponent is then halved.
        mantissa += mantissa & u64::from((exponent & 1) as u32).wrapping_neg();
        exponent >>= 1;
        mantissa <<= 1;
        // The square root of the fixed-point mantissa, bit by bit.
        let mut root = 0u64;
        let mut partial = 0u64;
        let mut bit = 1u64 << 53;
        for _ in 0..54 {
            let candidate = partial + bit;
            let isTaken = (mantissa.wrapping_sub(candidate) >> 63).wrapping_sub(1);
            partial += (bit << 1) & isTaken;
            mantissa -= candidate & isTaken;
            root += bit & isTaken;
            mantissa <<= 1;
            bit >>= 1;
        }
        // A guard bit and a sticky bit for the remainder.
        root <<= 1;
        root |= (mantissa | mantissa.wrapping_neg()) >> 63;
        exponent -= 54;
        root &= u64::from(((biasedExponent + 0x7FF) >> 11) as u32).wrapping_neg();
        Self::packed(0, exponent, root)
    }

    /// True when the value is below another value, as `fpr_lt` does.
    pub(crate) fn isLessThan(self, other: FloatingPoint) -> bool {
        // A signed comparison gives the order of two positive values. When the signs differ,
        // the sign gives the result, and two negative values compare in reverse.
        let left = self.bits as i64;
        let mut right = other.bits as i64;
        right &= !((left ^ right) >> 63);
        let isBelow = (left.wrapping_sub(right) >> 63) & 1;
        let isAbove = (right.wrapping_sub(left) >> 63) & 1;
        let areBothNegative = ((self.bits & other.bits) >> 63) as i64;
        (isBelow ^ ((isBelow ^ isAbove) & areBothNegative)) != 0
    }

    /// `2^63 * scale * exp(-x)`, rounded, for `0 <= x < log(2)`, as `fpr_expm_p63` does. The
    /// polynomial of FACCT approximates `exp(-x)` with about 50 bits of precision.
    pub(crate) fn scaledExponentialOfNegation(self, scale: FloatingPoint) -> u64 {
        const coefficients: [u64; 13] = [
            0x0000_0004_7411_83A3,
            0x0000_0036_548C_FC06,
            0x0000_024F_DCBF_140A,
            0x0000_171D_939D_E045,
            0x0000_D00C_F58F_6F84,
            0x0006_8068_1CF7_96E3,
            0x002D_82D8_305B_0FEA,
            0x0111_1111_0E06_6FD0,
            0x0555_5555_5507_0F00,
            0x1555_5555_5581_FF00,
            0x4000_0000_0002_B400,
            0x7FFF_FFFF_FFFF_4800,
            0x8000_0000_0000_0000,
        ];
        let mut y = coefficients[0];
        let z = ((self * Self::twoTo63).roundedTowardZero() as u64) << 1;
        for coefficient in &coefficients[1..] {
            y = coefficient.wrapping_sub(highProduct(z, y));
        }
        let z = ((scale * Self::twoTo63).roundedTowardZero() as u64) << 1;
        highProduct(z, y)
    }
}

/// The top 64 bits of the 128-bit product of two words, from 32-bit halves, as the loop of
/// `fpr_expm_p63` computes them.
fn highProduct(z: u64, y: u64) -> u64 {
    let (z0, z1) = (u64::from(z as u32), z >> 32);
    let (y0, y1) = (u64::from(y as u32), y >> 32);
    let a = z0 * y1 + ((z0 * y0) >> 32);
    let b = z1 * y0;
    let mut high = (a >> 32) + (b >> 32);
    high += (u64::from(a as u32) + u64::from(b as u32)) >> 32;
    high + z1 * y1
}

/// `value >> count` for a count in `0..64`, in two steps of at most 31 bits, as `fpr_ursh`
/// does.
fn unsignedRightShift(value: u64, count: i32) -> u64 {
    let value = value ^ ((value ^ (value >> 32)) & ((count >> 5) as u64).wrapping_neg());
    value >> (count & 31)
}

/// The arithmetic `value >> count` for a count in `0..64`, as `fpr_irsh` does.
fn signedRightShift(value: i64, count: i32) -> i64 {
    let value = value ^ ((value ^ (value >> 32)) & -i64::from(count >> 5));
    value >> (count & 31)
}

/// `value << count` for a count in `0..64`, as `fpr_ulsh` does.
fn leftShift(value: u64, count: i32) -> u64 {
    let value = value ^ ((value ^ (value << 32)) & ((count >> 5) as u64).wrapping_neg());
    value << (count & 31)
}

/// Shifts a mantissa left until its top bit is set and lowers the exponent by the shift, as the
/// `FPR_NORM64` macro of `fpr.c` does. A zero mantissa stays zero, and the exponent then
/// changes by 63.
fn normalize64(mantissa: &mut u64, exponent: &mut i32) {
    *exponent -= 63;
    for width in [32u32, 16, 8, 4, 2] {
        let top = (*mantissa >> (64 - width)) as u32;
        let isTopSet = (top | top.wrapping_neg()) >> 31;
        let shifted = *mantissa << width;
        *mantissa ^= (*mantissa ^ shifted) & u64::from(isTopSet).wrapping_sub(1);
        *exponent += (isTopSet * width) as i32;
    }
    let isTopSet = (*mantissa >> 63) as u32;
    *mantissa ^= (*mantissa ^ (*mantissa << 1)) & u64::from(isTopSet).wrapping_sub(1);
    *exponent += isTopSet as i32;
}

impl Add for FloatingPoint {
    type Output = FloatingPoint;

    /// The sum, as `fpr_add` does.
    fn add(self, other: FloatingPoint) -> FloatingPoint {
        let (mut x, mut y) = (self.bits, other.bits);
        // The first operand gets the larger absolute value. When both absolute values are
        // equal, a negative first operand swaps too, so that `x + (-x)` is positive zero.
        let difference = (x & magnitudeMask).wrapping_sub(y & magnitudeMask);
        let isSwapped = ((difference >> 63) as u32)
            | ((1u32.wrapping_sub((difference.wrapping_neg() >> 63) as u32)) & ((x >> 63) as u32));
        let swap = (x ^ y) & u64::from(isSwapped).wrapping_neg();
        x ^= swap;
        y ^= swap;
        // The signs, the unbiased exponents and the mantissas scaled to 2^55..2^56. A zero
        // operand has a zero mantissa and the exponent -1078.
        let mut xExponent = (x >> 52) as i32;
        let xSign = xExponent >> 11;
        xExponent &= 0x7FF;
        let implicitBit = u64::from(((xExponent + 0x7FF) >> 11) as u32) << 52;
        let mut xMantissa = ((x & mantissaMask) | implicitBit) << 3;
        xExponent -= 1078;
        let mut yExponent = (y >> 52) as i32;
        let ySign = yExponent >> 11;
        yExponent &= 0x7FF;
        let implicitBit = u64::from(((yExponent + 0x7FF) >> 11) as u32) << 52;
        let mut yMantissa = ((y & mantissaMask) | implicitBit) << 3;
        yExponent -= 1078;
        // Only y moves right. A shift above 59 bits gives zero.
        let mut shift = xExponent - yExponent;
        yMantissa &= u64::from(((shift - 60) as u32) >> 31).wrapping_neg();
        shift &= 63;
        // The lowest bit of y is a sticky bit.
        let droppedMask = leftShift(1, shift) - 1;
        yMantissa |= (yMantissa & droppedMask) + droppedMask;
        yMantissa = unsignedRightShift(yMantissa, shift);
        // Add the mantissas for equal signs, and subtract them otherwise.
        let isSubtraction = u64::from((xSign ^ ySign) as u32).wrapping_neg();
        xMantissa =
            xMantissa.wrapping_add(yMantissa.wrapping_sub((yMantissa << 1) & isSubtraction));
        normalize64(&mut xMantissa, &mut xExponent);
        xMantissa |= u64::from(((xMantissa as u32) & 0x1FF) + 0x1FF);
        xMantissa >>= 9;
        xExponent += 9;
        FloatingPoint::packed(xSign as u32, xExponent, xMantissa)
    }
}

impl Sub for FloatingPoint {
    type Output = FloatingPoint;

    /// The difference, as `fpr_sub` does.
    fn sub(self, other: FloatingPoint) -> FloatingPoint {
        self + -other
    }
}

impl Neg for FloatingPoint {
    type Output = FloatingPoint;

    /// The value with the opposite sign, as `fpr_neg` does.
    fn neg(self) -> FloatingPoint {
        FloatingPoint {
            bits: self.bits ^ (1 << 63),
        }
    }
}

impl Mul for FloatingPoint {
    type Output = FloatingPoint;

    /// The product, as `fpr_mul` does.
    fn mul(self, other: FloatingPoint) -> FloatingPoint {
        let (x, y) = (self.bits, other.bits);
        let xMantissa = (x & mantissaMask) | (1 << 52);
        let yMantissa = (y & mantissaMask) | (1 << 52);
        // The product of two 53-bit integers, with low halves of 25 bits.
        let x0 = (xMantissa as u32) & 0x01FF_FFFF;
        let x1 = (xMantissa >> 25) as u32;
        let y0 = (yMantissa as u32) & 0x01FF_FFFF;
        let y1 = (yMantissa >> 25) as u32;
        let mut wide = u64::from(x0) * u64::from(y0);
        let z0 = (wide as u32) & 0x01FF_FFFF;
        let mut z1 = (wide >> 25) as u32;
        wide = u64::from(x0) * u64::from(y1);
        z1 += (wide as u32) & 0x01FF_FFFF;
        let mut z2 = (wide >> 25) as u32;
        wide = u64::from(x1) * u64::from(y0);
        z1 += (wide as u32) & 0x01FF_FFFF;
        z2 += (wide >> 25) as u32;
        let mut product = u64::from(x1) * u64::from(y1);
        z2 += z1 >> 25;
        z1 &= 0x01FF_FFFF;
        product += u64::from(z2);
        // The low limbs only set the sticky bit.
        product |= u64::from(((z0 | z1) + 0x01FF_FFFF) >> 25);
        // A product of 2^55 or more moves right by one bit, with the sticky bit kept.
        let shifted = (product >> 1) | (product & 1);
        let isLarge = product >> 55;
        product ^= (product ^ shifted) & isLarge.wrapping_neg();
        let xExponent = ((x >> 52) & 0x7FF) as i32;
        let yExponent = ((y >> 52) & 0x7FF) as i32;
        let exponent = xExponent + yExponent - 2100 + isLarge as i32;
        let sign = ((x ^ y) >> 63) as u32;
        // A zero operand gives a zero mantissa.
        let isNotZero = ((xExponent + 0x7FF) & (yExponent + 0x7FF)) >> 11;
        product &= u64::from(isNotZero as u32).wrapping_neg();
        FloatingPoint::packed(sign, exponent, product)
    }
}

impl Div for FloatingPoint {
    type Output = FloatingPoint;

    /// The quotient, as `fpr_div` does. The divisor must not be zero.
    fn div(self, other: FloatingPoint) -> FloatingPoint {
        let (x, y) = (self.bits, other.bits);
        let mut xMantissa = (x & mantissaMask) | (1 << 52);
        let yMantissa = (y & mantissaMask) | (1 << 52);
        // The division bit by bit, for 55 bits.
        let mut quotient = 0u64;
        for _ in 0..55 {
            let isTaken = (xMantissa.wrapping_sub(yMantissa) >> 63).wrapping_sub(1);
            xMantissa -= isTaken & yMantissa;
            quotient |= isTaken & 1;
            xMantissa <<= 1;
            quotient <<= 1;
        }
        // The 56th bit is a sticky bit for the remainder.
        quotient |= (xMantissa | xMantissa.wrapping_neg()) >> 63;
        let shifted = (quotient >> 1) | (quotient & 1);
        let isLarge = quotient >> 55;
        quotient ^= (quotient ^ shifted) & isLarge.wrapping_neg();
        let xExponent = ((x >> 52) & 0x7FF) as i32;
        let yExponent = ((y >> 52) & 0x7FF) as i32;
        let mut exponent = xExponent - yExponent - 55 + isLarge as i32;
        let mut sign = ((x ^ y) >> 63) as u32;
        // A zero dividend gives positive zero.
        let isNotZero = (xExponent + 0x7FF) >> 11;
        sign &= isNotZero as u32;
        exponent &= -isNotZero;
        quotient &= u64::from(isNotZero as u32).wrapping_neg();
        FloatingPoint::packed(sign, exponent, quotient)
    }
}

#[cfg(test)]
mod tests {
    use super::FloatingPoint;

    /// SplitMix64, the seeded source of the random operands.
    struct Operands {
        state: u64,
    }

    impl Operands {
        fn seeded(seed: u64) -> Self {
            Operands { state: seed }
        }

        fn nextWord(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut word = self.state;
            word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            word ^ (word >> 31)
        }

        /// A normal binary64 value with a random sign and mantissa, and an unbiased exponent
        /// in `-exponentRange..=exponentRange`.
        fn normal(&mut self, exponentRange: u64) -> f64 {
            let word = self.nextWord();
            let exponent = 1023 - exponentRange + (word >> 52) % (2 * exponentRange + 1);
            f64::from_bits((word & (1 << 63)) | (exponent << 52) | (self.nextWord() >> 12))
        }
    }

    fn emulated(value: f64) -> FloatingPoint {
        FloatingPoint::fromBits(value.to_bits())
    }

    const operandSeed: u64 = 0x4641_4C43_4F4E_4650;

    // The hardware binary64 arithmetic of IEEE 754 is the independent source of the known
    // answers: each emulated operation of a normal value with a normal result must give the
    // bits of the hardware operation.

    #[test]
    fn arithmeticGivesTheBitsOfIEEE754ForNormalValues() {
        let mut operands = Operands::seeded(operandSeed);
        for case in 0..20_000 {
            let (x, y) = (operands.normal(300), operands.normal(300));
            let (left, right) = (emulated(x), emulated(y));
            assert_eq!(
                (left + right).bits(),
                (x + y).to_bits(),
                "{x} + {y}, case {case}"
            );
            assert_eq!(
                (left - right).bits(),
                (x - y).to_bits(),
                "{x} - {y}, case {case}"
            );
            assert_eq!(
                (left * right).bits(),
                (x * y).to_bits(),
                "{x} * {y}, case {case}"
            );
            assert_eq!(
                (left / right).bits(),
                (x / y).to_bits(),
                "{x} / {y}, case {case}"
            );
            assert_eq!(
                left.squared().bits(),
                (x * x).to_bits(),
                "{x}^2, case {case}"
            );
            assert_eq!(
                left.inverse().bits(),
                (1.0 / x).to_bits(),
                "1/{x}, case {case}"
            );
            let magnitude = x.abs();
            assert_eq!(
                emulated(magnitude).squareRoot().bits(),
                magnitude.sqrt().to_bits(),
                "sqrt({magnitude}), case {case}"
            );
            assert_eq!(left.halved().bits(), (x / 2.0).to_bits(), "{x} / 2");
            assert_eq!((-left).bits(), (-x).to_bits(), "-{x}");
        }
    }

    #[test]
    fn sumsWithCloseExponentsAndCancellationGiveTheBitsOfIEEE754() {
        // Close exponents exercise the alignment, the sticky bit and the cancellation.
        let mut operands = Operands::seeded(operandSeed ^ 1);
        for case in 0..20_000 {
            let x = operands.normal(3);
            let y = if case % 3 == 0 {
                f64::from_bits(x.to_bits() ^ (1 << 63) ^ (operands.nextWord() & 0xFF))
            } else {
                operands.normal(3)
            };
            assert_eq!(
                (emulated(x) + emulated(y)).bits(),
                (x + y).to_bits(),
                "{x} + {y}, case {case}"
            );
        }
    }

    #[test]
    fn zerosFollowTheRulesOfTheCCode() {
        let zero = FloatingPoint::zero;
        let negativeZero = -zero;
        let three = FloatingPoint::of(3);
        // x + (-x) and -0 + 0 are positive zero, and -0 + -0 is negative zero.
        assert_eq!((three - three).bits(), 0);
        assert_eq!((negativeZero + zero).bits(), 0);
        assert_eq!((zero + negativeZero).bits(), 0);
        assert_eq!((negativeZero + negativeZero).bits(), 1 << 63);
        assert_eq!((three * zero).bits(), 0);
        assert_eq!((-three * zero).bits(), 1 << 63);
        // The C code gives positive zero for any zero dividend.
        assert_eq!((negativeZero / three).bits(), 0);
        assert_eq!((zero / -three).bits(), 0);
        assert_eq!(zero.squareRoot().bits(), 0);
        assert_eq!(zero.halved().bits(), 0);
        assert_eq!((three + zero).bits(), three.bits());
    }

    #[test]
    fn tinyResultsAreZeroAndNotSubnormal() {
        let tiny = emulated(f64::MIN_POSITIVE);
        assert_eq!((tiny * FloatingPoint::oneHalf).bits(), 0);
        assert_eq!(tiny.halved().bits(), 0);
        assert_eq!((tiny / FloatingPoint::two).bits(), 0);
        assert_eq!(
            (emulated(f64::MIN_POSITIVE * 2.0) * FloatingPoint::oneHalf).bits(),
            f64::MIN_POSITIVE.to_bits()
        );
    }

    #[test]
    fn integersConvertWithRoundingToNearest() {
        let mut operands = Operands::seeded(operandSeed ^ 2);
        for case in 0..20_000 {
            let word = operands.nextWord();
            // Integers of every bit length, both signs, below 2^63 in absolute value.
            let integer = ((word >> 1) >> (word % 63)) as i64 * if case % 2 == 0 { 1 } else { -1 };
            assert_eq!(
                FloatingPoint::of(integer).bits(),
                (integer as f64).to_bits(),
                "{integer}"
            );
            let scale = (operands.nextWord() % 200) as i32 - 100;
            assert_eq!(
                FloatingPoint::scaled(integer, scale).bits(),
                ((integer as f64) * 2f64.powi(scale)).to_bits(),
                "{integer} * 2^{scale}"
            );
        }
        assert_eq!(FloatingPoint::of(0).bits(), 0);
        assert_eq!(
            FloatingPoint::of(i64::MAX).bits(),
            (i64::MAX as f64).to_bits()
        );
        assert_eq!(
            FloatingPoint::of(-i64::MAX).bits(),
            (-i64::MAX as f64).to_bits()
        );
    }

    #[test]
    fn roundingFunctionsGiveTheIntegersOfIEEE754() {
        let mut operands = Operands::seeded(operandSeed ^ 3);
        for case in 0..20_000 {
            let x = operands.normal(62).clamp(-9.2e18, 9.2e18);
            let value = emulated(x);
            assert_eq!(
                value.roundedToNearest(),
                x.round_ties_even() as i64,
                "rint({x}), case {case}"
            );
            assert_eq!(value.roundedDown(), x.floor() as i64, "floor({x})");
            assert_eq!(value.roundedTowardZero(), x.trunc() as i64, "trunc({x})");
        }
        for (x, nearest, down, towardZero) in [
            (0.5, 0, 0, 0),
            (1.5, 2, 1, 1),
            (2.5, 2, 2, 2),
            (-0.5, 0, -1, 0),
            (-1.5, -2, -2, -1),
            (-2.5, -2, -3, -2),
            (0.0, 0, 0, 0),
            (1e-300, 0, 0, 0),
            (-1e-300, 0, -1, 0),
        ] {
            let value = emulated(x);
            assert_eq!(value.roundedToNearest(), nearest, "rint({x})");
            assert_eq!(value.roundedDown(), down, "floor({x})");
            assert_eq!(value.roundedTowardZero(), towardZero, "trunc({x})");
        }
        // The C code floors negative zero to -1.
        assert_eq!((-FloatingPoint::zero).roundedDown(), -1);
    }

    #[test]
    fn comparisonOrdersEveryPairOfSigns() {
        let mut operands = Operands::seeded(operandSeed ^ 4);
        for _ in 0..20_000 {
            let (x, y) = (operands.normal(40), operands.normal(40));
            assert_eq!(emulated(x).isLessThan(emulated(y)), x < y, "{x} < {y}");
            assert!(!emulated(x).isLessThan(emulated(x)), "{x} < {x}");
        }
        let zero = FloatingPoint::zero;
        assert!(!zero.isLessThan(-zero));
        assert!((-zero).isLessThan(zero));
        assert!(FloatingPoint::minusTwoTo31MinusOne.isLessThan(FloatingPoint::twoTo31MinusOne));
    }

    #[test]
    fn constantsHoldTheirValues() {
        for (constant, value) in [
            (FloatingPoint::zero, 0.0),
            (FloatingPoint::one, 1.0),
            (FloatingPoint::two, 2.0),
            (FloatingPoint::oneHalf, 0.5),
            (FloatingPoint::twoTo31, 2147483648.0),
            (FloatingPoint::twoTo31MinusOne, 2147483647.0),
            (FloatingPoint::minusTwoTo31MinusOne, -2147483647.0),
            (FloatingPoint::twoTo63MinusOne, 9223372036854775807.0),
            (FloatingPoint::minusTwoTo63MinusOne, -9223372036854775807.0),
            (FloatingPoint::twoTo63, 9223372036854775808.0),
        ] {
            assert_eq!(constant.bits(), f64::to_bits(value), "{value}");
        }
    }

    #[test]
    fn exponentialMatchesTheCCode() {
        // Known answers of `fpr_expm_p63` of the C library, for x in 0..log(2) and a scale
        // below one, the range of the sampler.
        for (x, scale, expected) in [
            (0.0, 0.5, 0x4000_0000_0000_0000u64),
            (0.25, 0.8, 0x4FBF_CB95_5B39_B625),
            (0.5, 0.75, 0x3A3A_18F5_4EC2_1A88),
            (0.69, 0.99, 0x3F8F_49C6_7B64_3DC5),
            (0.1, 0.9, 0x683C_BDC3_65CE_DFAF),
            (0.000001, 0.6, 0x4CCC_C7C4_4F7A_0142),
        ] {
            assert_eq!(
                emulated(x).scaledExponentialOfNegation(emulated(scale)),
                expected,
                "exp(-{x}) * {scale}"
            );
        }
    }
}
