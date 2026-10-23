use OQSNativeSHA3::{SHAKE128, SHAKE256};

/// The modulus q of ML-DSA: `2^23 - 2^13 + 1`.
pub(crate) const modulus: i32 = 8_380_417;

/// The number of coefficients of a polynomial.
pub(crate) const coefficientCount: usize = 256;

/// The bits d that Power2Round moves from t to t0, FIPS 204, Table 1.
pub(crate) const droppedBits: u32 = 13;

/// `q^-1` modulo `2^32`, for the Montgomery reduction.
const inverseModulus: u32 = 58_728_449;

/// `2^56` modulo q: the factor `2^64 / 256` with which the inverse NTT leaves the Montgomery
/// domain and divides by 256.
const inverseTransformScale: i32 = 41_978;

/// The root of unity of the NTT of FIPS 204: 1753, a primitive 512th root of unity modulo q.
const rootOfUnity: i64 = 1753;

/// The twiddle factors of the NTT: `2^32 · 1753^BitRev8(i) mod q`, as the representative
/// nearest zero. The first entry is zero, as in the table of mldsa-native, and no butterfly
/// uses it.
const zetas: [i32; coefficientCount] = rootPowers();

/// The twiddle factors in the Montgomery form and the order of `zetas.inc` of mldsa-native.
const fn rootPowers() -> [i32; coefficientCount] {
    let modulusWide = modulus as i64;
    let montgomeryFactor = (1i64 << 32) % modulusWide;
    let mut powers = [0i32; coefficientCount];
    let mut index = 1;
    while index < coefficientCount {
        let mut reversed = 0usize;
        let mut bit = 0;
        while bit < 8 {
            // The shift clears bit 0, so `+` joins the two parts.
            reversed = (reversed << 1) + ((index >> bit) & 1);
            bit += 1;
        }
        let mut power = montgomeryFactor;
        let mut step = 0;
        while step < reversed {
            power = power * rootOfUnity % modulusWide;
            step += 1;
        }
        if power > (modulusWide - 1) / 2 {
            power -= modulusWide;
        }
        powers[index] = power as i32;
        index += 1;
    }
    powers
}

/// The Montgomery reduction of `mld_montgomery_reduce`: a value congruent to `value · 2^-32`
/// modulo q. For `|value| < 2^31 q` the result is below q in absolute value.
pub(crate) fn montgomeryReduced(value: i64) -> i32 {
    // The low 32 bits of `value · q^-1`, as a signed number, as the C code computes them.
    let multiple = (value as u32).wrapping_mul(inverseModulus) as i32;
    ((value - i64::from(multiple) * i64::from(modulus)) >> 32) as i32
}

/// The Montgomery product `left · right · 2^-32` modulo q of `mld_fqmul`.
fn montgomeryProduct(left: i32, right: i32) -> i32 {
    montgomeryReduced(i64::from(left) * i64::from(right))
}

/// The `mld_reduce32` of mldsa-native: a value congruent modulo q, at least -6283009 and below
/// 6283009, for a value up to `2^31 - 2^22 - 1`.
pub(crate) fn reduced(value: i32) -> i32 {
    let quotient = (value + (1 << 22)) >> 23;
    value - quotient * modulus
}

/// All ones when a value is negative and zero otherwise, with no branch, as
/// `mld_ct_cmask_neg_i32`.
fn negativeMask(value: i32) -> u32 {
    (value >> 31) as u32
}

/// `first` when the mask is all ones and `second` when it is zero, with no branch, as
/// `mld_ct_sel_int32`.
fn selected(first: i32, second: i32, mask: u32) -> i32 {
    let (first, second) = (first as u32, second as u32);
    (second ^ (mask & (first ^ second))) as i32
}

/// The `mld_caddq` of mldsa-native: a value above -q plus q when it is negative, with no
/// branch.
pub(crate) fn nonNegative(value: i32) -> i32 {
    selected(value + modulus, value, negativeMask(value))
}

/// The absolute value of `mld_ct_abs_i32`, with no branch.
fn absolute(value: i32) -> i32 {
    selected(-value, value, negativeMask(value))
}

/// True for the gamma2 of ML-DSA-44, `(q - 1) / 88`. The other sets have `(q - 1) / 32`.
const fn isNarrowRounding(gamma2: i32) -> bool {
    gamma2 == (modulus - 1) / 88
}

/// The Decompose of FIPS 204, Algorithm 36, as `mld_decompose` computes it for a standard
/// representative: the high bits `w1` and the low bits `w0` of a value.
pub(crate) fn decomposed(value: i32, gamma2: i32) -> (i32, i32) {
    let mut high = (value + 127) >> 7;
    if isNarrowRounding(gamma2) {
        high = (high * 11_275 + (1 << 23)) >> 24;
        // The value 44 is the top of the range, which wraps to zero.
        high = selected(0, high, negativeMask(43 - high));
    } else {
        high = (high * 1025 + (1 << 21)) >> 22;
        high &= 15;
    }
    let low = value - high * 2 * gamma2;
    let low = selected(low - modulus, low, negativeMask((modulus - 1) / 2 - low));
    (high, low)
}

/// The MakeHint of FIPS 204, Algorithm 39, in the form of `mld_make_hint`: true when the low
/// bits of a value overflow into its high bits.
pub(crate) fn isHint(low: i32, high: i32, gamma2: i32) -> bool {
    low > gamma2 || low < -gamma2 || (low == -gamma2 && high != 0)
}

/// The UseHint of FIPS 204, Algorithm 40, as `mld_use_hint`: the high bits of a standard
/// representative, corrected by a hint bit.
pub(crate) fn hintedHigh(value: i32, hint: i32, gamma2: i32) -> i32 {
    let (high, low) = decomposed(value, gamma2);
    if hint == 0 {
        return high;
    }
    if isNarrowRounding(gamma2) {
        if low > 0 {
            if high == 43 { 0 } else { high + 1 }
        } else if high == 0 {
            43
        } else {
            high - 1
        }
    } else if low > 0 {
        (high + 1) & 15
    } else {
        (high - 1) & 15
    }
}

/// Writes values of `bits` bits each into bytes, the low bit first, as the packing functions
/// of FIPS 204, Algorithms 16 and 17, do.
fn packBits(values: impl Iterator<Item = u32>, bits: u32, output: &mut [u8]) {
    debug_assert_eq!(output.len(), 32 * bits as usize);
    let mut buffer = 0u64;
    let mut bufferedBits = 0;
    let mut position = 0;
    for value in values {
        debug_assert!(value < 1 << bits, "{value} has more than {bits} bits");
        // The buffer holds fewer than 8 bits above `bufferedBits`, so `+` adds disjoint bits.
        buffer += u64::from(value) << bufferedBits;
        bufferedBits += bits;
        while bufferedBits >= 8 {
            output[position] = buffer as u8;
            buffer >>= 8;
            bufferedBits -= 8;
            position += 1;
        }
    }
}

/// Reads 256 values of `bits` bits each from bytes, the low bit first, as the unpacking
/// functions of FIPS 204, Algorithms 18 and 19, do.
fn unpackedBits(bits: u32, input: &[u8]) -> [u32; coefficientCount] {
    debug_assert_eq!(input.len(), 32 * bits as usize);
    let mask = (1u64 << bits) - 1;
    let mut values = [0u32; coefficientCount];
    let mut buffer = 0u64;
    let mut bufferedBits = 0;
    let mut position = 0;
    for value in values.iter_mut() {
        while bufferedBits < bits {
            buffer += u64::from(input[position]) << bufferedBits;
            position += 1;
            bufferedBits += 8;
        }
        *value = (buffer & mask) as u32;
        buffer >>= bits;
        bufferedBits -= bits;
    }
    values
}

/// A polynomial of ML-DSA: 256 coefficients modulo q, in the signed representatives that the
/// arithmetic of mldsa-native gives at each step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Polynomial {
    pub(crate) coefficients: [i32; coefficientCount],
}

impl Polynomial {
    /// The zero polynomial.
    pub(crate) const zero: Polynomial = Polynomial {
        coefficients: [0; coefficientCount],
    };

    /// The NTT of `mld_poly_ntt` in place: eight layers of butterflies with Montgomery
    /// products and no reduction. Each coefficient must be below q in absolute value, and the
    /// result is below 9 q.
    pub(crate) fn transform(&mut self) {
        let coefficients = &mut self.coefficients;
        let mut zetaIndex = 1;
        let mut length = coefficientCount / 2;
        while length > 0 {
            for start in (0..coefficientCount).step_by(2 * length) {
                let zeta = zetas[zetaIndex];
                zetaIndex += 1;
                for index in start..start + length {
                    let twiddled = montgomeryProduct(coefficients[index + length], zeta);
                    coefficients[index + length] = coefficients[index] - twiddled;
                    coefficients[index] += twiddled;
                }
            }
            length /= 2;
        }
    }

    /// The inverse NTT of `mld_poly_invntt_tomont` in place: eight layers of butterflies, then
    /// a Montgomery product with `2^64 / 256`. Each coefficient must be below q in absolute
    /// value, and so is the result.
    pub(crate) fn inverseTransform(&mut self) {
        let coefficients = &mut self.coefficients;
        let mut zetaIndex = coefficientCount - 1;
        let mut length = 1;
        while length < coefficientCount {
            for start in (0..coefficientCount).step_by(2 * length) {
                let zeta = -zetas[zetaIndex];
                zetaIndex -= 1;
                for index in start..start + length {
                    let low = coefficients[index];
                    coefficients[index] = low + coefficients[index + length];
                    coefficients[index + length] =
                        montgomeryProduct(low - coefficients[index + length], zeta);
                }
            }
            length *= 2;
        }
        for coefficient in coefficients.iter_mut() {
            *coefficient = montgomeryProduct(*coefficient, inverseTransformScale);
        }
    }

    /// The pointwise Montgomery product of two polynomials in the NTT domain, as
    /// `mld_poly_pointwise_montgomery`.
    pub(crate) fn transformedProduct(&self, other: &Polynomial) -> Polynomial {
        let mut result = *self;
        for (coefficient, factor) in result.coefficients.iter_mut().zip(other.coefficients) {
            *coefficient = montgomeryProduct(*coefficient, factor);
        }
        result
    }

    /// The inner product of two vectors in the NTT domain, as
    /// `mld_polyvecl_pointwise_acc_montgomery`: the sum of the products in 64 bits, and one
    /// Montgomery reduction of each sum.
    pub(crate) fn innerProduct(left: &[Polynomial], right: &[Polynomial]) -> Polynomial {
        let mut sums = [0i64; coefficientCount];
        for (leftPolynomial, rightPolynomial) in left.iter().zip(right) {
            for ((sum, leftValue), rightValue) in sums
                .iter_mut()
                .zip(leftPolynomial.coefficients)
                .zip(rightPolynomial.coefficients)
            {
                *sum += i64::from(leftValue) * i64::from(rightValue);
            }
        }
        let mut result = Polynomial::zero;
        for (coefficient, sum) in result.coefficients.iter_mut().zip(sums) {
            *coefficient = montgomeryReduced(sum);
        }
        result
    }

    /// The sum of two polynomials, with no reduction, as `mld_poly_add`.
    pub(crate) fn plus(&self, other: &Polynomial) -> Polynomial {
        let mut result = *self;
        for (coefficient, addend) in result.coefficients.iter_mut().zip(other.coefficients) {
            *coefficient += addend;
        }
        result
    }

    /// The difference of two polynomials, with no reduction, as `mld_poly_sub`.
    pub(crate) fn minus(&self, other: &Polynomial) -> Polynomial {
        let mut result = *self;
        for (coefficient, subtrahend) in result.coefficients.iter_mut().zip(other.coefficients) {
            *coefficient -= subtrahend;
        }
        result
    }

    /// Each coefficient reduced with `mld_reduce32`, as `mld_poly_reduce`.
    pub(crate) fn reduced(&self) -> Polynomial {
        let mut result = *self;
        for coefficient in result.coefficients.iter_mut() {
            *coefficient = reduced(*coefficient);
        }
        result
    }

    /// Each coefficient with q added when it is negative, as `mld_poly_caddq`.
    pub(crate) fn nonNegative(&self) -> Polynomial {
        let mut result = *self;
        for coefficient in result.coefficients.iter_mut() {
            *coefficient = nonNegative(*coefficient);
        }
        result
    }

    /// Each coefficient times `2^d`, as `mld_poly_shiftl`.
    pub(crate) fn shiftedLeft(&self) -> Polynomial {
        let mut result = *self;
        for coefficient in result.coefficients.iter_mut() {
            *coefficient *= 1 << droppedBits;
        }
        result
    }

    /// True when each coefficient is below a bound in absolute value, as `mld_poly_chknorm`
    /// decides it, with no early exit.
    pub(crate) fn isNormBelow(&self, bound: i32) -> bool {
        let violations = self.coefficients.iter().fold(0u32, |mask, coefficient| {
            mask | negativeMask(bound - 1 - absolute(*coefficient))
        });
        violations == 0
    }

    /// The Power2Round of FIPS 204, Algorithm 35, of each standard representative, as
    /// `mld_poly_power2round`: the high part t1 and the low part t0.
    pub(crate) fn power2Rounded(&self) -> (Polynomial, Polynomial) {
        let mut high = Polynomial::zero;
        let mut low = Polynomial::zero;
        for ((value, highPart), lowPart) in self
            .coefficients
            .iter()
            .zip(high.coefficients.iter_mut())
            .zip(low.coefficients.iter_mut())
        {
            *highPart = (value + (1 << (droppedBits - 1)) - 1) >> droppedBits;
            *lowPart = value - (*highPart << droppedBits);
        }
        (high, low)
    }

    /// The Decompose of each standard representative, as `mld_poly_decompose`: the high bits
    /// w1 and the low bits w0.
    pub(crate) fn decomposed(&self, gamma2: i32) -> (Polynomial, Polynomial) {
        let mut high = Polynomial::zero;
        let mut low = Polynomial::zero;
        for ((value, highPart), lowPart) in self
            .coefficients
            .iter()
            .zip(high.coefficients.iter_mut())
            .zip(low.coefficients.iter_mut())
        {
            (*highPart, *lowPart) = decomposed(*value, gamma2);
        }
        (high, low)
    }

    /// The UseHint of each standard representative with the bits of a hint polynomial, as
    /// `mld_poly_use_hint`.
    pub(crate) fn hintedHigh(&self, hint: &Polynomial, gamma2: i32) -> Polynomial {
        let mut result = *self;
        for (coefficient, hintBit) in result.coefficients.iter_mut().zip(hint.coefficients) {
            *coefficient = hintedHigh(*coefficient, hintBit, gamma2);
        }
        result
    }

    /// The RejNTTPoly of FIPS 204, Algorithm 30, as `mld_poly_uniform`: rejection sampling of
    /// 23-bit values below q from SHAKE128 of the seed rho, a column byte and a row byte.
    pub(crate) fn sampledUniform(seed: &[u8; 32], column: u8, row: u8) -> Polynomial {
        let mut sponge = SHAKE128::new();
        sponge.absorb(seed);
        sponge.absorb(&[column, row]);
        let mut reader = sponge.finalize();
        let mut polynomial = Polynomial::zero;
        let mut count = 0;
        let mut block = [0u8; SHAKE128::rate];
        while count < coefficientCount {
            reader.squeeze(&mut block);
            for triple in block.chunks_exact(3) {
                if count == coefficientCount {
                    break;
                }
                // The three bytes hold disjoint bits, so `+` joins them.
                let candidate = (u32::from(triple[0])
                    + (u32::from(triple[1]) << 8)
                    + (u32::from(triple[2]) << 16))
                    & 0x7F_FFFF;
                if candidate < modulus as u32 {
                    polynomial.coefficients[count] = candidate as i32;
                    count += 1;
                }
            }
        }
        polynomial
    }

    /// The RejBoundedPoly of FIPS 204, Algorithm 31, as `mld_poly_uniform_eta`: coefficients
    /// from -eta to eta, from the half bytes of SHAKE256 of the seed rho' and a 16-bit nonce.
    pub(crate) fn sampledShort(eta: i32, seed: &[u8; 64], nonce: u8) -> Polynomial {
        let mut sponge = SHAKE256::new();
        sponge.absorb(seed);
        sponge.absorb(&[nonce, 0]);
        let mut reader = sponge.finalize();
        let mut polynomial = Polynomial::zero;
        let mut count = 0;
        let mut block = [0u8; SHAKE256::rate];
        while count < coefficientCount {
            reader.squeeze(&mut block);
            for byte in block {
                for halfByte in [byte & 0x0F, byte >> 4] {
                    if count == coefficientCount {
                        break;
                    }
                    if let Some(coefficient) = Self::boundedCoefficient(eta, halfByte) {
                        polynomial.coefficients[count] = coefficient;
                        count += 1;
                    }
                }
            }
        }
        polynomial
    }

    /// The CoeffFromHalfByte of FIPS 204, Algorithm 15, as `mld_rej_eta` computes it: a half
    /// byte below 15 gives `2 - (b mod 5)` for eta 2, a half byte below 9 gives `4 - b` for
    /// eta 4, and any other half byte is rejected.
    fn boundedCoefficient(eta: i32, halfByte: u8) -> Option<i32> {
        let value = u32::from(halfByte);
        if eta == 2 {
            // `205 b >> 10` is `b / 5` for each b below 15.
            (value < 15).then(|| 2 - (value - ((205 * value) >> 10) * 5) as i32)
        } else {
            (value < 9).then(|| 4 - value as i32)
        }
    }

    /// The ExpandMask of FIPS 204, Algorithm 34, for one polynomial, as
    /// `mld_poly_uniform_gamma1`: the BitUnpack of SHAKE256 of the seed rho' and a 16-bit nonce
    /// into coefficients from `-(gamma1 - 1)` to gamma1.
    pub(crate) fn sampledMask(gamma1Bits: u32, seed: &[u8; 64], nonce: u16) -> Polynomial {
        let bits = gamma1Bits + 1;
        let mut bytes = [0u8; 640];
        let bytes = &mut bytes[..32 * bits as usize];
        let mut sponge = SHAKE256::new();
        sponge.absorb(seed);
        sponge.absorb(&nonce.to_le_bytes());
        sponge.finalize().squeeze(bytes);
        Polynomial::boundUnpacked(1 << gamma1Bits, bits, bytes)
    }

    /// The SampleInBall of FIPS 204, Algorithm 29, as `mld_poly_challenge`: tau coefficients
    /// of 1 or -1 at the places and with the signs that SHAKE256 of the commitment hash
    /// chooses.
    pub(crate) fn sampledInBall(tau: usize, commitmentHash: &[u8]) -> Polynomial {
        let mut sponge = SHAKE256::new();
        sponge.absorb(commitmentHash);
        let mut reader = sponge.finalize();
        let mut block = [0u8; SHAKE256::rate];
        reader.squeeze(&mut block);
        let mut signs = u64::from_le_bytes(block[..8].try_into().expect("8 bytes"));
        let mut position = 8;
        let mut polynomial = Polynomial::zero;
        for index in coefficientCount - tau..coefficientCount {
            let place = loop {
                if position >= SHAKE256::rate {
                    reader.squeeze(&mut block);
                    position = 0;
                }
                let candidate = usize::from(block[position]);
                position += 1;
                if candidate <= index {
                    break candidate;
                }
            };
            polynomial.coefficients[index] = polynomial.coefficients[place];
            polynomial.coefficients[place] = 1 - 2 * (signs & 1) as i32;
            signs >>= 1;
        }
        polynomial
    }

    /// The SimpleBitPack of FIPS 204, Algorithm 16: each coefficient, which must be below
    /// `2^bits`, in `bits` bits.
    pub(crate) fn simplePacked(&self, bits: u32, output: &mut [u8]) {
        packBits(
            self.coefficients
                .iter()
                .map(|coefficient| *coefficient as u32),
            bits,
            output,
        );
    }

    /// The BitPack of FIPS 204, Algorithm 17: `bound - coefficient` of each coefficient in
    /// `bits` bits, for the coefficients from `bound + 1 - 2^bits` to bound.
    pub(crate) fn boundPacked(&self, bound: i32, bits: u32, output: &mut [u8]) {
        packBits(
            self.coefficients
                .iter()
                .map(|coefficient| (bound - coefficient) as u32),
            bits,
            output,
        );
    }

    /// The SimpleBitUnpack of FIPS 204, Algorithm 18: each coefficient from `bits` bits.
    pub(crate) fn simpleUnpacked(bits: u32, input: &[u8]) -> Polynomial {
        let mut polynomial = Polynomial::zero;
        for (coefficient, value) in polynomial
            .coefficients
            .iter_mut()
            .zip(unpackedBits(bits, input))
        {
            *coefficient = value as i32;
        }
        polynomial
    }

    /// The BitUnpack of FIPS 204, Algorithm 19: `bound - value` for each value of `bits`
    /// bits, as the unpacking functions of mldsa-native compute it for any input.
    pub(crate) fn boundUnpacked(bound: i32, bits: u32, input: &[u8]) -> Polynomial {
        let mut polynomial = Polynomial::zero;
        for (coefficient, value) in polynomial
            .coefficients
            .iter_mut()
            .zip(unpackedBits(bits, input))
        {
            *coefficient = bound - value as i32;
        }
        polynomial
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Polynomial, absolute, coefficientCount, decomposed, hintedHigh, inverseTransformScale,
        isHint, modulus, montgomeryReduced, nonNegative, reduced, zetas,
    };

    const q: i64 = modulus as i64;

    /// `base^exponent mod q`, by repeated squaring in 128 bits.
    fn power(base: i64, exponent: u32) -> i64 {
        let mut result = 1i128;
        let mut square = i128::from(base.rem_euclid(q));
        let mut remaining = exponent;
        while remaining > 0 {
            if remaining & 1 == 1 {
                result = result * square % i128::from(q);
            }
            square = square * square % i128::from(q);
            remaining >>= 1;
        }
        result as i64
    }

    /// The bytes of a simple seeded sequence, the same for each test run.
    fn seededBytes(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 33) as u8
            })
            .collect()
    }

    /// A polynomial of seeded coefficients from `-bound` to `bound`.
    fn polynomialFrom(seed: u64, bound: i32) -> Polynomial {
        let bytes = seededBytes(seed, 4 * coefficientCount);
        let mut polynomial = Polynomial::zero;
        for (coefficient, chunk) in polynomial.coefficients.iter_mut().zip(bytes.chunks(4)) {
            let value = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
            *coefficient = (value % (2 * bound as u32 + 1)) as i32 - bound;
        }
        polynomial
    }

    /// The product of two polynomials modulo `X^256 + 1` and q, by the schoolbook method.
    fn schoolbookProduct(left: &Polynomial, right: &Polynomial) -> [i64; coefficientCount] {
        let mut wide = [0i128; 2 * coefficientCount];
        for (leftIndex, leftValue) in left.coefficients.iter().enumerate() {
            for (rightIndex, rightValue) in right.coefficients.iter().enumerate() {
                wide[leftIndex + rightIndex] += i128::from(*leftValue) * i128::from(*rightValue);
            }
        }
        let mut result = [0i64; coefficientCount];
        for (index, value) in result.iter_mut().enumerate() {
            *value =
                (wide[index] - wide[index + coefficientCount]).rem_euclid(i128::from(q)) as i64;
        }
        result
    }

    fn canonical(polynomial: &Polynomial) -> [i64; coefficientCount] {
        polynomial
            .coefficients
            .map(|value| i64::from(value).rem_euclid(q))
    }

    #[test]
    fn twiddleFactorsAreTheTableOfMLDSANative() {
        // Entries of `zetas.inc` of mldsa-native.
        assert_eq!(
            &zetas[..8],
            &[
                0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468
            ]
        );
        assert_eq!(
            (zetas[64], zetas[128], zetas[200]),
            (-3930395, 2091667, -542412)
        );
        assert_eq!(&zetas[253..], &[1400424, -846154, 1976782]);
        // Each entry is 2^32 · 1753^BitRev8(i) mod q, nearest zero.
        for (index, zeta) in zetas.iter().enumerate().skip(1) {
            let reversed = (index as u8).reverse_bits();
            let mut expected = power(2, 32) * power(1753, u32::from(reversed)) % q;
            if expected > (q - 1) / 2 {
                expected -= q;
            }
            assert_eq!(i64::from(*zeta), expected, "{index}");
        }
        assert_eq!(i64::from(inverseTransformScale), power(2, 56));
    }

    #[test]
    fn montgomeryReductionDividesBy2To32AcrossItsRange() {
        let limit = (1i64 << 31) * q - 1;
        let bytes = seededBytes(1, 8 * 2000);
        let samples = bytes
            .chunks(8)
            .map(|chunk| i64::from_le_bytes(chunk.try_into().expect("8 bytes")) % limit)
            .chain([0, 1, -1, limit, -limit, q, -q]);
        for value in samples {
            let result = montgomeryReduced(value);
            assert!(i64::from(result).abs() < q, "{value}");
            assert_eq!(
                (i128::from(result) * (1i128 << 32) - i128::from(value)).rem_euclid(i128::from(q)),
                0,
                "{value}"
            );
        }
    }

    #[test]
    fn reductionKeepsTheResidueInItsRangeAcrossItsDomain() {
        let domainMaximum = i32::MAX - (1 << 22);
        let samples = (i32::MIN..=domainMaximum).step_by(4099).chain([
            i32::MIN,
            domainMaximum,
            0,
            -1,
            modulus,
            -modulus,
        ]);
        for value in samples {
            let result = reduced(value);
            assert!((-6_283_009..6_283_009).contains(&result), "{value}");
            assert_eq!(
                (i64::from(value) - i64::from(result)).rem_euclid(q),
                0,
                "{value}"
            );
        }
    }

    #[test]
    fn nonNegativeAddsTheModulusToEachNegativeValueOnly() {
        for value in -modulus + 1..modulus {
            let expected = if value < 0 { value + modulus } else { value };
            assert_eq!(nonNegative(value), expected);
        }
        assert_eq!(absolute(-5), 5);
        assert_eq!(absolute(5), 5);
        assert_eq!(absolute(0), 0);
    }

    /// The Decompose of FIPS 204, Algorithm 36, written from the specification.
    fn specifiedDecomposition(value: i64, gamma2: i64) -> (i64, i64) {
        let alpha = 2 * gamma2;
        let positive = value.rem_euclid(q);
        let mut low = positive.rem_euclid(alpha);
        if low > alpha / 2 {
            low -= alpha;
        }
        if positive - low == q - 1 {
            (0, low - 1)
        } else {
            ((positive - low) / alpha, low)
        }
    }

    #[test]
    fn decompositionAndHintsFollowFIPS204ForEveryValue() {
        for gamma2 in [(modulus - 1) / 88, (modulus - 1) / 32] {
            let wide = i64::from(gamma2);
            let highCount = (q - 1) / (2 * wide);
            for value in 0..modulus {
                let (high, low) = decomposed(value, gamma2);
                let expected = specifiedDecomposition(i64::from(value), wide);
                assert_eq!((i64::from(high), i64::from(low)), expected, "{value}");
                // The UseHint of FIPS 204, Algorithm 40.
                let used = if expected.1 > 0 {
                    (expected.0 + 1).rem_euclid(highCount)
                } else {
                    (expected.0 - 1).rem_euclid(highCount)
                };
                assert_eq!(i64::from(hintedHigh(value, 1, gamma2)), used, "{value}");
                assert_eq!(i64::from(hintedHigh(value, 0, gamma2)), expected.0);
            }
        }
    }

    #[test]
    fn hintsAreTheConditionOfMLDSANativeAtEachEdge() {
        let gamma2 = (modulus - 1) / 32;
        assert!(!isHint(gamma2, 3, gamma2));
        assert!(isHint(gamma2 + 1, 3, gamma2));
        assert!(!isHint(-gamma2 + 1, 3, gamma2));
        assert!(isHint(-gamma2 - 1, 0, gamma2));
        // A low part of exactly -gamma2 is a hint unless the high part is zero.
        assert!(isHint(-gamma2, 1, gamma2));
        assert!(!isHint(-gamma2, 0, gamma2));
        assert!(!isHint(0, 0, gamma2));
    }

    #[test]
    fn power2RoundingSplitsEveryValueAsFIPS204Says() {
        let mut polynomial = Polynomial::zero;
        for start in (0..modulus).step_by(coefficientCount) {
            for (index, coefficient) in polynomial.coefficients.iter_mut().enumerate() {
                *coefficient = (start + index as i32).min(modulus - 1);
            }
            let (high, low) = polynomial.power2Rounded();
            for index in 0..coefficientCount {
                let value = polynomial.coefficients[index];
                let (highPart, lowPart) = (high.coefficients[index], low.coefficients[index]);
                assert_eq!(highPart * (1 << 13) + lowPart, value, "{value}");
                assert!((-(1 << 12) + 1..=1 << 12).contains(&lowPart), "{value}");
            }
        }
    }

    #[test]
    fn normCheckAcceptsValuesBelowTheBoundAndRefusesTheBoundItself() {
        let bound = 1000;
        let mut polynomial = Polynomial::zero;
        polynomial.coefficients[7] = bound - 1;
        polynomial.coefficients[8] = -(bound - 1);
        assert!(polynomial.isNormBelow(bound));
        polynomial.coefficients[255] = bound;
        assert!(!polynomial.isNormBelow(bound));
        polynomial.coefficients[255] = -bound;
        assert!(!polynomial.isNormBelow(bound));
        polynomial.coefficients[255] = 0;
        polynomial.coefficients[0] = -5_000_000;
        assert!(!polynomial.isNormBelow(bound));
    }

    #[test]
    fn transformedProductIsTheProductModuloXTo256PlusOne() {
        for seed in 0..6 {
            let left = polynomialFrom(seed, modulus - 1);
            let right = polynomialFrom(seed + 50, 1 << 19);
            let mut leftTransform = left;
            let mut rightTransform = right;
            leftTransform.transform();
            rightTransform.transform();
            let mut product = leftTransform.transformedProduct(&rightTransform);
            product.inverseTransform();
            assert!(product.isNormBelow(modulus), "seed {seed}");
            assert_eq!(
                canonical(&product),
                schoolbookProduct(&left, &right),
                "seed {seed}"
            );
        }
    }

    #[test]
    fn inverseTransformUndoesTheTransformWithTheMontgomeryFactor() {
        for seed in 0..6 {
            let original = polynomialFrom(seed, modulus - 1);
            let mut polynomial = original;
            polynomial.transform();
            assert!(polynomial.isNormBelow(9 * modulus));
            polynomial.inverseTransform();
            let expected = original
                .coefficients
                .map(|value| (i64::from(value) * power(2, 32)).rem_euclid(q));
            assert_eq!(canonical(&polynomial), expected, "seed {seed}");
        }
    }

    #[test]
    fn innerProductIsTheSumOfThePointwiseProducts() {
        let left: Vec<Polynomial> = (0..7)
            .map(|seed| polynomialFrom(seed, modulus - 1))
            .collect();
        let right: Vec<Polynomial> = (0..7)
            .map(|seed| polynomialFrom(seed + 9, 9 * modulus - 1))
            .collect();
        let inner = Polynomial::innerProduct(&left, &right);
        assert!(inner.isNormBelow(modulus));
        let sum = left.iter().zip(&right).fold(
            Polynomial::zero,
            |total, (leftPolynomial, rightPolynomial)| {
                total
                    .plus(&leftPolynomial.transformedProduct(rightPolynomial))
                    .reduced()
            },
        );
        assert_eq!(canonical(&inner), canonical(&sum));
    }

    #[test]
    fn sumsDifferencesAndShiftsWorkOnEachCoefficient() {
        let left = polynomialFrom(1, 1 << 20);
        let right = polynomialFrom(2, 1 << 20);
        let total = left.plus(&right);
        let difference = left.minus(&right);
        for index in 0..coefficientCount {
            assert_eq!(
                total.coefficients[index],
                left.coefficients[index] + right.coefficients[index]
            );
            assert_eq!(
                difference.coefficients[index],
                left.coefficients[index] - right.coefficients[index]
            );
        }
        let mut small = Polynomial::zero;
        small.coefficients[3] = 1023;
        small.coefficients[4] = 1;
        let shifted = small.shiftedLeft();
        assert_eq!(
            (shifted.coefficients[3], shifted.coefficients[4]),
            (1023 << 13, 1 << 13)
        );
        let reducedSum = total.reduced();
        for index in 0..coefficientCount {
            assert_eq!(
                i64::from(reducedSum.coefficients[index]).rem_euclid(q),
                i64::from(total.coefficients[index]).rem_euclid(q)
            );
        }
    }

    /// The packing functions of mldsa-native for each width, written from `poly.c` and
    /// `poly_kl.c`, as the independent answers of the generic packing.
    fn cPacked(values: &[u32; coefficientCount], bits: u32) -> Vec<u8> {
        let mut output = vec![0u8; 32 * bits as usize];
        let byte = |value: u32| (value & 0xFF) as u8;
        match bits {
            10 => {
                for (index, a) in values.chunks(4).enumerate() {
                    let r = &mut output[5 * index..5 * index + 5];
                    r[0] = byte(a[0]);
                    r[1] = byte((a[0] >> 8) | (a[1] << 2));
                    r[2] = byte((a[1] >> 6) | (a[2] << 4));
                    r[3] = byte((a[2] >> 4) | (a[3] << 6));
                    r[4] = byte(a[3] >> 2);
                }
            }
            13 => {
                for (index, t) in values.chunks(8).enumerate() {
                    let r = &mut output[13 * index..13 * index + 13];
                    r[0] = byte(t[0]);
                    r[1] = byte(t[0] >> 8) | byte(t[1] << 5);
                    r[2] = byte(t[1] >> 3);
                    r[3] = byte(t[1] >> 11) | byte(t[2] << 2);
                    r[4] = byte(t[2] >> 6) | byte(t[3] << 7);
                    r[5] = byte(t[3] >> 1);
                    r[6] = byte(t[3] >> 9) | byte(t[4] << 4);
                    r[7] = byte(t[4] >> 4);
                    r[8] = byte(t[4] >> 12) | byte(t[5] << 1);
                    r[9] = byte(t[5] >> 7) | byte(t[6] << 6);
                    r[10] = byte(t[6] >> 2);
                    r[11] = byte(t[6] >> 10) | byte(t[7] << 3);
                    r[12] = byte(t[7] >> 5);
                }
            }
            3 => {
                for (index, t) in values.chunks(8).enumerate() {
                    let r = &mut output[3 * index..3 * index + 3];
                    r[0] = byte(t[0] | (t[1] << 3) | (t[2] << 6));
                    r[1] = byte((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
                    r[2] = byte((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
                }
            }
            4 => {
                for (index, t) in values.chunks(2).enumerate() {
                    output[index] = byte(t[0] | (t[1] << 4));
                }
            }
            6 => {
                for (index, a) in values.chunks(4).enumerate() {
                    let r = &mut output[3 * index..3 * index + 3];
                    r[0] = byte(a[0]) | byte(a[1] << 6);
                    r[1] = byte(a[1] >> 2) | byte(a[2] << 4);
                    r[2] = byte(a[2] >> 4) | byte(a[3] << 2);
                }
            }
            18 => {
                for (index, t) in values.chunks(4).enumerate() {
                    let r = &mut output[9 * index..9 * index + 9];
                    r[0] = byte(t[0]);
                    r[1] = byte(t[0] >> 8);
                    r[2] = byte(t[0] >> 16) | byte(t[1] << 2);
                    r[3] = byte(t[1] >> 6);
                    r[4] = byte(t[1] >> 14) | byte(t[2] << 4);
                    r[5] = byte(t[2] >> 4);
                    r[6] = byte(t[2] >> 12) | byte(t[3] << 6);
                    r[7] = byte(t[3] >> 2);
                    r[8] = byte(t[3] >> 10);
                }
            }
            20 => {
                for (index, t) in values.chunks(2).enumerate() {
                    let r = &mut output[5 * index..5 * index + 5];
                    r[0] = byte(t[0]);
                    r[1] = byte(t[0] >> 8);
                    r[2] = byte(t[0] >> 16) | byte(t[1] << 4);
                    r[3] = byte(t[1] >> 4);
                    r[4] = byte(t[1] >> 12);
                }
            }
            _ => unreachable!("no packing of {bits} bits"),
        }
        output
    }

    #[test]
    fn packingGivesTheBytesOfThePackingFunctionsOfMLDSANative() {
        for bits in [3u32, 4, 6, 10, 13, 18, 20] {
            for seed in 0..4 {
                let bytes = seededBytes(u64::from(bits) * 10 + seed, 4 * coefficientCount);
                let mut values = [0u32; coefficientCount];
                for (value, chunk) in values.iter_mut().zip(bytes.chunks(4)) {
                    *value = u32::from_le_bytes(chunk.try_into().expect("4 bytes")) % (1 << bits);
                }
                let mut polynomial = Polynomial::zero;
                for (coefficient, value) in polynomial.coefficients.iter_mut().zip(values) {
                    *coefficient = value as i32;
                }
                let mut packed = vec![0u8; 32 * bits as usize];
                polynomial.simplePacked(bits, &mut packed);
                assert_eq!(packed, cPacked(&values, bits), "{bits} bits");
                assert_eq!(Polynomial::simpleUnpacked(bits, &packed), polynomial);
                // BitPack stores `bound - coefficient`.
                let bound: i32 = 1 << (bits - 1);
                let mut offset = Polynomial::zero;
                for (coefficient, value) in offset.coefficients.iter_mut().zip(values) {
                    *coefficient = bound - value as i32;
                }
                offset.boundPacked(bound, bits, &mut packed);
                assert_eq!(packed, cPacked(&values, bits), "{bits} bits");
                assert_eq!(Polynomial::boundUnpacked(bound, bits, &packed), offset);
            }
        }
    }

    #[test]
    fn unpackingReadsAnyBytesAsTheUnpackingFunctionsOfMLDSANative() {
        // `mld_polyz_unpack` for 18 bits, `mld_polyt0_unpack` and `mld_polyeta_unpack` for
        // eta 2, of bytes that no packing gives.
        let bytes = seededBytes(77, 32 * 18);
        let z = Polynomial::boundUnpacked(1 << 17, 18, &bytes);
        for index in 0..coefficientCount / 4 {
            let a = |offset: usize| i32::from(bytes[9 * index + offset]);
            let expected = [
                (a(0) | (a(1) << 8) | (a(2) << 16)) & 0x3FFFF,
                ((a(2) >> 2) | (a(3) << 6) | (a(4) << 14)) & 0x3FFFF,
                ((a(4) >> 4) | (a(5) << 4) | (a(6) << 12)) & 0x3FFFF,
                ((a(6) >> 6) | (a(7) << 2) | (a(8) << 10)) & 0x3FFFF,
            ];
            for (offset, value) in expected.iter().enumerate() {
                assert_eq!(z.coefficients[4 * index + offset], (1 << 17) - value);
            }
        }
        let bytes = seededBytes(78, 32 * 13);
        let low = Polynomial::boundUnpacked(1 << 12, 13, &bytes);
        for index in 0..coefficientCount / 8 {
            let a = |offset: usize| i32::from(bytes[13 * index + offset]);
            let first = (a(0) | (a(1) << 8)) & 0x1FFF;
            let fourth = ((a(4) >> 7) | (a(5) << 1) | (a(6) << 9)) & 0x1FFF;
            let last = ((a(11) >> 3) | (a(12) << 5)) & 0x1FFF;
            assert_eq!(low.coefficients[8 * index], (1 << 12) - first);
            assert_eq!(low.coefficients[8 * index + 3], (1 << 12) - fourth);
            assert_eq!(low.coefficients[8 * index + 7], (1 << 12) - last);
        }
        let bytes = seededBytes(79, 96);
        let short = Polynomial::boundUnpacked(2, 3, &bytes);
        for index in 0..coefficientCount / 8 {
            let a = |offset: usize| i32::from(bytes[3 * index + offset]);
            assert_eq!(short.coefficients[8 * index], 2 - (a(0) & 7));
            assert_eq!(
                short.coefficients[8 * index + 2],
                2 - (((a(0) >> 6) | (a(1) << 2)) & 7)
            );
            assert_eq!(
                short.coefficients[8 * index + 5],
                2 - (((a(1) >> 7) | (a(2) << 1)) & 7)
            );
            assert_eq!(short.coefficients[8 * index + 7], 2 - ((a(2) >> 5) & 7));
        }
    }

    #[test]
    fn boundedCoefficientsAreTheCoeffFromHalfByteOfFIPS204() {
        for halfByte in 0..16u8 {
            let expectedNarrow = (halfByte < 15).then(|| 2 - i32::from(halfByte % 5));
            assert_eq!(
                Polynomial::boundedCoefficient(2, halfByte),
                expectedNarrow,
                "{halfByte}"
            );
            let expectedWide = (halfByte < 9).then(|| 4 - i32::from(halfByte));
            assert_eq!(
                Polynomial::boundedCoefficient(4, halfByte),
                expectedWide,
                "{halfByte}"
            );
        }
    }

    #[test]
    fn samplesStayInTheirRangesAndDependOnTheirSeeds() {
        let seed = [9u8; 32];
        let uniform = Polynomial::sampledUniform(&seed, 1, 2);
        assert!(
            uniform
                .coefficients
                .iter()
                .all(|value| (0..modulus).contains(value))
        );
        assert_ne!(uniform, Polynomial::sampledUniform(&seed, 2, 1));
        let wideSeed = [5u8; 64];
        for eta in [2, 4] {
            let short = Polynomial::sampledShort(eta, &wideSeed, 3);
            assert!(short.isNormBelow(eta + 1));
            assert!(!short.isNormBelow(eta), "eta {eta} reaches its bound");
            assert_ne!(short, Polynomial::sampledShort(eta, &wideSeed, 4));
        }
        for gamma1Bits in [17, 19] {
            let gamma1 = 1 << gamma1Bits;
            let mask = Polynomial::sampledMask(gamma1Bits, &wideSeed, 300);
            assert!(
                mask.coefficients
                    .iter()
                    .all(|value| (-(gamma1 - 1)..=gamma1).contains(value))
            );
            assert_ne!(mask, Polynomial::sampledMask(gamma1Bits, &wideSeed, 301));
        }
    }

    #[test]
    fn challengesHaveTauCoefficientsOfOneOrMinusOne() {
        for (tau, seed) in [(39usize, 1u64), (49, 2), (60, 3)] {
            let commitmentHash = seededBytes(seed, 48);
            let challenge = Polynomial::sampledInBall(tau, &commitmentHash);
            let nonZero = challenge
                .coefficients
                .iter()
                .filter(|value| **value != 0)
                .count();
            assert_eq!(nonZero, tau);
            assert!(challenge.isNormBelow(2));
            assert_ne!(
                challenge,
                Polynomial::sampledInBall(tau, &commitmentHash[1..])
            );
        }
    }
}
