use crate::primeModulus::PrimeModulus;
use crate::smallPrime::smallPrimes;

/// The big integers of the NTRU solver, the `zint_*` functions of `keygen.c` of the Falcon code
/// of PQClean.
///
/// A big integer is a slice of 31-bit words, the least significant word first, with the top bit
/// of each word clear. A signed big integer uses the two's complement over all its words. The
/// functions keep the operations of the C code, with no branch on the values.
pub(crate) struct BigInteger;

/// The mask of the 31 bits of a word.
const wordMask: u32 = 0x7FFF_FFFF;

impl BigInteger {
    /// Subtracts `b` from `a` when `control` is 1, and leaves `a` as it is when `control` is 0.
    /// Returns the borrow either way, as `zint_sub` does.
    pub(crate) fn subtract(a: &mut [u32], b: &[u32], control: u32) -> u32 {
        let mut borrow = 0u32;
        let mask = control.wrapping_neg();
        for (word, other) in a.iter_mut().zip(b) {
            let value = word.wrapping_sub(*other).wrapping_sub(borrow);
            borrow = value >> 31;
            *word ^= ((value & wordMask) ^ *word) & mask;
        }
        borrow
    }

    /// Multiplies a big integer by a small value below `2^31` in place, and returns the carry
    /// word, as `zint_mul_small` does.
    pub(crate) fn multiplySmall(value: &mut [u32], factor: u32) -> u32 {
        let mut carry = 0u32;
        for word in value.iter_mut() {
            let product = u64::from(*word) * u64::from(factor) + u64::from(carry);
            *word = (product as u32) & wordMask;
            carry = (product >> 31) as u32;
        }
        carry
    }

    /// An unsigned big integer modulo a small prime, as `zint_mod_small_unsigned` does.
    pub(crate) fn unsignedResidue(value: &[u32], modulus: &PrimeModulus) -> u32 {
        // Horner's rule from the top word: multiply by 2^31 and add the next word.
        let mut residue = 0u32;
        for word in value.iter().rev() {
            residue = modulus.product(residue, modulus.r2);
            let reduced = word.wrapping_sub(modulus.p);
            let reduced = reduced.wrapping_add(modulus.p & (reduced >> 31).wrapping_neg());
            residue = modulus.sum(residue, reduced);
        }
        residue
    }

    /// A signed big integer modulo a small prime, with `rx = 2^(31 len) mod p`, as
    /// `zint_mod_small_signed` does.
    pub(crate) fn signedResidue(value: &[u32], modulus: &PrimeModulus, rx: u32) -> u32 {
        let Some(top) = value.last() else {
            return 0;
        };
        let residue = Self::unsignedResidue(value, modulus);
        modulus.difference(residue, rx & (top >> 30).wrapping_neg())
    }

    /// Adds `y s` to `x`, where `x` has one word more than `y` and receives the carry in its
    /// last word, as `zint_add_mul_small` does.
    pub(crate) fn addMultiple(x: &mut [u32], y: &[u32], factor: u32) {
        let mut carry = 0u32;
        for (word, other) in x.iter_mut().zip(y) {
            let value = u64::from(*other) * u64::from(factor) + u64::from(*word) + u64::from(carry);
            *word = (value as u32) & wordMask;
            carry = (value >> 31) as u32;
        }
        x[y.len()] = carry;
    }

    /// Replaces `x` with `x - p` when `x > (p - 1)/2`, for an odd modulus `p` of the same
    /// length, as `zint_norm_zero` does.
    pub(crate) fn normalizeAroundZero(x: &mut [u32], modulus: &[u32]) {
        // The comparison of x with (p - 1)/2 from the top word: -1, 0 or 1.
        let mut comparison = 0u32;
        let mut carriedBit = 0u32;
        for (word, modulusWord) in x.iter().zip(modulus).rev() {
            let halfWord = (modulusWord >> 1) | (carriedBit << 30);
            carriedBit = modulusWord & 1;
            let difference = halfWord.wrapping_sub(*word);
            let sign = (difference.wrapping_neg() >> 31) | (difference >> 31).wrapping_neg();
            comparison |= sign & (comparison & 1).wrapping_sub(1);
        }
        Self::subtract(x, modulus, comparison >> 31);
    }

    /// Rebuilds `count` big integers of `length` words from their residues modulo the first
    /// small primes, in place, as `zint_rebuild_CRT` does. Integer `v` starts at `v stride`.
    /// The signed form normalizes each value around zero. The scratch space holds `length`
    /// words.
    pub(crate) fn rebuildFromResidues(
        values: &mut [u32],
        length: usize,
        stride: usize,
        count: usize,
        isSigned: bool,
        scratch: &mut [u32],
    ) {
        // The scratch space holds the product q of the primes done so far.
        scratch[0] = smallPrimes[0].p;
        for u in 1..length {
            let prime = smallPrimes[u];
            let modulus = PrimeModulus::new(prime.p);
            for v in 0..count {
                let x = &mut values[v * stride..v * stride + u + 1];
                // x mod p, and (x mod q) mod p, give x mod q p.
                let residue = x[u];
                let lower = Self::unsignedResidue(&x[..u], &modulus);
                let factor = modulus.product(prime.s, modulus.difference(residue, lower));
                Self::addMultiple(x, &scratch[..u], factor);
            }
            scratch[u] = Self::multiplySmall(&mut scratch[..u], prime.p);
        }
        if isSigned {
            for v in 0..count {
                Self::normalizeAroundZero(
                    &mut values[v * stride..v * stride + length],
                    &scratch[..length],
                );
            }
        }
    }

    /// Negates a big integer when `control` is 1, as `zint_negate` does.
    pub(crate) fn negate(value: &mut [u32], control: u32) {
        let mut carry = control;
        let mask = control.wrapping_neg() >> 1;
        for word in value.iter_mut() {
            let flipped = (*word ^ mask).wrapping_add(carry);
            *word = flipped & wordMask;
            carry = flipped >> 31;
        }
    }

    /// Replaces `a` with `(a xa + b xb) / 2^31` and `b` with `(a ya + b yb) / 2^31`, negating
    /// each result that is negative, as `zint_co_reduce` does. Returns bit 0 when `a` was
    /// negated and bit 1 when `b` was.
    pub(crate) fn coReduce(
        a: &mut [u32],
        b: &mut [u32],
        xa: i64,
        xb: i64,
        ya: i64,
        yb: i64,
    ) -> u32 {
        let length = a.len();
        let mut carryA = 0i64;
        let mut carryB = 0i64;
        for u in 0..length {
            let (wa, wb) = (u64::from(a[u]), u64::from(b[u]));
            let za = wa
                .wrapping_mul(xa as u64)
                .wrapping_add(wb.wrapping_mul(xb as u64))
                .wrapping_add(carryA as u64);
            let zb = wa
                .wrapping_mul(ya as u64)
                .wrapping_add(wb.wrapping_mul(yb as u64))
                .wrapping_add(carryB as u64);
            if u > 0 {
                a[u - 1] = (za as u32) & wordMask;
                b[u - 1] = (zb as u32) & wordMask;
            }
            carryA = (za as i64) >> 31;
            carryB = (zb as i64) >> 31;
        }
        a[length - 1] = carryA as u32;
        b[length - 1] = carryB as u32;
        let isNegativeA = ((carryA as u64) >> 63) as u32;
        let isNegativeB = ((carryB as u64) >> 63) as u32;
        Self::negate(a, isNegativeA);
        Self::negate(b, isNegativeB);
        isNegativeA | (isNegativeB << 1)
    }

    /// Finishes a modular reduction by an odd modulus `m`: for `isNegative = 1`, `-m <= a < 0`
    /// and `m` is added, and else `0 <= a < 2 m` and `m` is subtracted when `a >= m`, as
    /// `zint_finish_mod` does.
    pub(crate) fn finishReduction(a: &mut [u32], modulus: &[u32], isNegative: u32) {
        let mut borrow = 0u32;
        for (word, modulusWord) in a.iter().zip(modulus) {
            borrow = word.wrapping_sub(*modulusWord).wrapping_sub(borrow) >> 31;
        }
        // The words of m or -m, and zero when nothing is to subtract.
        let flip = isNegative.wrapping_neg() >> 1;
        let keep = (isNegative | 1u32.wrapping_sub(borrow)).wrapping_neg();
        let mut carry = isNegative;
        for (word, modulusWord) in a.iter_mut().zip(modulus) {
            let subtrahend = (modulusWord ^ flip) & keep;
            let value = word.wrapping_sub(subtrahend).wrapping_sub(carry);
            *word = value & wordMask;
            carry = value >> 31;
        }
    }

    /// Replaces `a` with `(a xa + b xb) / 2^31 mod m` and `b` with `(a ya + b yb) / 2^31 mod m`,
    /// for an odd modulus `m` with `m0i = -1/m[0] mod 2^31`, as `zint_co_reduce_mod` does.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn coReduceModulo(
        a: &mut [u32],
        b: &mut [u32],
        modulus: &[u32],
        m0i: u32,
        xa: i64,
        xb: i64,
        ya: i64,
        yb: i64,
    ) {
        let length = a.len();
        let mut carryA = 0i64;
        let mut carryB = 0i64;
        // Four Montgomery multiplications in one: the factors that clear the low word.
        let factorA = (a[0]
            .wrapping_mul(xa as u32)
            .wrapping_add(b[0].wrapping_mul(xb as u32)))
        .wrapping_mul(m0i)
            & wordMask;
        let factorB = (a[0]
            .wrapping_mul(ya as u32)
            .wrapping_add(b[0].wrapping_mul(yb as u32)))
        .wrapping_mul(m0i)
            & wordMask;
        for u in 0..length {
            let (wa, wb) = (u64::from(a[u]), u64::from(b[u]));
            let modulusWord = u64::from(modulus[u]);
            let za = wa
                .wrapping_mul(xa as u64)
                .wrapping_add(wb.wrapping_mul(xb as u64))
                .wrapping_add(modulusWord.wrapping_mul(u64::from(factorA)))
                .wrapping_add(carryA as u64);
            let zb = wa
                .wrapping_mul(ya as u64)
                .wrapping_add(wb.wrapping_mul(yb as u64))
                .wrapping_add(modulusWord.wrapping_mul(u64::from(factorB)))
                .wrapping_add(carryB as u64);
            if u > 0 {
                a[u - 1] = (za as u32) & wordMask;
                b[u - 1] = (zb as u32) & wordMask;
            }
            carryA = (za as i64) >> 31;
            carryB = (zb as i64) >> 31;
        }
        a[length - 1] = carryA as u32;
        b[length - 1] = carryB as u32;
        // Now -m <= a, b < 2 m.
        Self::finishReduction(a, modulus, ((carryA as u64) >> 63) as u32);
        Self::finishReduction(b, modulus, ((carryB as u64) >> 63) as u32);
    }

    /// The extended binary GCD of two odd big integers `x` and `y` of the same length, as
    /// `zint_bezout` does: true when the GCD is 1, and then `x u - y v = 1` with `0 <= u <= y`
    /// and `0 <= v <= x`. The scratch space holds four integers of the length.
    pub(crate) fn bezout(
        u0: &mut [u32],
        v0: &mut [u32],
        x: &[u32],
        y: &[u32],
        scratch: &mut [u32],
    ) -> bool {
        let length = x.len();
        if length == 0 {
            return false;
        }
        let (u1, rest) = scratch.split_at_mut(length);
        let (v1, rest) = rest.split_at_mut(length);
        let (a, rest) = rest.split_at_mut(length);
        let b = &mut rest[..length];
        let x0i = PrimeModulus::negativeInverse(x[0]);
        let y0i = PrimeModulus::negativeInverse(y[0]);
        // a = x, u0 = 1, v0 = 0, b = y, u1 = y, v1 = x - 1, with a = x u0 - y v0 and
        // b = x u1 - y v1 kept at each step.
        a.copy_from_slice(x);
        b.copy_from_slice(y);
        u0.fill(0);
        u0[0] = 1;
        v0.fill(0);
        u1.copy_from_slice(y);
        v1.copy_from_slice(x);
        v1[0] = v1[0].wrapping_sub(1);
        // Each step removes at least 30 bits from the total length of a and b.
        let mut remaining = 62 * length as u32 + 30;
        while remaining >= 30 {
            // The top two words of a and b at the highest index where either is nonzero, or
            // the low words when both are down to one word.
            let mut c0 = u32::MAX;
            let mut c1 = u32::MAX;
            let (mut a0, mut a1, mut b0, mut b1) = (0u32, 0u32, 0u32, 0u32);
            for j in (0..length).rev() {
                let (aw, bw) = (a[j], b[j]);
                a0 ^= (a0 ^ aw) & c0;
                a1 ^= (a1 ^ aw) & c1;
                b0 ^= (b0 ^ bw) & c0;
                b1 ^= (b1 ^ bw) & c1;
                c1 = c0;
                c0 &= ((aw | bw).wrapping_add(wordMask) >> 31).wrapping_sub(1);
            }
            a1 |= a0 & c1;
            a0 &= !c1;
            b1 |= b0 & c1;
            b0 &= !c1;
            let mut aHigh = (u64::from(a0) << 31).wrapping_add(u64::from(a1));
            let mut bHigh = (u64::from(b0) << 31).wrapping_add(u64::from(b1));
            let mut aLow = a[0];
            let mut bLow = b[0];
            // The factors of 31 steps of the bit-by-bit algorithm, from the extracted words.
            let (mut pa, mut pb, mut qa, mut qb) = (1i64, 0i64, 0i64, 1i64);
            for i in 0..31 {
                let difference = bHigh.wrapping_sub(aHigh);
                let isAAbove =
                    ((difference ^ ((aHigh ^ bHigh) & (aHigh ^ difference))) >> 63) as u32;
                let isAOdd = (aLow >> i) & 1;
                let isBOdd = (bLow >> i) & 1;
                let subtractsB = isAOdd & isBOdd & isAAbove;
                let subtractsA = isAOdd & isBOdd & !isAAbove;
                let halvesA = subtractsB | (isAOdd ^ 1);
                aLow = aLow.wrapping_sub(bLow & subtractsB.wrapping_neg());
                aHigh = aHigh.wrapping_sub(bHigh & u64::from(subtractsB).wrapping_neg());
                pa = pa.wrapping_sub(qa & -i64::from(subtractsB));
                pb = pb.wrapping_sub(qb & -i64::from(subtractsB));
                bLow = bLow.wrapping_sub(aLow & subtractsA.wrapping_neg());
                bHigh = bHigh.wrapping_sub(aHigh & u64::from(subtractsA).wrapping_neg());
                qa = qa.wrapping_sub(pa & -i64::from(subtractsA));
                qb = qb.wrapping_sub(pb & -i64::from(subtractsA));
                // A division by 2 is a missing multiplication by 2 of the low words.
                aLow = aLow.wrapping_add(aLow & halvesA.wrapping_sub(1));
                pa = pa.wrapping_add(pa & (i64::from(halvesA) - 1));
                pb = pb.wrapping_add(pb & (i64::from(halvesA) - 1));
                aHigh ^= (aHigh ^ (aHigh >> 1)) & u64::from(halvesA).wrapping_neg();
                bLow = bLow.wrapping_add(bLow & halvesA.wrapping_neg());
                qa = qa.wrapping_add(qa & -i64::from(halvesA));
                qb = qb.wrapping_add(qb & -i64::from(halvesA));
                bHigh ^= (bHigh ^ (bHigh >> 1)) & u64::from(halvesA).wrapping_sub(1);
            }
            // Apply the factors, and negate them where a or b came out negative.
            let negations = Self::coReduce(a, b, pa, pb, qa, qb);
            let isANegated = -i64::from(negations & 1);
            let isBNegated = -i64::from(negations >> 1);
            pa = pa.wrapping_sub(pa.wrapping_add(pa) & isANegated);
            pb = pb.wrapping_sub(pb.wrapping_add(pb) & isANegated);
            qa = qa.wrapping_sub(qa.wrapping_add(qa) & isBNegated);
            qb = qb.wrapping_sub(qb.wrapping_add(qb) & isBNegated);
            Self::coReduceModulo(u0, u1, y, y0i, pa, pb, qa, qb);
            Self::coReduceModulo(v0, v1, x, x0i, pa, pb, qa, qb);
            remaining -= 30;
        }
        // a holds the GCD, which must be 1, and x and y must be odd.
        let mut nonOne = a[0] ^ 1;
        for word in &a[1..] {
            nonOne |= word;
        }
        (1u32.wrapping_sub((nonOne | nonOne.wrapping_neg()) >> 31) & x[0] & y[0]) != 0
    }

    /// Adds `k y 2^(31 wordShift + bitShift)` to `x`, truncated to the length of `x`, for signed
    /// `x` and `y`, as `zint_add_scaled_mul_small` does.
    pub(crate) fn addScaledMultiple(
        x: &mut [u32],
        y: &[u32],
        factor: i32,
        wordShift: usize,
        bitShift: u32,
    ) {
        let Some(top) = y.last() else {
            return;
        };
        let signWord = (top >> 30).wrapping_neg() >> 1;
        let mut carriedBits = 0u32;
        let mut carry = 0i32;
        for (position, word) in x.iter_mut().skip(wordShift).enumerate() {
            let source = y.get(position).copied().unwrap_or(signWord);
            let shifted = ((source << bitShift) & wordMask) | carriedBits;
            carriedBits = source >> (31 - bitShift);
            // The expression does not overflow.
            let value = (i64::from(shifted) * i64::from(factor)
                + i64::from(*word)
                + i64::from(carry)) as u64;
            *word = (value as u32) & wordMask;
            carry = ((value >> 31) as u32) as i32;
        }
    }

    /// Subtracts `y 2^(31 wordShift + bitShift)` from `x`, truncated to the length of `x`, for
    /// signed `x` and `y`, as `zint_sub_scaled` does.
    pub(crate) fn subtractScaled(x: &mut [u32], y: &[u32], wordShift: usize, bitShift: u32) {
        let Some(top) = y.last() else {
            return;
        };
        let signWord = (top >> 30).wrapping_neg() >> 1;
        let mut carriedBits = 0u32;
        let mut borrow = 0u32;
        for (position, word) in x.iter_mut().skip(wordShift).enumerate() {
            let source = y.get(position).copied().unwrap_or(signWord);
            let shifted = ((source << bitShift) & wordMask) | carriedBits;
            carriedBits = source >> (31 - bitShift);
            let value = word.wrapping_sub(shifted).wrapping_sub(borrow);
            *word = value & wordMask;
            borrow = value >> 31;
        }
    }

    /// The value of a signed one-word big integer, as `zint_one_to_plain` does.
    pub(crate) fn oneWordValue(word: u32) -> i32 {
        (word | ((word & 0x4000_0000) << 1)) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::BigInteger;
    use crate::primeModulus::PrimeModulus;
    use crate::smallPrime::smallPrimes;

    /// The words of a nonnegative value, least significant first.
    fn words(value: u128, length: usize) -> Vec<u32> {
        (0..length)
            .map(|index| ((value >> (31 * index)) & 0x7FFF_FFFF) as u32)
            .collect()
    }

    /// The value of the words, which must fit in 128 bits.
    fn value(words: &[u32]) -> u128 {
        words
            .iter()
            .rev()
            .fold(0u128, |value, word| (value << 31) | u128::from(*word))
    }

    /// The words of a signed value in two's complement over the length.
    fn signedWords(value: i128, length: usize) -> Vec<u32> {
        let modulus = 1i128 << (31 * length);
        words(value.rem_euclid(modulus) as u128, length)
    }

    #[test]
    fn arithmeticOfWordsGivesTheValuesOfTheIntegers() {
        let x = words(0x1234_5678_9ABC_DEF0_1122_3344, 4);
        let y = words(0x0FED_CBA9_8765_4321, 4);
        let mut difference = x.clone();
        assert_eq!(BigInteger::subtract(&mut difference, &y, 1), 0);
        assert_eq!(
            value(&difference),
            0x1234_5678_9ABC_DEF0_1122_3344 - 0x0FED_CBA9_8765_4321
        );
        let mut unchanged = x.clone();
        assert_eq!(BigInteger::subtract(&mut unchanged, &y, 0), 0);
        assert_eq!(unchanged, x);
        let mut borrowed = y.clone();
        assert_eq!(BigInteger::subtract(&mut borrowed, &x, 1), 1);
        let mut product = x.clone();
        product.push(0);
        assert_eq!(BigInteger::multiplySmall(&mut product, 12289), 0);
        assert_eq!(value(&product), 0x1234_5678_9ABC_DEF0_1122_3344 * 12289);
        let mut sum = vec![5, 0, 0, 0, 0];
        BigInteger::addMultiple(&mut sum, &x, 3);
        assert_eq!(value(&sum), 5 + 3 * 0x1234_5678_9ABC_DEF0_1122_3344);
        for value in [-3i128, 0, 7, -(1 << 61), 1 << 61] {
            let mut negated = signedWords(value, 3);
            BigInteger::negate(&mut negated, 1);
            assert_eq!(negated, signedWords(-value, 3), "{value}");
        }
        assert_eq!(BigInteger::oneWordValue(0x7FFF_FFFF), -1);
        assert_eq!(BigInteger::oneWordValue(0x3FFF_FFFF), 0x3FFF_FFFF);
        assert_eq!(BigInteger::oneWordValue(0xFFFF_FFF0), -16);
    }

    #[test]
    fn residuesAreTheValuesModuloAPrime() {
        let modulus = PrimeModulus::new(smallPrimes[3].p);
        let p = i128::from(modulus.p);
        for number in [0i128, 1, 12289, (1 << 90) + 12345, -1, -(1 << 80) - 7] {
            let integer = signedWords(number, 3);
            if number >= 0 {
                assert_eq!(
                    i128::from(BigInteger::unsignedResidue(&integer, &modulus)),
                    number % p
                );
            }
            let rx = modulus.powerOfR(3);
            assert_eq!(
                i128::from(BigInteger::signedResidue(&integer, &modulus, rx)),
                number.rem_euclid(p),
                "{number}"
            );
        }
        assert_eq!(BigInteger::signedResidue(&[], &modulus, 0), 0);
    }

    #[test]
    fn rebuildingFromResiduesGivesTheIntegers() {
        // Two integers of three words, as residues modulo the first three primes, at stride 4.
        // Both lie within half the product of the primes.
        let numbers = [(1i128 << 80) + 12345, -(1i128 << 70) - 99];
        let mut values = vec![0u32; 8];
        for (index, number) in numbers.iter().enumerate() {
            for (u, prime) in smallPrimes[..3].iter().enumerate() {
                values[4 * index + u] = number.rem_euclid(i128::from(prime.p)) as u32;
            }
        }
        let mut scratch = vec![0u32; 3];
        BigInteger::rebuildFromResidues(&mut values, 3, 4, 2, true, &mut scratch);
        let product: i128 = smallPrimes[..3]
            .iter()
            .map(|prime| i128::from(prime.p))
            .product();
        assert_eq!(value(&scratch), product as u128);
        assert_eq!(&values[..3], signedWords(numbers[0], 3).as_slice());
        assert_eq!(&values[4..7], signedWords(numbers[1], 3).as_slice());
    }

    #[test]
    fn bezoutGivesTheCoefficientsOfTwoCoprimeIntegers() {
        // Two odd coprime values below 2^60, so that x u - y v fits in 128 bits.
        let (xv, yv) = (0x0123_4567_89AB_CDF1u128, 0x0FED_CBA9_8765_4321u128);
        let (x, y) = (words(xv, 2), words(yv, 2));
        let (mut u, mut v) = (vec![0u32; 2], vec![0u32; 2]);
        let mut scratch = vec![0u32; 8];
        assert!(BigInteger::bezout(&mut u, &mut v, &x, &y, &mut scratch));
        let (uv, vv) = (value(&u), value(&v));
        assert!(uv <= yv && vv <= xv);
        assert_eq!((xv * uv) as i128 - (yv * vv) as i128, 1);
        // An even input and a common factor fail: the second pair shares the factor 15.
        let even = words(xv + 1, 2);
        assert!(!BigInteger::bezout(&mut u, &mut v, &even, &y, &mut scratch));
        let shared = words(0x0123_4567_89AB_CDEF, 2);
        assert!(!BigInteger::bezout(
            &mut u,
            &mut v,
            &shared,
            &y,
            &mut scratch
        ));
        assert!(!BigInteger::bezout(
            &mut [],
            &mut [],
            &[],
            &[],
            &mut scratch
        ));
    }

    #[test]
    fn scaledOperationsShiftByWordsAndBits() {
        for (wordShift, bitShift) in [(0usize, 0u32), (0, 5), (1, 0), (1, 30)] {
            let shift = 31 * wordShift as u32 + bitShift;
            let x = signedWords(1 << 100, 4);
            let y = signedWords(-(1 << 40) - 3, 2);
            let mut sum = x.clone();
            BigInteger::addScaledMultiple(&mut sum, &y, -7, wordShift, bitShift);
            let expected = (1i128 << 100) + 7 * (((1i128 << 40) + 3) << shift);
            assert_eq!(sum, signedWords(expected, 4), "{wordShift} {bitShift}");
            let mut difference = x.clone();
            BigInteger::subtractScaled(&mut difference, &y, wordShift, bitShift);
            let expected = (1i128 << 100) + (((1i128 << 40) + 3) << shift);
            assert_eq!(
                difference,
                signedWords(expected, 4),
                "{wordShift} {bitShift}"
            );
        }
    }
}
