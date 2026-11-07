use crate::bigInteger::BigInteger;
use crate::floatingPoint::FloatingPoint;
use crate::fourierTransform::FourierTransform;
use crate::primeModulus::PrimeModulus;
use crate::smallPrime::smallPrimes;
use crate::solverFailure::SolverFailure;
use alloc::vec;
use alloc::vec::Vec;

/// The solver of the NTRU equation `f G - g F = q mod X^N + 1`, the `solve_NTRU_*` functions of
/// `keygen.c` of the Falcon code of PQClean.
///
/// The solver goes down to degree 1 with the field norms of `f` and `g`, solves there with the
/// extended GCD of the two resultants, and comes back up, one degree at a time, with Babai
/// reduction to keep `F` and `G` small. Big integers are kept in residues modulo the small
/// primes, or in words of 31 bits. Each level gives the next one its `F` and `G` in the layout
/// of the C code: the words of each coefficient together, `F` first.
pub(crate) struct NTRUSolver;

/// The words of each coefficient of `f` and `g` at each depth, `MAX_BL_SMALL` of `keygen.c`.
const smallLengths: [usize; 11] = [1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209];

/// The words of each coefficient of the unreduced `F` and `G` at each depth, `MAX_BL_LARGE` of
/// `keygen.c`.
const largeLengths: [usize; 10] = [2, 2, 5, 7, 12, 21, 40, 78, 157, 308];

/// The average and the standard deviation of the bit length of the coefficients of `f` and `g`
/// at each depth, `BITLENGTH` of `keygen.c`.
const bitLengths: [(i32, i32); 11] = [
    (4, 0),
    (11, 1),
    (24, 1),
    (50, 1),
    (102, 1),
    (202, 2),
    (401, 4),
    (794, 5),
    (1577, 8),
    (3138, 13),
    (6308, 25),
];

/// The largest depth at which the reduction computes `k f` with the number-theoretic
/// transform, `DEPTH_INT_FG` of `keygen.c`.
const deepestTransformDepth: usize = 4;

/// The modulus `q`.
const q: u32 = 12289;

/// The residues of a small polynomial modulo a prime.
fn smallResidues(values: &[i8], modulus: &PrimeModulus) -> Vec<u32> {
    values
        .iter()
        .map(|value| modulus.reduced(i32::from(*value)))
        .collect()
}

/// The roots of the transform and of its inverse for a prime and a degree.
fn roots(prime: usize, logn: u32) -> (PrimeModulus, Vec<u32>, Vec<u32>) {
    let modulus = PrimeModulus::new(smallPrimes[prime].p);
    let n = 1usize << logn;
    let (mut forward, mut inverse) = (vec![0u32; n], vec![0u32; n]);
    modulus.fillRoots(&mut forward, &mut inverse, smallPrimes[prime].g, logn);
    (modulus, forward, inverse)
}

/// The transforms of `f'(X^2) = f adj(f)` from the values of `f` at pairs of roots: the
/// product of the two values of each pair, as `make_fg_step` and `modp_poly_rec_res` compute it.
fn pairProduct(modulus: &PrimeModulus, first: u32, second: u32) -> u32 {
    modulus.product(modulus.product(first, second), modulus.r2)
}

impl NTRUSolver {
    /// Solves the NTRU equation for `f` and `g` of degree `2^logn`, as `solve_NTRU` does: the
    /// polynomial `F` when a solution with coefficients within `limit` exists and checks out
    /// modulo the first prime, and else the step that fails.
    pub(crate) fn solution(
        f: &[i8],
        g: &[i8],
        logn: u32,
        limit: i32,
    ) -> Result<Vec<i8>, SolverFailure> {
        let n = 1usize << logn;
        let mut solution = Self::deepest(f, g, logn).ok_or(SolverFailure::deepest)?;
        if logn <= 2 {
            // The coefficients are too large for the special code of the two top levels.
            for depth in (0..logn as usize).rev() {
                solution = Self::intermediate(f, g, logn, depth, &solution)
                    .ok_or(SolverFailure::intermediate)?;
            }
        } else {
            for depth in (2..logn as usize).rev() {
                solution = Self::intermediate(f, g, logn, depth, &solution)
                    .ok_or(SolverFailure::intermediate)?;
            }
            solution = Self::depthOne(f, g, logn, &solution).ok_or(SolverFailure::depthOne)?;
            solution = Self::depthZero(f, g, logn, &solution);
        }
        let bigF =
            Self::smallPolynomial(&solution[..n], limit).ok_or(SolverFailure::bigFOutOfRange)?;
        let bigG = Self::smallPolynomial(&solution[n..2 * n], limit)
            .ok_or(SolverFailure::bigGOutOfRange)?;
        // f G - g F = q, checked modulo the first prime in the transform.
        let (modulus, forward, _) = roots(0, logn);
        let mut transformed = [f, g, &bigF, &bigG].map(|values| smallResidues(values, &modulus));
        for values in transformed.iter_mut() {
            modulus.transform(values, 1, &forward, logn);
        }
        let [ft, gt, bigFt, bigGt] = &transformed;
        let expected = modulus.product(q, 1);
        let isSolution = (0..n).all(|u| {
            modulus.difference(
                modulus.product(ft[u], bigGt[u]),
                modulus.product(gt[u], bigFt[u]),
            ) == expected
        });
        if isSolution {
            Ok(bigF)
        } else {
            Err(SolverFailure::equationNotSatisfied)
        }
    }

    /// The coefficients of one-word signed big integers, as `poly_big_to_small` does, or `None`
    /// when one is outside `-limit..=limit`.
    fn smallPolynomial(words: &[u32], limit: i32) -> Option<Vec<i8>> {
        words
            .iter()
            .map(|word| {
                let value = BigInteger::oneWordValue(*word);
                (-limit..=limit).contains(&value).then_some(value as i8)
            })
            .collect()
    }

    /// The field norms of `f` and `g` one degree down, as `make_fg_step` does: from `N`
    /// coefficients of `slen` words, in residues and in the transform when `isInTransform`, to
    /// `N / 2` coefficients of `tlen` words, in the transform when `isOutTransform`.
    fn halvedPair(
        data: &[u32],
        logn: u32,
        depth: usize,
        isInTransform: bool,
        isOutTransform: bool,
    ) -> Vec<u32> {
        let n = 1usize << logn;
        let hn = n >> 1;
        let slen = smallLengths[depth];
        let tlen = smallLengths[depth + 1];
        let mut fs = data[..n * slen].to_vec();
        let mut gs = data[n * slen..2 * n * slen].to_vec();
        let mut halved = vec![0u32; 2 * hn * tlen];
        let mut values = vec![0u32; n];
        // The first slen words: the residues are there, and the transform is undone as they
        // are used.
        for u in 0..slen {
            let (modulus, forward, inverse) = roots(u, logn);
            for (source, target) in [(&mut fs, 0), (&mut gs, hn * tlen)] {
                for (v, value) in values.iter_mut().enumerate() {
                    *value = source[v * slen + u];
                }
                if !isInTransform {
                    modulus.transform(&mut values, 1, &forward, logn);
                }
                for v in 0..hn {
                    halved[target + v * tlen + u] =
                        pairProduct(&modulus, values[2 * v], values[2 * v + 1]);
                }
                if isInTransform {
                    modulus.inverseTransform(&mut source[u..], slen, &inverse, logn);
                }
            }
            if !isOutTransform {
                let (fd, gd) = halved.split_at_mut(hn * tlen);
                modulus.inverseTransform(&mut fd[u..], tlen, &inverse, logn - 1);
                modulus.inverseTransform(&mut gd[u..], tlen, &inverse, logn - 1);
            }
        }
        // The other words: the values come back from the residues, and are reduced again.
        let mut scratch = vec![0u32; slen];
        BigInteger::rebuildFromResidues(&mut fs, slen, slen, n, true, &mut scratch);
        BigInteger::rebuildFromResidues(&mut gs, slen, slen, n, true, &mut scratch);
        for u in slen..tlen {
            let (modulus, forward, inverse) = roots(u, logn);
            let rx = modulus.powerOfR(slen as u32);
            for (source, target) in [(&fs, 0), (&gs, hn * tlen)] {
                for (v, value) in values.iter_mut().enumerate() {
                    *value =
                        BigInteger::signedResidue(&source[v * slen..(v + 1) * slen], &modulus, rx);
                }
                modulus.transform(&mut values, 1, &forward, logn);
                for v in 0..hn {
                    halved[target + v * tlen + u] =
                        pairProduct(&modulus, values[2 * v], values[2 * v + 1]);
                }
            }
            if !isOutTransform {
                let (fd, gd) = halved.split_at_mut(hn * tlen);
                modulus.inverseTransform(&mut fd[u..], tlen, &inverse, logn - 1);
                modulus.inverseTransform(&mut gd[u..], tlen, &inverse, logn - 1);
            }
        }
        halved
    }

    /// `f` and `g` at a depth, as `make_fg` does: `2^(logn - depth)` coefficients of
    /// `MAX_BL_SMALL[depth]` words each, `f` first, in residues, and in the transform when
    /// `isOutTransform`.
    fn pairAtDepth(f: &[i8], g: &[i8], logn: u32, depth: usize, isOutTransform: bool) -> Vec<u32> {
        let n = 1usize << logn;
        let (modulus, forward, _) = roots(0, logn);
        let mut data = smallResidues(&f[..n], &modulus);
        data.extend(smallResidues(&g[..n], &modulus));
        if depth == 0 {
            if isOutTransform {
                let (ft, gt) = data.split_at_mut(n);
                modulus.transform(ft, 1, &forward, logn);
                modulus.transform(gt, 1, &forward, logn);
            }
            return data;
        }
        if depth == 1 {
            return Self::halvedPair(&data, logn, 0, false, isOutTransform);
        }
        data = Self::halvedPair(&data, logn, 0, false, true);
        for d in 1..depth - 1 {
            data = Self::halvedPair(&data, logn - d as u32, d, true, true);
        }
        Self::halvedPair(
            &data,
            logn - depth as u32 + 1,
            depth - 1,
            true,
            isOutTransform,
        )
    }

    /// The deepest level, as `solve_NTRU_deepest` does: `F` and `G` of degree 1 from the
    /// resultants of `f` and `g` with `X^N + 1`, by the extended GCD, times `q`.
    fn deepest(f: &[i8], g: &[i8], logn: u32) -> Option<Vec<u32>> {
        let length = smallLengths[logn as usize];
        let mut resultants = Self::pairAtDepth(f, g, logn, logn as usize, false);
        let mut scratch = vec![0u32; 4 * length];
        BigInteger::rebuildFromResidues(&mut resultants, length, length, 2, false, &mut scratch);
        let (fResultant, gResultant) = resultants.split_at(length);
        let mut solution = vec![0u32; 2 * length];
        let (bigF, bigG) = solution.split_at_mut(length);
        // f' G' - g' F' = 1, with G' as the coefficient of f' and F' as the coefficient of g'.
        if !BigInteger::bezout(bigG, bigF, fResultant, gResultant, &mut scratch) {
            return None;
        }
        if BigInteger::multiplySmall(bigF, q) != 0 || BigInteger::multiplySmall(bigG, q) != 0 {
            return None;
        }
        Some(solution)
    }

    /// The approximate values of big integers: `N` coefficients of `length` words at `stride`,
    /// as `poly_big_to_fp` does.
    fn approximations(
        output: &mut [FloatingPoint],
        words: &[u32],
        length: usize,
        stride: usize,
        logn: u32,
    ) {
        let n = 1usize << logn;
        if length == 0 {
            output[..n].fill(FloatingPoint::zero);
            return;
        }
        for (u, approximation) in output[..n].iter_mut().enumerate() {
            let value = &words[u * stride..u * stride + length];
            // A negative value is negated on the fly, and its result negated back.
            let negative = (value[length - 1] >> 30).wrapping_neg();
            let flip = negative >> 1;
            let mut carry = negative & 1;
            let mut sum = FloatingPoint::zero;
            let mut scale = FloatingPoint::one;
            for word in value {
                let mut w = (word ^ flip).wrapping_add(carry);
                carry = w >> 31;
                w &= 0x7FFF_FFFF;
                w = w.wrapping_sub((w << 1) & negative);
                sum = sum + FloatingPoint::of(i64::from(w as i32)) * scale;
                scale = scale * FloatingPoint::twoTo31;
            }
            *approximation = sum;
        }
    }

    /// Adds `-k f 2^(31 wordShift + bitShift)` to `F` modulo `X^N + 1` by the quadratic method,
    /// as `poly_sub_scaled` does.
    #[allow(clippy::too_many_arguments)]
    fn subtractScaledProduct(
        bigF: &mut [u32],
        bigFLength: usize,
        bigFStride: usize,
        f: &[u32],
        fLength: usize,
        fStride: usize,
        k: &[i32],
        wordShift: usize,
        bitShift: u32,
        logn: u32,
    ) {
        let n = 1usize << logn;
        for (u, value) in k.iter().take(n).enumerate() {
            let mut factor = value.wrapping_neg();
            let mut x = u * bigFStride;
            for v in 0..n {
                BigInteger::addScaledMultiple(
                    &mut bigF[x..x + bigFLength],
                    &f[v * fStride..v * fStride + fLength],
                    factor,
                    wordShift,
                    bitShift,
                );
                if u + v == n - 1 {
                    // The product wraps around X^N = -1.
                    x = 0;
                    factor = factor.wrapping_neg();
                } else {
                    x += bigFStride;
                }
            }
        }
    }

    /// Subtracts `k f 2^(31 wordShift + bitShift)` from `F`, with `k f` computed in residues by
    /// the transform, as `poly_sub_scaled_ntt` does.
    #[allow(clippy::too_many_arguments)]
    fn subtractScaledProductByTransform(
        bigF: &mut [u32],
        bigFLength: usize,
        bigFStride: usize,
        f: &[u32],
        fLength: usize,
        fStride: usize,
        k: &[i32],
        wordShift: usize,
        bitShift: u32,
        logn: u32,
    ) {
        let n = 1usize << logn;
        let productLength = fLength + 1;
        let mut product = vec![0u32; n * productLength];
        let mut transformedK = vec![0u32; n];
        for u in 0..productLength {
            let (modulus, forward, inverse) = roots(u, logn);
            let rx = modulus.powerOfR(fLength as u32);
            for (value, factor) in transformedK.iter_mut().zip(k) {
                *value = modulus.reduced(*factor);
            }
            modulus.transform(&mut transformedK, 1, &forward, logn);
            for v in 0..n {
                product[v * productLength + u] =
                    BigInteger::signedResidue(&f[v * fStride..v * fStride + fLength], &modulus, rx);
            }
            modulus.transform(&mut product[u..], productLength, &forward, logn);
            for (v, factor) in transformedK.iter().enumerate() {
                let slot = v * productLength + u;
                product[slot] = pairProduct(&modulus, *factor, product[slot]);
            }
            modulus.inverseTransform(&mut product[u..], productLength, &inverse, logn);
        }
        let mut scratch = vec![0u32; productLength];
        BigInteger::rebuildFromResidues(
            &mut product,
            productLength,
            productLength,
            n,
            true,
            &mut scratch,
        );
        for u in 0..n {
            BigInteger::subtractScaled(
                &mut bigF[u * bigFStride..u * bigFStride + bigFLength],
                &product[u * productLength..(u + 1) * productLength],
                wordShift,
                bitShift,
            );
        }
    }

    /// The unreduced `F` and `G` of a level from the `F'` and `G'` of the level below:
    /// `F = F'(X^2) adj(g)` and `G = G'(X^2) adj(f)`, in residues modulo the first `llen`
    /// primes, as both `solve_NTRU_intermediate` and `solve_NTRU_binary_depth1` compute them.
    /// The values of `f` and `g` at each prime come from `transformedPair`.
    fn liftedPair(
        deeper: &[u32],
        deeperLength: usize,
        largeLength: usize,
        logn: u32,
        mut transformedPair: impl FnMut(usize, &PrimeModulus, &[u32], &[u32]) -> (Vec<u32>, Vec<u32>),
    ) -> (Vec<u32>, Vec<u32>) {
        let n = 1usize << logn;
        let hn = n >> 1;
        let (deeperF, deeperG) = deeper.split_at(deeperLength * hn);
        let mut bigF = vec![0u32; n * largeLength];
        let mut bigG = vec![0u32; n * largeLength];
        // F' and G' modulo each prime, in the first N/2 slots.
        for u in 0..largeLength {
            let modulus = PrimeModulus::new(smallPrimes[u].p);
            let rx = modulus.powerOfR(deeperLength as u32);
            for v in 0..hn {
                let words = v * deeperLength..(v + 1) * deeperLength;
                bigF[v * largeLength + u] =
                    BigInteger::signedResidue(&deeperF[words.clone()], &modulus, rx);
                bigG[v * largeLength + u] =
                    BigInteger::signedResidue(&deeperG[words], &modulus, rx);
            }
        }
        let (mut bigFHalf, mut bigGHalf) = (vec![0u32; hn], vec![0u32; hn]);
        for u in 0..largeLength {
            let (modulus, forward, inverse) = roots(u, logn);
            let (fx, gx) = transformedPair(u, &modulus, &forward, &inverse);
            for v in 0..hn {
                bigFHalf[v] = bigF[v * largeLength + u];
                bigGHalf[v] = bigG[v * largeLength + u];
            }
            modulus.transform(&mut bigFHalf, 1, &forward, logn - 1);
            modulus.transform(&mut bigGHalf, 1, &forward, logn - 1);
            // The two roots of each pair share their square, so F and G at both roots come
            // from F' and G' at the square and from the values of g and f at the other root.
            for v in 0..hn {
                let scaledF = modulus.product(bigFHalf[v], modulus.r2);
                let scaledG = modulus.product(bigGHalf[v], modulus.r2);
                bigF[2 * v * largeLength + u] = modulus.product(gx[2 * v + 1], scaledF);
                bigF[(2 * v + 1) * largeLength + u] = modulus.product(gx[2 * v], scaledF);
                bigG[2 * v * largeLength + u] = modulus.product(fx[2 * v + 1], scaledG);
                bigG[(2 * v + 1) * largeLength + u] = modulus.product(fx[2 * v], scaledG);
            }
            modulus.inverseTransform(&mut bigF[u..], largeLength, &inverse, logn);
            modulus.inverseTransform(&mut bigG[u..], largeLength, &inverse, logn);
        }
        (bigF, bigG)
    }

    /// An intermediate level, as `solve_NTRU_intermediate` does: `F` and `G` of degree
    /// `2^(logn - depth)` with `MAX_BL_SMALL[depth]` words for each coefficient, from the
    /// solution of the level below, or `None` when the reduction fails.
    fn intermediate(
        f: &[i8],
        g: &[i8],
        lognTop: u32,
        depth: usize,
        deeper: &[u32],
    ) -> Option<Vec<u32>> {
        let logn = lognTop - depth as u32;
        let n = 1usize << logn;
        let slen = smallLengths[depth];
        let dlen = smallLengths[depth + 1];
        let llen = largeLengths[depth];
        // f and g of this level in residues and in the transform. The first slen words leave
        // the transform as they are used, and then the values are rebuilt.
        let mut pair = Self::pairAtDepth(f, g, lognTop, depth, true);
        let mut scratch = vec![0u32; llen];
        let (mut fx, mut gx) = (vec![0u32; n], vec![0u32; n]);
        let (mut bigF, mut bigG) =
            Self::liftedPair(deeper, dlen, llen, logn, |u, modulus, forward, inverse| {
                if u == slen {
                    let (ft, gt) = pair.split_at_mut(n * slen);
                    BigInteger::rebuildFromResidues(ft, slen, slen, n, true, &mut scratch);
                    BigInteger::rebuildFromResidues(gt, slen, slen, n, true, &mut scratch);
                }
                let (ft, gt) = pair.split_at_mut(n * slen);
                if u < slen {
                    for v in 0..n {
                        fx[v] = ft[v * slen + u];
                        gx[v] = gt[v * slen + u];
                    }
                    modulus.inverseTransform(&mut ft[u..], slen, inverse, logn);
                    modulus.inverseTransform(&mut gt[u..], slen, inverse, logn);
                } else {
                    let rx = modulus.powerOfR(slen as u32);
                    for v in 0..n {
                        let words = v * slen..(v + 1) * slen;
                        fx[v] = BigInteger::signedResidue(&ft[words.clone()], modulus, rx);
                        gx[v] = BigInteger::signedResidue(&gt[words], modulus, rx);
                    }
                    modulus.transform(&mut fx, 1, forward, logn);
                    modulus.transform(&mut gx, 1, forward, logn);
                }
                (fx.clone(), gx.clone())
            });
        BigInteger::rebuildFromResidues(&mut bigF, llen, llen, n, true, &mut scratch);
        BigInteger::rebuildFromResidues(&mut bigG, llen, llen, n, true, &mut scratch);
        let (ft, gt) = pair.split_at(n * slen);
        Self::reduce(&mut bigF, &mut bigG, ft, gt, logn, depth)?;
        // The values of slen words, F first.
        let mut solution = Vec::with_capacity(2 * n * slen);
        for values in [&bigF, &bigG] {
            for u in 0..n {
                solution.extend_from_slice(&values[u * llen..u * llen + slen]);
            }
        }
        Some(solution)
    }

    /// The Babai reduction of an intermediate level, as the second half of
    /// `solve_NTRU_intermediate` does: `F` and `G` of `llen` words for each coefficient
    /// become values of `slen` words, with `k = (F adj(f) + G adj(g)) / (f adj(f) + g adj(g))`
    /// removed in steps of decreasing scale. `None` when a coefficient of `k` overflows.
    fn reduce(
        bigF: &mut [u32],
        bigG: &mut [u32],
        ft: &[u32],
        gt: &[u32],
        logn: u32,
        depth: usize,
    ) -> Option<()> {
        let n = 1usize << logn;
        let slen = smallLengths[depth];
        let llen = largeLengths[depth];
        // adj(f), adj(g) and 1 / (f adj(f) + g adj(g)) from the top ten words of f and g, which
        // are scaled down by 2^scaleOfSmall.
        let topLength = slen.min(10);
        let scaleOfSmall = 31 * (slen - topLength) as i32;
        let (mut adjointF, mut adjointG) =
            (vec![FloatingPoint::zero; n], vec![FloatingPoint::zero; n]);
        Self::approximations(
            &mut adjointF,
            &ft[slen - topLength..],
            topLength,
            slen,
            logn,
        );
        Self::approximations(
            &mut adjointG,
            &gt[slen - topLength..],
            topLength,
            slen,
            logn,
        );
        let (average, deviation) = bitLengths[depth];
        let minimumSmallBits = average - 6 * deviation;
        let maximumSmallBits = average + 6 * deviation;
        FourierTransform::transform(&mut adjointF, logn);
        FourierTransform::transform(&mut adjointG, logn);
        let mut inverseNorm = vec![FloatingPoint::zero; n];
        FourierTransform::inverseNorm(&mut inverseNorm, &adjointF, &adjointG, logn);
        FourierTransform::adjoint(&mut adjointF, logn);
        FourierTransform::adjoint(&mut adjointG, logn);
        // The expected bit length of F and G, and its length in words.
        let mut largeLength = llen;
        let mut maximumLargeBits = 31 * llen as i32;
        let mut scaleOfK = maximumLargeBits - minimumSmallBits;
        let (mut rt1, mut rt2) = (vec![FloatingPoint::zero; n], vec![FloatingPoint::zero; n]);
        let mut k = vec![0i32; n];
        loop {
            let topLength = largeLength.min(10);
            let scaleOfLarge = 31 * (largeLength - topLength) as i32;
            Self::approximations(
                &mut rt1,
                &bigF[largeLength - topLength..],
                topLength,
                llen,
                logn,
            );
            Self::approximations(
                &mut rt2,
                &bigG[largeLength - topLength..],
                topLength,
                llen,
                logn,
            );
            FourierTransform::transform(&mut rt1, logn);
            FourierTransform::transform(&mut rt2, logn);
            FourierTransform::multiply(&mut rt1, &adjointF, logn);
            FourierTransform::multiply(&mut rt2, &adjointG, logn);
            FourierTransform::add(&mut rt2, &rt1, logn);
            FourierTransform::multiplyByAutoAdjoint(&mut rt2, &inverseNorm, logn);
            FourierTransform::inverseTransform(&mut rt2, logn);
            // k is to scale by 2^scaleOfK, so the values move by 2^-dc.
            let mut dc = scaleOfK - scaleOfLarge + scaleOfSmall;
            let mut base = if dc < 0 {
                dc = -dc;
                FloatingPoint::two
            } else {
                FloatingPoint::oneHalf
            };
            let mut scale = FloatingPoint::one;
            while dc != 0 {
                if dc & 1 != 0 {
                    scale = scale * base;
                }
                dc >>= 1;
                base = base.squared();
            }
            for (factor, value) in k.iter_mut().zip(&rt2) {
                let scaled = *value * scale;
                // A value out of the 32-bit range means that the reduction failed.
                if !FloatingPoint::minusTwoTo31MinusOne.isLessThan(scaled)
                    || !scaled.isLessThan(FloatingPoint::twoTo31MinusOne)
                {
                    return None;
                }
                *factor = scaled.roundedToNearest() as i32;
            }
            let wordShift = (scaleOfK / 31) as usize;
            let bitShift = (scaleOfK % 31) as u32;
            for (large, small) in [(&mut *bigF, ft), (&mut *bigG, gt)] {
                if depth <= deepestTransformDepth {
                    Self::subtractScaledProductByTransform(
                        large,
                        largeLength,
                        llen,
                        small,
                        slen,
                        slen,
                        &k,
                        wordShift,
                        bitShift,
                        logn,
                    );
                } else {
                    Self::subtractScaledProduct(
                        large,
                        largeLength,
                        llen,
                        small,
                        slen,
                        slen,
                        &k,
                        wordShift,
                        bitShift,
                        logn,
                    );
                }
            }
            // The new bound of the size of F and G, with f and g at their largest.
            let newMaximum = scaleOfK + maximumSmallBits + 10;
            if newMaximum < maximumLargeBits {
                maximumLargeBits = newMaximum;
                if largeLength as i32 * 31 >= maximumLargeBits + 31 {
                    largeLength -= 1;
                }
            }
            // Each step reduces by at least 25 bits, and the last step has an unscaled k.
            if scaleOfK <= 0 {
                break;
            }
            scaleOfK = (scaleOfK - 25).max(0);
        }
        // Values shorter than slen words get their sign extended.
        if largeLength < slen {
            for values in [&mut *bigF, &mut *bigG] {
                for u in 0..n {
                    let row = &mut values[u * llen..(u + 1) * llen];
                    let signWord = (row[largeLength - 1] >> 30).wrapping_neg() >> 1;
                    row[largeLength..slen].fill(signWord);
                }
            }
        }
        Some(())
    }

    /// The level of depth 1 of the binary case, as `solve_NTRU_binary_depth1` does: the
    /// unreduced `F` and `G` fit in 53 bits, so one reduction in floating point is enough.
    /// Each coefficient of the result is one word.
    fn depthOne(f: &[i8], g: &[i8], lognTop: u32, deeper: &[u32]) -> Option<Vec<u32>> {
        let depth = 1;
        let nTop = 1usize << lognTop;
        let logn = lognTop - 1;
        let n = 1usize << logn;
        let slen = smallLengths[depth];
        let dlen = smallLengths[depth + 1];
        let llen = largeLengths[depth];
        let mut ft = vec![0u32; n * slen];
        let mut gt = vec![0u32; n * slen];
        let (mut fx, mut gx) = (vec![0u32; nTop], vec![0u32; nTop]);
        let (mut bigF, mut bigG) = Self::liftedPair(deeper, dlen, llen, logn, |u, _, _, _| {
            // f and g of full degree in the transform, then their field norms one degree down,
            // with the tables of the full degree, whose first halves are those of degree N.
            let (modulus, forward, inverse) = roots(u, lognTop);
            for (target, source) in [(&mut fx, f), (&mut gx, g)] {
                for (value, coefficient) in target.iter_mut().zip(&source[..nTop]) {
                    *value = modulus.reduced(i32::from(*coefficient));
                }
                modulus.transform(target, 1, &forward, lognTop);
                modulus.reduceResultant(target, lognTop);
            }
            let pair = (fx[..n].to_vec(), gx[..n].to_vec());
            // The residues of f and g of this level, out of the transform, for the first slen
            // primes.
            if u < slen {
                for (target, source) in [(&mut ft, &mut fx), (&mut gt, &mut gx)] {
                    modulus.inverseTransform(&mut source[..n], 1, &inverse, logn);
                    for v in 0..n {
                        target[v * slen + u] = source[v];
                    }
                }
            }
            pair
        });
        let mut scratch = vec![0u32; llen];
        for (values, length) in [
            (&mut bigF, llen),
            (&mut bigG, llen),
            (&mut ft, slen),
            (&mut gt, slen),
        ] {
            BigInteger::rebuildFromResidues(values, length, length, n, true, &mut scratch);
        }
        // F, G, f and g in floating point, then k = (F adj(f) + G adj(g)) / (f adj(f) + g adj(g))
        // rounded, and F - k f and G - k g.
        let mut values =
            [(&bigF, llen), (&bigG, llen), (&ft, slen), (&gt, slen)].map(|(words, length)| {
                let mut approximation = vec![FloatingPoint::zero; n];
                Self::approximations(&mut approximation, words, length, length, logn);
                FourierTransform::transform(&mut approximation, logn);
                approximation
            });
        let [rt1, rt2, rt3, rt4] = &mut values;
        let mut k = vec![FloatingPoint::zero; n];
        let mut inverseNorm = vec![FloatingPoint::zero; n];
        FourierTransform::sumOfAdjointProducts(&mut k, rt1, rt2, rt3, rt4, logn);
        FourierTransform::inverseNorm(&mut inverseNorm, rt3, rt4, logn);
        FourierTransform::multiplyByAutoAdjoint(&mut k, &inverseNorm, logn);
        FourierTransform::inverseTransform(&mut k, logn);
        for value in k.iter_mut() {
            // A value out of the 64-bit range means that the reduction failed.
            if !value.isLessThan(FloatingPoint::twoTo63MinusOne)
                || !FloatingPoint::minusTwoTo63MinusOne.isLessThan(*value)
            {
                return None;
            }
            *value = FloatingPoint::of(value.roundedToNearest());
        }
        FourierTransform::transform(&mut k, logn);
        FourierTransform::multiply(rt3, &k, logn);
        FourierTransform::multiply(rt4, &k, logn);
        FourierTransform::subtract(rt1, rt3, logn);
        FourierTransform::subtract(rt2, rt4, logn);
        FourierTransform::inverseTransform(rt1, logn);
        FourierTransform::inverseTransform(rt2, logn);
        Some(
            rt1.iter()
                .chain(rt2.iter())
                .map(|value| value.roundedToNearest() as u32)
                .collect(),
        )
    }

    /// The top level of the binary case, as `solve_NTRU_binary_depth0` does: everything fits
    /// in 31 bits, so the first prime alone carries the computation. Each coefficient of the
    /// result is one word.
    fn depthZero(f: &[i8], g: &[i8], logn: u32, deeper: &[u32]) -> Vec<u32> {
        let n = 1usize << logn;
        let hn = n >> 1;
        let (modulus, forward, inverse) = roots(0, logn);
        // F' and G' in the transform of half the degree.
        let mut halves = [&deeper[..hn], &deeper[hn..n]].map(|words| {
            let mut values: Vec<u32> = words
                .iter()
                .map(|word| modulus.reduced(BigInteger::oneWordValue(*word)))
                .collect();
            modulus.transform(&mut values, 1, &forward, logn - 1);
            values
        });
        let [bigFHalf, bigGHalf] = &mut halves;
        let mut ft = smallResidues(&f[..n], &modulus);
        let mut gt = smallResidues(&g[..n], &modulus);
        modulus.transform(&mut ft, 1, &forward, logn);
        modulus.transform(&mut gt, 1, &forward, logn);
        // The unreduced F = F'(X^2) adj(g) and G = G'(X^2) adj(f).
        for u in (0..n).step_by(2) {
            let (ftA, ftB, gtA, gtB) = (ft[u], ft[u + 1], gt[u], gt[u + 1]);
            let scaledF = modulus.product(bigFHalf[u >> 1], modulus.r2);
            let scaledG = modulus.product(bigGHalf[u >> 1], modulus.r2);
            ft[u] = modulus.product(gtB, scaledF);
            ft[u + 1] = modulus.product(gtA, scaledF);
            gt[u] = modulus.product(ftB, scaledG);
            gt[u + 1] = modulus.product(ftA, scaledG);
        }
        modulus.inverseTransform(&mut ft, 1, &inverse, logn);
        modulus.inverseTransform(&mut gt, 1, &inverse, logn);
        let (mut bigF, mut bigG) = (ft, gt);
        modulus.transform(&mut bigF, 1, &forward, logn);
        modulus.transform(&mut bigG, 1, &forward, logn);
        // F adj(f) + G adj(g) and f adj(f) + g adj(g), in the transform.
        let mut products = vec![0u32; n];
        let mut norms = vec![0u32; n];
        for (source, other, isFirst) in [(f, &bigF, true), (g, &bigG, false)] {
            let mut values = vec![0u32; n];
            let mut adjoint = vec![0u32; n];
            values[0] = modulus.reduced(i32::from(source[0]));
            adjoint[0] = values[0];
            for u in 1..n {
                values[u] = modulus.reduced(i32::from(source[u]));
                adjoint[n - u] = modulus.reduced(-i32::from(source[u]));
            }
            modulus.transform(&mut values, 1, &forward, logn);
            modulus.transform(&mut adjoint, 1, &forward, logn);
            for u in 0..n {
                let scaled = modulus.product(adjoint[u], modulus.r2);
                let product = modulus.product(scaled, other[u]);
                let norm = modulus.product(scaled, values[u]);
                if isFirst {
                    products[u] = product;
                    norms[u] = norm;
                } else {
                    products[u] = modulus.sum(products[u], product);
                    norms[u] = modulus.sum(norms[u], norm);
                }
            }
        }
        modulus.inverseTransform(&mut products, 1, &inverse, logn);
        modulus.inverseTransform(&mut norms, 1, &inverse, logn);
        // k = rounded (F adj(f) + G adj(g)) / (f adj(f) + g adj(g)), with the floating-point
        // transform. The norm is auto-adjoint, so its values are the real parts alone.
        let toFloatingPoint = |values: &[u32]| -> Vec<FloatingPoint> {
            values
                .iter()
                .map(|value| FloatingPoint::of(i64::from(modulus.normalized(*value))))
                .collect()
        };
        let mut norm = toFloatingPoint(&norms);
        FourierTransform::transform(&mut norm, logn);
        let mut quotient = toFloatingPoint(&products);
        FourierTransform::transform(&mut quotient, logn);
        FourierTransform::divideByAutoAdjoint(&mut quotient, &norm[..hn], logn);
        FourierTransform::inverseTransform(&mut quotient, logn);
        let mut k: Vec<u32> = quotient
            .iter()
            .map(|value| modulus.reduced(value.roundedToNearest() as i32))
            .collect();
        // F - k f and G - k g.
        let mut ft = smallResidues(&f[..n], &modulus);
        let mut gt = smallResidues(&g[..n], &modulus);
        modulus.transform(&mut k, 1, &forward, logn);
        modulus.transform(&mut ft, 1, &forward, logn);
        modulus.transform(&mut gt, 1, &forward, logn);
        for u in 0..n {
            let scaled = modulus.product(k[u], modulus.r2);
            bigF[u] = modulus.difference(bigF[u], modulus.product(scaled, ft[u]));
            bigG[u] = modulus.difference(bigG[u], modulus.product(scaled, gt[u]));
        }
        modulus.inverseTransform(&mut bigF, 1, &inverse, logn);
        modulus.inverseTransform(&mut bigG, 1, &inverse, logn);
        bigF.iter()
            .chain(bigG.iter())
            .map(|value| modulus.normalized(*value) as u32)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{NTRUSolver, smallLengths};
    use crate::floatingPoint::FloatingPoint;
    use crate::modularPolynomial::ModularPolynomial;
    use crate::solverFailure::SolverFailure;
    use OQSNativeAlgorithmTests::{FuzzRandom, LinearCongruentialSequence, OutputDigest};

    /// The FNV-1a hash of the bytes of a polynomial, the digest that the C program of the known
    /// answers prints.
    fn digest(values: &[i8]) -> u64 {
        values.iter().fold(0xCBF2_9CE4_8422_2325u64, |hash, value| {
            (hash ^ u64::from(*value as u8)).wrapping_mul(0x0000_0100_0000_01B3)
        })
    }

    /// The polynomials `f` and `g` of degree `2^logn` with coefficients in `-bound..=bound`, from
    /// the SplitMix64 words of the seed `(logn << 40) ^ (bound << 20) ^ index`, as the C program
    /// of the known answers draws them.
    fn pair(logn: u32, bound: i32, index: u64) -> (Vec<i8>, Vec<i8>) {
        let seed = (u64::from(logn) << 40) ^ ((bound as u64) << 20) ^ index;
        let mut random = FuzzRandom::seeded(seed);
        let mut polynomial = || -> Vec<i8> {
            (0..1usize << logn)
                .map(|_| ((random.nextWord() % (2 * bound as u64 + 1)) as i32 - bound) as i8)
                .collect()
        };
        let f = polynomial();
        let g = polynomial();
        (f, g)
    }

    /// The product of two polynomials in `Z[X] / (X^N + 1)`.
    fn negacyclicProduct(first: &[i8], second: &[i8]) -> Vec<i64> {
        let n = first.len();
        let mut product = vec![0i64; n];
        for (i, a) in first.iter().enumerate() {
            for (j, b) in second.iter().enumerate() {
                let term = i64::from(*a) * i64::from(*b);
                if i + j < n {
                    product[i + j] += term;
                } else {
                    product[i + j - n] -= term;
                }
            }
        }
        product
    }

    /// Known answers of `solve_NTRU` of the C library with the limit 127 for pairs of `pair`:
    /// the degree, the bound, the index, and the digest of `F` or the step that fails. The
    /// degrees 1 to 2 take the general solver to the top, and the others the binary code of
    /// the two top levels. The step at depth 1 never fails for these pairs or any other known
    /// pair.
    const solutions: [(u32, i32, u64, Result<u64, SolverFailure>); 16] = [
        (1, 96, 0, Ok(0x07DA_2E07_B4A0_6129)),
        (2, 48, 2, Ok(0x23D9_B212_1522_C76B)),
        (3, 24, 0, Ok(0xA843_0A42_AF48_4091)),
        (9, 4, 2, Ok(0xF9B1_1C65_51B1_B33A)),
        (10, 4, 3, Ok(0xD824_E1C3_7D9E_EADA)),
        (9, 1, 0, Err(SolverFailure::deepest)),
        (10, 127, 0, Err(SolverFailure::deepest)),
        (3, 48, 17, Err(SolverFailure::intermediate)),
        (9, 1, 3, Err(SolverFailure::intermediate)),
        (10, 1, 1, Err(SolverFailure::intermediate)),
        (1, 2, 10, Err(SolverFailure::bigFOutOfRange)),
        (5, 1, 5, Err(SolverFailure::bigFOutOfRange)),
        (1, 32, 14, Err(SolverFailure::bigGOutOfRange)),
        (6, 4, 11, Err(SolverFailure::bigGOutOfRange)),
        (1, 1, 4, Err(SolverFailure::equationNotSatisfied)),
        (2, 1, 7, Err(SolverFailure::equationNotSatisfied)),
    ];

    #[test]
    fn eachPairIsSolvedOrRefusedAtTheStepOfTheCCode() {
        for (logn, bound, index, expected) in solutions {
            let (f, g) = pair(logn, bound, index);
            assert_eq!(
                NTRUSolver::solution(&f, &g, logn, 127).map(|bigF| digest(&bigF)),
                expected,
                "logn {logn}, bound {bound}, index {index}"
            );
        }
    }

    #[test]
    fn aSolutionSatisfiesTheNTRUEquationOverTheIntegers() {
        for (logn, bound, index, expected) in solutions {
            if expected.is_err() {
                continue;
            }
            let (f, g) = pair(logn, bound, index);
            let bigF = NTRUSolver::solution(&f, &g, logn, 127).expect("a solution");
            let bigG = ModularPolynomial::completedSecretPolynomial(&f, &g, &bigF, logn)
                .expect("G of a solution");
            let fG = negacyclicProduct(&f, &bigG);
            let gF = negacyclicProduct(&g, &bigF);
            let difference: Vec<i64> = fG.iter().zip(&gF).map(|(a, b)| a - b).collect();
            let mut q = vec![0i64; 1 << logn];
            q[0] = 12289;
            assert_eq!(difference, q, "logn {logn}, bound {bound}, index {index}");
        }
    }

    #[test]
    fn approximationsGiveTheValuesOfPolyBigToFpAlsoWhenTheCarryCrossesZeroWords() {
        // poly_big_to_fp of keygen.c for 8 values of 1, 2, 3, 5 and 10 words: 16 polynomials of
        // random words, about half of whose values are negative, then for each length of 2
        // words or more the values -2^(31 (length - 1)) k for k from 1 to 8. Their low words
        // are zero, so the carry of the negation crosses each of them. A word is the top 31
        // bits of the next state of the sequence.
        let mut sequence = LinearCongruentialSequence::new(7);
        let mut output = Vec::new();
        for length in [1usize, 2, 3, 5, 10] {
            for case in 0..17 {
                let mut words: Vec<u32> =
                    (0..8 * length).map(|_| sequence.nextState() >> 1).collect();
                if case == 16 {
                    if length < 2 {
                        continue;
                    }
                    for (k, value) in words.chunks_mut(length).enumerate() {
                        value[..length - 1].fill(0);
                        value[length - 1] = (k as u32 + 1).wrapping_neg() & 0x7FFF_FFFF;
                    }
                }
                let mut approximations = vec![FloatingPoint::zero; 8];
                NTRUSolver::approximations(&mut approximations, &words, length, length, 3);
                output.extend(
                    approximations
                        .iter()
                        .flat_map(|value| value.bits().to_le_bytes()),
                );
            }
        }
        assert_eq!(
            OutputDigest::of(&output),
            "067a8e0aa7584adc5c9a0ed614ae0544bf975cc367b338f806ca39ef4d71f18f"
        );
    }

    /// The inputs of a seed of the C program of the known answers of the intermediate level:
    /// `f`, `g`, the top logn, the depth and the deeper `F` and `G`. The next word modulo 7,
    /// plus 2, is the depth, and the depth plus 1 plus the next word modulo 2 is the top logn.
    /// The next word modulo 4 is the kind of f and g. For each coefficient in turn, f and g
    /// take the next words modulo 3, 7 or 255 for kind 0, 1 and 2, minus 1, 3 or 127. Kind 3 is
    /// kind 2, and then the next word, unless it is a multiple of 4, sets both coefficients to
    /// zero. Then the next word modulo 3 is the shape of the deeper values and the next word
    /// modulo 31 is a shift. Each deeper coefficient takes the next words. Its top word is
    /// shifted right by the shift for shape 0. For shape 1 the next word decides: when it is
    /// even, the top word is shifted and complemented, and else it is shifted. Shape 2 keeps
    /// the top word.
    fn intermediateInputs(seed: u32) -> (Vec<i8>, Vec<i8>, u32, usize, Vec<u32>) {
        let mut sequence = LinearCongruentialSequence::new(seed);
        let mut word = || sequence.nextState() >> 1;
        let depth = 2 + (word() % 7) as usize;
        let lognTop = depth as u32 + 1 + word() % 2;
        let nTop = 1usize << lognTop;
        let hn = (1usize << (lognTop - depth as u32)) >> 1;
        let deeperLength = smallLengths[depth + 1];
        let kind = word() % 4;
        let range = [1, 3, 127, 127][kind as usize];
        let (mut f, mut g) = (vec![0i8; nTop], vec![0i8; nTop]);
        for u in 0..nTop {
            f[u] = ((word() % (2 * range + 1)) as i32 - range as i32) as i8;
            g[u] = ((word() % (2 * range + 1)) as i32 - range as i32) as i8;
            if kind == 3 && word() % 4 != 0 {
                f[u] = 0;
                g[u] = 0;
            }
        }
        let shape = word() % 3;
        let shift = word() % 31;
        let mut deeper = Vec::with_capacity(2 * hn * deeperLength);
        for _ in 0..2 * hn {
            let mut value: Vec<u32> = (0..deeperLength).map(|_| word()).collect();
            let top = value[deeperLength - 1];
            value[deeperLength - 1] = match shape {
                0 => top >> shift,
                1 if word() % 2 == 0 => 0x7FFF_FFFF ^ (top >> shift),
                1 => top >> shift,
                _ => top,
            };
            deeper.extend(value);
        }
        (f, g, lognTop, depth, deeper)
    }

    #[test]
    fn intermediateLevelsGiveTheValuesOfSolveNTRUIntermediateAndFailWhereItFails() {
        // solve_NTRU_intermediate of keygen.c for the inputs of each seed, with deeper values
        // that no deeper level of a key gives. Twelve of them make the reduction fail. The
        // seeds 277 and 1522 succeed at depth 2, where the start of the scale of k decides the
        // result, and the seed 567 succeeds at depth 8. The output is the result byte, then
        // the 2 N slen words of F and G for a result of 1.
        let seeds = [1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 277, 567, 1522];
        let mut output = Vec::new();
        let mut successes = 0;
        for seed in seeds {
            let (f, g, lognTop, depth, deeper) = intermediateInputs(seed);
            match NTRUSolver::intermediate(&f, &g, lognTop, depth, &deeper) {
                Some(solution) => {
                    output.push(1);
                    output.extend(solution.iter().flat_map(|value| value.to_le_bytes()));
                    successes += 1;
                }
                None => output.push(0),
            }
        }
        assert_eq!(successes, 3);
        assert_eq!(
            OutputDigest::of(&output),
            "226c08ecde61a5f706f222963d6a79594c3cf98e554463a96bbd7ee2838c0cf4"
        );
    }

    #[test]
    fn depthOneGivesTheValuesOfSolveNTRUBinaryDepth1AndFailsWhereItFails() {
        // solve_NTRU_binary_depth1 of keygen.c for the inputs of each seed: the next word
        // modulo 4, plus 3, is the top logn, and the next word modulo 4 is the kind of f and g.
        // For each coefficient in turn, f and g take the next words modulo 7, 3 or 255 for kind
        // 0, 1 and 2, minus 3, 1 or 127. Kind 3 is kind 2, and then the next word, unless it is
        // a multiple of 4, sets both coefficients to zero. The 4 hn words of F and G of the
        // deeper level are the next words, each odd one with its low 30 bits set, which no
        // deeper level of a key gives. The last three seeds make the reduction fail. The output
        // is the result byte, then the 2 N words of F and G for a result of 1.
        let seeds = [
            1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 80997, 280261, 955829,
        ];
        let mut output = Vec::new();
        let mut failures = 0;
        for seed in seeds {
            let mut sequence = LinearCongruentialSequence::new(seed);
            let mut word = || sequence.nextState() >> 1;
            let lognTop = 3 + word() % 4;
            let nTop = 1usize << lognTop;
            let kind = word() % 4;
            let range = [3, 1, 127, 127][kind as usize];
            let (mut f, mut g) = (vec![0i8; nTop], vec![0i8; nTop]);
            for u in 0..nTop {
                f[u] = ((word() % (2 * range + 1)) as i32 - range as i32) as i8;
                g[u] = ((word() % (2 * range + 1)) as i32 - range as i32) as i8;
                if kind == 3 && word() % 4 != 0 {
                    f[u] = 0;
                    g[u] = 0;
                }
            }
            let deeper: Vec<u32> = (0..nTop)
                .map(|u| word() | if u % 2 == 1 { 0x3FFF_FFFF } else { 0 })
                .collect();
            match NTRUSolver::depthOne(&f, &g, lognTop, &deeper) {
                Some(solution) => {
                    output.push(1);
                    output.extend(solution.iter().flat_map(|value| value.to_le_bytes()));
                }
                None => {
                    output.push(0);
                    failures += 1;
                }
            }
        }
        assert_eq!(failures, 3);
        assert_eq!(
            OutputDigest::of(&output),
            "33de2ae2e78494b1b310bb8049c35b966d106d80c081de96ec0e1076e06df3d7"
        );
    }

    #[test]
    fn theLimitAcceptsTheLargestCoefficientAndRefusesOneLess() {
        let (f, g) = pair(9, 4, 2);
        let bigF = NTRUSolver::solution(&f, &g, 9, 127).expect("a solution");
        let bigG = ModularPolynomial::completedSecretPolynomial(&f, &g, &bigF, 9)
            .expect("G of a solution");
        let largest = |values: &[i8]| {
            values
                .iter()
                .map(|value| i32::from(*value).abs())
                .max()
                .expect("coefficients")
        };
        assert_eq!((largest(&bigF), largest(&bigG)), (49, 66));
        assert_eq!(NTRUSolver::solution(&f, &g, 9, 66), Ok(bigF));
        assert_eq!(
            NTRUSolver::solution(&f, &g, 9, 65),
            Err(SolverFailure::bigGOutOfRange)
        );
        // F passes the limit of its largest coefficient, and G does not.
        assert_eq!(
            NTRUSolver::solution(&f, &g, 9, 49),
            Err(SolverFailure::bigGOutOfRange)
        );
        assert_eq!(
            NTRUSolver::solution(&f, &g, 9, 48),
            Err(SolverFailure::bigFOutOfRange)
        );
    }
}
