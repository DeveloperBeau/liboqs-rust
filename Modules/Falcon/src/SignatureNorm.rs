/// The acceptance bound of the squared norm of a signature vector `(s1, s2)`, as `common.c` of
/// the Falcon code of PQClean gives it.
///
/// The squared norm saturates at `2^32 - 1` once it reaches `2^31`, so a large vector never
/// wraps around to a small norm.
pub(crate) struct SignatureNorm;

/// The inclusive bounds `floor(beta^2)` of the squared norm, for `logn` from 1 to 10.
const squaredNormBounds: [u32; 11] = [
    0, 101498, 208714, 428865, 892039, 1852696, 3842630, 7959734, 16468416, 34034726, 70265242,
];

impl SignatureNorm {
    /// True when the squared norm of `(s1, s2)` is within the bound, as `is_short` does.
    pub(crate) fn isShort(first: &[i16], second: &[i16], logn: u32) -> bool {
        let n = 1usize << logn;
        let mut squaredNorm = 0u32;
        let mut overflow = 0u32;
        for (left, right) in first[..n].iter().zip(&second[..n]) {
            let left = i32::from(*left);
            squaredNorm = squaredNorm.wrapping_add((left * left) as u32);
            overflow |= squaredNorm;
            let right = i32::from(*right);
            squaredNorm = squaredNorm.wrapping_add((right * right) as u32);
            overflow |= squaredNorm;
        }
        squaredNorm |= (overflow >> 31).wrapping_neg();
        squaredNorm <= squaredNormBounds[logn as usize]
    }

    /// True when the squared norm of `(s1, s2)` is within the bound, from the saturated squared
    /// norm of `s1` and the vector `s2`, as `is_short_half` does.
    pub(crate) fn isShortHalf(firstSquaredNorm: u32, second: &[i16], logn: u32) -> bool {
        let n = 1usize << logn;
        let mut squaredNorm = firstSquaredNorm;
        let mut overflow = (squaredNorm >> 31).wrapping_neg();
        for value in &second[..n] {
            let value = i32::from(*value);
            squaredNorm = squaredNorm.wrapping_add((value * value) as u32);
            overflow |= squaredNorm;
        }
        squaredNorm |= (overflow >> 31).wrapping_neg();
        squaredNorm <= squaredNormBounds[logn as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::SignatureNorm;

    #[test]
    fn theBoundOfEachDegreeIsInclusive() {
        // Falcon-512: 5833^2 + 104^2 + 4^2 + 2^2 + 1^2 = 34034726, the bound.
        let mut first = vec![0i16; 512];
        let mut second = vec![0i16; 512];
        first[0] = 5833;
        second[..4].copy_from_slice(&[104, 4, 2, 1]);
        assert!(SignatureNorm::isShort(&first, &second, 9));
        second[4] = 1;
        assert!(!SignatureNorm::isShort(&first, &second, 9));
        // Falcon-1024: 8382^2 + 85^2 + 9^2 + 3^2 + 3 = 70265242, the bound.
        let mut first = vec![0i16; 1024];
        let mut second = vec![0i16; 1024];
        first[0] = 8382;
        second[..6].copy_from_slice(&[85, 9, 3, 1, 1, 1]);
        assert!(SignatureNorm::isShort(&first, &second, 10));
        second[6] = -1;
        assert!(!SignatureNorm::isShort(&first, &second, 10));
        // The first vector counts as much as the second.
        assert!(!SignatureNorm::isShort(&second, &first, 10));
        second[6] = 0;
        assert!(SignatureNorm::isShort(&second, &first, 10));
    }

    #[test]
    fn aSquaredNormOf2To31OrMoreSaturatesAndIsRefused() {
        // 512 coefficients of -32768 in each half give 2^39, far above 2^32: without the
        // saturation the sum would wrap to zero.
        let first = vec![-32768i16; 512];
        let second = vec![-32768i16; 512];
        assert!(!SignatureNorm::isShort(&first, &second, 9));
        assert!(!SignatureNorm::isShortHalf(0, &second, 9));
        assert!(!SignatureNorm::isShortHalf(1 << 31, &vec![0i16; 512], 9));
        assert!(SignatureNorm::isShortHalf(34034726, &vec![0i16; 512], 9));
        assert!(!SignatureNorm::isShortHalf(34034727, &vec![0i16; 512], 9));
    }

    #[test]
    fn halfFormAddsTheSecondVectorToTheGivenNorm() {
        let mut second = vec![0i16; 512];
        second[7] = -3;
        assert!(SignatureNorm::isShortHalf(34034726 - 9, &second, 9));
        assert!(!SignatureNorm::isShortHalf(34034726 - 8, &second, 9));
    }
}
