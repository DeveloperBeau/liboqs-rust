use crate::StatefulTreeHeight;

/// The algorithms that the default test suite runs through the test programs and the parity
/// checks, a sample that a debug build checks in seconds.
///
/// Every algorithm is in the sample except most SLH-DSA schemes and the stateful sets of large
/// trees. The small sets of SLH-DSA, the names that end in `S`, sign in one to two seconds
/// each, so the sample leaves them out. The 144 pre-hash forms differ from the pure forms only
/// in the message that they sign, so the sample takes each pre-hash function with one fast
/// set, `SHA2_128F`. A stateful set is in the sample when its largest tree has a height of
/// `largestStatefulTreeHeight` or less, see `StatefulTreeHeight`. The C library generates a
/// key of a tree of height 10 in about two seconds, and of height 16 in two minutes. The
/// ignored tests run every algorithm, and `parity run` checks every algorithm in release
/// builds, the stateful sets of trees of height 20 or more with `--large-trees`.
pub struct SuiteSample;

impl SuiteSample {
    /// The height of the largest tree of a stateful set in the sample.
    pub const largestStatefulTreeHeight: u32 = 10;

    /// True when the default test suite runs the algorithm of a liboqs name.
    pub fn contains(name: &str) -> bool {
        if let Some(height) = StatefulTreeHeight::largest(name) {
            return height <= Self::largestStatefulTreeHeight;
        }
        match name.strip_prefix("SLH_DSA_") {
            None => true,
            Some(scheme) => match scheme.strip_prefix("PURE_") {
                Some(set) => set.ends_with('F'),
                None => scheme.ends_with("_PREHASH_SHA2_128F"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SuiteSample;

    #[test]
    fn sampleHoldsTheFastPureSetsAndOneSetOfEachPreHashFunction() {
        for name in [
            "ML-KEM-768",
            "Kyber512",
            "ML-DSA-44",
            "SLH_DSA_PURE_SHA2_128F",
            "SLH_DSA_PURE_SHAKE_256F",
            "SLH_DSA_SHA2_224_PREHASH_SHA2_128F",
            "SLH_DSA_SHA2_512_256_PREHASH_SHA2_128F",
            "SLH_DSA_SHAKE_256_PREHASH_SHA2_128F",
        ] {
            assert!(SuiteSample::contains(name), "{name}");
        }
        for name in [
            "SLH_DSA_PURE_SHA2_128S",
            "SLH_DSA_PURE_SHAKE_256S",
            "SLH_DSA_SHA2_224_PREHASH_SHA2_128S",
            "SLH_DSA_SHA2_224_PREHASH_SHAKE_128F",
            "SLH_DSA_SHA3_512_PREHASH_SHA2_256F",
        ] {
            assert!(!SuiteSample::contains(name), "{name}");
        }
    }

    #[test]
    fn sampleHoldsTheStatefulSetsWhoseLargestTreeHasAHeightOf10OrLess() {
        for name in [
            "XMSS-SHA2_10_256",
            "XMSSMT-SHA2_60/6_256",
            "LMS_SHA256_H5_W1",
            "LMS_SHA256_H10_W8_H10_W8",
        ] {
            assert!(SuiteSample::contains(name), "{name}");
        }
        for name in [
            "XMSS-SHA2_16_256",
            "XMSSMT-SHA2_40/2_256",
            "LMS_SHA256_H15_W1",
            "LMS_SHA256_H15_W8_H5_W8",
        ] {
            assert!(!SuiteSample::contains(name), "{name}");
        }
    }
}
