/// The algorithms that the default test suite runs through the test programs and the parity
/// checks, a sample that a debug build checks in seconds.
///
/// Every algorithm is in the sample except most SLH-DSA schemes. The small sets of SLH-DSA, the
/// names that end in `S`, sign in one to two seconds each, so the sample leaves them out. The
/// 144 pre-hash forms differ from the pure forms only in the message that they sign, so the
/// sample takes each pre-hash function with one fast set, `SHA2_128F`. The ignored tests run
/// every algorithm, and `parity run` checks every algorithm in release builds.
pub struct SuiteSample;

impl SuiteSample {
    /// True when the default test suite runs the algorithm of a liboqs name.
    pub fn contains(name: &str) -> bool {
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
}
