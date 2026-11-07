use OQSNativeDomain::RandomGenerating;

/// The random source of the C library for the time that a `COracle` is in use.
pub enum OracleRandomness<'random> {
    /// The NIST AES-256 CTR DRBG of liboqs, seeded with a 48-byte entropy input.
    nist([u8; 48]),
    /// The generator that the liboqs known-answer programs use for an algorithm, seeded with a
    /// 48-byte entropy input: the SHAKE256 generator for HQC and the NIST DRBG for the others.
    knownAnswer {
        /// The liboqs name of the algorithm.
        algorithm: &'random str,
        /// The entropy input.
        entropy: [u8; 48],
    },
    /// A Rust source. The C code reads each random byte from it through a callback.
    source(&'random mut dyn RandomGenerating),
}
