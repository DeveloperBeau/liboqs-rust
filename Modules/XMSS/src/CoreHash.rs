/// The hash function of one liboqs set, as `core_hash` of `core_hash.c` computes it for the
/// value of `HASH` that the build of the set defines.
///
/// The build of a set fixes its function. The C code never reads the hash function of the
/// parameters that the object identifier of a key gives, so a key with the identifier of another
/// set still hashes with the function of the set that signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoreHash {
    /// SHA-256, cut to its first 24 bytes, `XMSS_CORE_HASH_SHA256_N24`.
    sha256N24,
    /// SHAKE256 with 24 bytes of output, `XMSS_CORE_HASH_SHAKE256_N24`.
    shake256N24,
    /// SHA-256, `XMSS_CORE_HASH_SHA256_N32`.
    sha256N32,
    /// SHAKE128 with 32 bytes of output, `XMSS_CORE_HASH_SHAKE128_N32`.
    shake128N32,
    /// SHAKE256 with 32 bytes of output, `XMSS_CORE_HASH_SHAKE256_N32`.
    shake256N32,
    /// SHA-512, `XMSS_CORE_HASH_SHA512_N64`.
    sha512N64,
    /// SHAKE256 with 64 bytes of output, `XMSS_CORE_HASH_SHAKE256_N64`.
    shake256N64,
}

impl CoreHash {
    /// The length of an output in bytes, the n of the sets that use the function.
    pub(crate) const fn outputLength(self) -> usize {
        match self {
            CoreHash::sha256N24 | CoreHash::shake256N24 => 24,
            CoreHash::sha256N32 | CoreHash::shake128N32 | CoreHash::shake256N32 => 32,
            CoreHash::sha512N64 | CoreHash::shake256N64 => 64,
        }
    }
}
