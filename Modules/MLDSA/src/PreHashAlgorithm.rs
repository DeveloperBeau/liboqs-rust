/// A hash function of HashML-DSA, FIPS 204, Section 5.4: the function that hashes the message
/// of a pre-hash signature.
///
/// The cases are the twelve hash functions of mldsa-native, the `MLD_PREHASH_*` constants that
/// liboqs `tests/vectors_sig.c` passes to `signature_pre_hash_internal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreHashAlgorithm {
    /// SHA-224 of FIPS 180-4.
    sha224,
    /// SHA-256 of FIPS 180-4.
    sha256,
    /// SHA-384 of FIPS 180-4.
    sha384,
    /// SHA-512 of FIPS 180-4.
    sha512,
    /// SHA-512/224 of FIPS 180-4.
    sha512224,
    /// SHA-512/256 of FIPS 180-4.
    sha512256,
    /// SHA3-224 of FIPS 202.
    sha3224,
    /// SHA3-256 of FIPS 202.
    sha3256,
    /// SHA3-384 of FIPS 202.
    sha3384,
    /// SHA3-512 of FIPS 202.
    sha3512,
    /// SHAKE128 of FIPS 202, with 32 bytes of output.
    shake128,
    /// SHAKE256 of FIPS 202, with 64 bytes of output.
    shake256,
}

impl PreHashAlgorithm {
    /// The length of the hash of a message in bytes, which `mld_validate_hash_length` checks.
    pub(crate) const fn hashLength(self) -> usize {
        match self {
            PreHashAlgorithm::sha224 | PreHashAlgorithm::sha512224 | PreHashAlgorithm::sha3224 => {
                28
            }
            PreHashAlgorithm::sha256
            | PreHashAlgorithm::sha512256
            | PreHashAlgorithm::sha3256
            | PreHashAlgorithm::shake128 => 32,
            PreHashAlgorithm::sha384 | PreHashAlgorithm::sha3384 => 48,
            PreHashAlgorithm::sha512 | PreHashAlgorithm::sha3512 | PreHashAlgorithm::shake256 => 64,
        }
    }

    /// The DER encoding of the object identifier of the hash function, the 11 bytes before the
    /// hash in the message of a pre-hash signature, FIPS 204, Algorithm 4.
    pub(crate) const fn objectIdentifier(self) -> [u8; 11] {
        // The identifiers are 2.16.840.1.101.3.4.2.n of the NIST hash algorithms.
        let lastArc = match self {
            PreHashAlgorithm::sha256 => 0x01,
            PreHashAlgorithm::sha384 => 0x02,
            PreHashAlgorithm::sha512 => 0x03,
            PreHashAlgorithm::sha224 => 0x04,
            PreHashAlgorithm::sha512224 => 0x05,
            PreHashAlgorithm::sha512256 => 0x06,
            PreHashAlgorithm::sha3224 => 0x07,
            PreHashAlgorithm::sha3256 => 0x08,
            PreHashAlgorithm::sha3384 => 0x09,
            PreHashAlgorithm::sha3512 => 0x0A,
            PreHashAlgorithm::shake128 => 0x0B,
            PreHashAlgorithm::shake256 => 0x0C,
        };
        [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, lastArc,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::PreHashAlgorithm;

    #[test]
    fn eachAlgorithmHasTheIdentifierAndTheLengthOfMLDSANative() {
        // The `oid_map` of `mld_get_hash_oid` and the lengths of `mld_validate_hash_length` in
        // `sign.c` of mldsa-native.
        let expected = [
            (PreHashAlgorithm::sha224, 0x04, 28),
            (PreHashAlgorithm::sha256, 0x01, 32),
            (PreHashAlgorithm::sha384, 0x02, 48),
            (PreHashAlgorithm::sha512, 0x03, 64),
            (PreHashAlgorithm::sha512224, 0x05, 28),
            (PreHashAlgorithm::sha512256, 0x06, 32),
            (PreHashAlgorithm::sha3224, 0x07, 28),
            (PreHashAlgorithm::sha3256, 0x08, 32),
            (PreHashAlgorithm::sha3384, 0x09, 48),
            (PreHashAlgorithm::sha3512, 0x0A, 64),
            (PreHashAlgorithm::shake128, 0x0B, 32),
            (PreHashAlgorithm::shake256, 0x0C, 64),
        ];
        for (algorithm, lastArc, length) in expected {
            assert_eq!(
                algorithm.objectIdentifier(),
                [
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, lastArc
                ],
                "{algorithm:?}"
            );
            assert_eq!(algorithm.hashLength(), length, "{algorithm:?}");
        }
    }
}
