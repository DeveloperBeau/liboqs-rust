use OQSNativeSHA2::{SHA224, SHA256, SHA384, SHA512, SHA512224, SHA512256};
use OQSNativeSHA3::{SHA3224, SHA3256, SHA3384, SHA3512, SHAKE128, SHAKE256};
use alloc::vec::Vec;

/// A hash function of the pre-hash form HashSLH-DSA of FIPS 205, Section 10.2.2, which signs
/// the digest of a message in place of the message.
///
/// The cases follow the order of the pre-hash forms in the liboqs list. SHAKE128 gives a digest
/// of 32 bytes and SHAKE256 one of 64 bytes, as FIPS 205 says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreHash {
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
    /// SHAKE128 of FIPS 202, with a digest of 32 bytes.
    shake128,
    /// SHAKE256 of FIPS 202, with a digest of 64 bytes.
    shake256,
}

impl PreHash {
    /// The twelve functions, in the order of the pre-hash forms in the liboqs list.
    pub const all: [PreHash; 12] = [
        PreHash::sha224,
        PreHash::sha256,
        PreHash::sha384,
        PreHash::sha512,
        PreHash::sha512224,
        PreHash::sha512256,
        PreHash::sha3224,
        PreHash::sha3256,
        PreHash::sha3384,
        PreHash::sha3512,
        PreHash::shake128,
        PreHash::shake256,
    ];

    /// The position of the function in the liboqs list of pre-hash forms, from 0 to 11.
    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    /// The part of the liboqs names that names the function, such as `SHA2_512_224`.
    pub(crate) const fn liboqsName(self) -> &'static str {
        match self {
            PreHash::sha224 => "SHA2_224",
            PreHash::sha256 => "SHA2_256",
            PreHash::sha384 => "SHA2_384",
            PreHash::sha512 => "SHA2_512",
            PreHash::sha512224 => "SHA2_512_224",
            PreHash::sha512256 => "SHA2_512_256",
            PreHash::sha3224 => "SHA3_224",
            PreHash::sha3256 => "SHA3_256",
            PreHash::sha3384 => "SHA3_384",
            PreHash::sha3512 => "SHA3_512",
            PreHash::shake128 => "SHAKE_128",
            PreHash::shake256 => "SHAKE_256",
        }
    }

    /// The DER encoding of the object identifier of the function, `2.16.840.1.101.3.4.2.x`,
    /// which the pre-hash message holds before the digest.
    pub(crate) const fn objectIdentifier(self) -> [u8; 11] {
        let lastArc = match self {
            PreHash::sha256 => 0x01,
            PreHash::sha384 => 0x02,
            PreHash::sha512 => 0x03,
            PreHash::sha224 => 0x04,
            PreHash::sha512224 => 0x05,
            PreHash::sha512256 => 0x06,
            PreHash::sha3224 => 0x07,
            PreHash::sha3256 => 0x08,
            PreHash::sha3384 => 0x09,
            PreHash::sha3512 => 0x0A,
            PreHash::shake128 => 0x0B,
            PreHash::shake256 => 0x0C,
        };
        [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, lastArc,
        ]
    }

    /// Appends the digest of a message to a buffer.
    pub(crate) fn appendDigest(self, message: &[u8], output: &mut Vec<u8>) {
        match self {
            PreHash::sha224 => output.extend_from_slice(&SHA224::hash(message)),
            PreHash::sha256 => output.extend_from_slice(&SHA256::hash(message)),
            PreHash::sha384 => output.extend_from_slice(&SHA384::hash(message)),
            PreHash::sha512 => output.extend_from_slice(&SHA512::hash(message)),
            PreHash::sha512224 => output.extend_from_slice(&SHA512224::hash(message)),
            PreHash::sha512256 => output.extend_from_slice(&SHA512256::hash(message)),
            PreHash::sha3224 => output.extend_from_slice(&SHA3224::hash(message)),
            PreHash::sha3256 => output.extend_from_slice(&SHA3256::hash(message)),
            PreHash::sha3384 => output.extend_from_slice(&SHA3384::hash(message)),
            PreHash::sha3512 => output.extend_from_slice(&SHA3512::hash(message)),
            PreHash::shake128 => {
                let mut digest = [0u8; 32];
                SHAKE128::hash(message, &mut digest);
                output.extend_from_slice(&digest);
            }
            PreHash::shake256 => {
                let mut digest = [0u8; 64];
                SHAKE256::hash(message, &mut digest);
                output.extend_from_slice(&digest);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PreHash;
    use alloc::vec::Vec;

    #[test]
    fn objectIdentifiersAreTheNISTHashArcs() {
        // `hash_slh_dsa_pad` of the C code, and the arcs 2.16.840.1.101.3.4.2.x of the NIST
        // algorithm register: 1 to 3 for SHA-256, SHA-384 and SHA-512, 4 to 6 for SHA-224,
        // SHA-512/224 and SHA-512/256, 7 to 10 for SHA3 and 11 and 12 for SHAKE.
        let lastArcs: Vec<u8> = PreHash::all
            .iter()
            .map(|preHash| preHash.objectIdentifier()[10])
            .collect();
        assert_eq!(lastArcs, [4, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12]);
        for preHash in PreHash::all {
            assert_eq!(
                &preHash.objectIdentifier()[..10],
                &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02]
            );
        }
    }

    #[test]
    fn digestsHaveTheLengthsOfFIPS205Section10Point2() {
        let lengths: Vec<usize> = PreHash::all
            .iter()
            .map(|preHash| {
                let mut digest = Vec::new();
                preHash.appendDigest(b"abc", &mut digest);
                digest.len()
            })
            .collect();
        assert_eq!(lengths, [28, 32, 48, 64, 28, 32, 28, 32, 48, 64, 32, 64]);
    }

    #[test]
    fn digestsOfABCAreTheStandardDigests() {
        // The first bytes of the digests of `abc` of FIPS 180-4 and FIPS 202.
        let firstBytes: Vec<[u8; 4]> = PreHash::all
            .iter()
            .map(|preHash| {
                let mut digest = Vec::new();
                preHash.appendDigest(b"abc", &mut digest);
                [digest[0], digest[1], digest[2], digest[3]]
            })
            .collect();
        assert_eq!(
            firstBytes,
            [
                [0x23, 0x09, 0x7d, 0x22],
                [0xba, 0x78, 0x16, 0xbf],
                [0xcb, 0x00, 0x75, 0x3f],
                [0xdd, 0xaf, 0x35, 0xa1],
                [0x46, 0x34, 0x27, 0x0f],
                [0x53, 0x04, 0x8e, 0x26],
                [0xe6, 0x42, 0x82, 0x4c],
                [0x3a, 0x98, 0x5d, 0xa7],
                [0xec, 0x01, 0x49, 0x82],
                [0xb7, 0x51, 0x85, 0x0b],
                [0x58, 0x81, 0x09, 0x2d],
                [0x48, 0x33, 0x66, 0x60],
            ]
        );
    }

    #[test]
    fn indicesAndNamesFollowTheLiboqsList() {
        for (position, preHash) in PreHash::all.iter().enumerate() {
            assert_eq!(preHash.index(), position);
        }
        let names: Vec<&str> = PreHash::all
            .iter()
            .map(|preHash| preHash.liboqsName())
            .collect();
        assert_eq!(
            names,
            [
                "SHA2_224",
                "SHA2_256",
                "SHA2_384",
                "SHA2_512",
                "SHA2_512_224",
                "SHA2_512_256",
                "SHA3_224",
                "SHA3_256",
                "SHA3_384",
                "SHA3_512",
                "SHAKE_128",
                "SHAKE_256"
            ]
        );
    }
}
