use crate::{CoreHash, Scheme, Variant};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, StatefulSignatureDescription};
use alloc::vec::Vec;

/// XMSS, the eXtended Merkle Signature Scheme of RFC 8391 with one tree, with one parameter set.
///
/// The 21 parameter sets are the XMSS sets of liboqs, such as `XMSS::sha2Height10Bits256` for
/// `XMSS-SHA2_10_256`. A name gives the hash function, the height of the tree and the length n
/// of a hash in bits. Each set gives the bytes of the liboqs algorithm of the same name, whose
/// C code keeps the BDS traversal state of `xmss_core_fast.c` in the secret key.
///
/// A key pair draws 2 n random bytes and then n more. A signature draws none: it uses the next
/// one-time key of the secret key, advances the key and saves it before it releases the
/// signature. A key makes 2^h - 1 signatures, as liboqs counts them.
pub struct XMSS {
    scheme: &'static Scheme,
}

impl XMSS {
    /// XMSS-SHA2_10_256: SHA-256, a tree of height 10 and n = 32 bytes.
    pub const sha2Height10Bits256: XMSS = XMSS {
        scheme: &Scheme::new("XMSS-SHA2_10_256", 0x01, Variant::xmss, CoreHash::sha256N32),
    };

    /// XMSS-SHA2_16_256: SHA-256, a tree of height 16 and n = 32 bytes.
    pub const sha2Height16Bits256: XMSS = XMSS {
        scheme: &Scheme::new("XMSS-SHA2_16_256", 0x02, Variant::xmss, CoreHash::sha256N32),
    };

    /// XMSS-SHA2_20_256: SHA-256, a tree of height 20 and n = 32 bytes.
    pub const sha2Height20Bits256: XMSS = XMSS {
        scheme: &Scheme::new("XMSS-SHA2_20_256", 0x03, Variant::xmss, CoreHash::sha256N32),
    };

    /// XMSS-SHAKE_10_256: SHAKE128, a tree of height 10 and n = 32 bytes.
    pub const shake128Height10Bits256: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE_10_256",
            0x07,
            Variant::xmss,
            CoreHash::shake128N32,
        ),
    };

    /// XMSS-SHAKE_16_256: SHAKE128, a tree of height 16 and n = 32 bytes.
    pub const shake128Height16Bits256: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE_16_256",
            0x08,
            Variant::xmss,
            CoreHash::shake128N32,
        ),
    };

    /// XMSS-SHAKE_20_256: SHAKE128, a tree of height 20 and n = 32 bytes.
    pub const shake128Height20Bits256: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE_20_256",
            0x09,
            Variant::xmss,
            CoreHash::shake128N32,
        ),
    };

    /// XMSS-SHA2_10_512: SHA-512, a tree of height 10 and n = 64 bytes.
    pub const sha2Height10Bits512: XMSS = XMSS {
        scheme: &Scheme::new("XMSS-SHA2_10_512", 0x04, Variant::xmss, CoreHash::sha512N64),
    };

    /// XMSS-SHA2_16_512: SHA-512, a tree of height 16 and n = 64 bytes.
    pub const sha2Height16Bits512: XMSS = XMSS {
        scheme: &Scheme::new("XMSS-SHA2_16_512", 0x05, Variant::xmss, CoreHash::sha512N64),
    };

    /// XMSS-SHA2_20_512: SHA-512, a tree of height 20 and n = 64 bytes.
    pub const sha2Height20Bits512: XMSS = XMSS {
        scheme: &Scheme::new("XMSS-SHA2_20_512", 0x06, Variant::xmss, CoreHash::sha512N64),
    };

    /// XMSS-SHAKE_10_512: SHAKE256, a tree of height 10 and n = 64 bytes.
    pub const shake256Height10Bits512: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE_10_512",
            0x0a,
            Variant::xmss,
            CoreHash::shake256N64,
        ),
    };

    /// XMSS-SHAKE_16_512: SHAKE256, a tree of height 16 and n = 64 bytes.
    pub const shake256Height16Bits512: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE_16_512",
            0x0b,
            Variant::xmss,
            CoreHash::shake256N64,
        ),
    };

    /// XMSS-SHAKE_20_512: SHAKE256, a tree of height 20 and n = 64 bytes.
    pub const shake256Height20Bits512: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE_20_512",
            0x0c,
            Variant::xmss,
            CoreHash::shake256N64,
        ),
    };

    /// XMSS-SHA2_10_192: SHA-256 cut to 24 bytes, a tree of height 10 and n = 24 bytes.
    pub const sha2Height10Bits192: XMSS = XMSS {
        scheme: &Scheme::new("XMSS-SHA2_10_192", 0x0d, Variant::xmss, CoreHash::sha256N24),
    };

    /// XMSS-SHA2_16_192: SHA-256 cut to 24 bytes, a tree of height 16 and n = 24 bytes.
    pub const sha2Height16Bits192: XMSS = XMSS {
        scheme: &Scheme::new("XMSS-SHA2_16_192", 0x0e, Variant::xmss, CoreHash::sha256N24),
    };

    /// XMSS-SHA2_20_192: SHA-256 cut to 24 bytes, a tree of height 20 and n = 24 bytes.
    pub const sha2Height20Bits192: XMSS = XMSS {
        scheme: &Scheme::new("XMSS-SHA2_20_192", 0x0f, Variant::xmss, CoreHash::sha256N24),
    };

    /// XMSS-SHAKE256_10_192: SHAKE256, a tree of height 10 and n = 24 bytes.
    pub const shake256Height10Bits192: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE256_10_192",
            0x13,
            Variant::xmss,
            CoreHash::shake256N24,
        ),
    };

    /// XMSS-SHAKE256_16_192: SHAKE256, a tree of height 16 and n = 24 bytes.
    pub const shake256Height16Bits192: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE256_16_192",
            0x14,
            Variant::xmss,
            CoreHash::shake256N24,
        ),
    };

    /// XMSS-SHAKE256_20_192: SHAKE256, a tree of height 20 and n = 24 bytes.
    pub const shake256Height20Bits192: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE256_20_192",
            0x15,
            Variant::xmss,
            CoreHash::shake256N24,
        ),
    };

    /// XMSS-SHAKE256_10_256: SHAKE256, a tree of height 10 and n = 32 bytes.
    pub const shake256Height10Bits256: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE256_10_256",
            0x10,
            Variant::xmss,
            CoreHash::shake256N32,
        ),
    };

    /// XMSS-SHAKE256_16_256: SHAKE256, a tree of height 16 and n = 32 bytes.
    pub const shake256Height16Bits256: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE256_16_256",
            0x11,
            Variant::xmss,
            CoreHash::shake256N32,
        ),
    };

    /// XMSS-SHAKE256_20_256: SHAKE256, a tree of height 20 and n = 32 bytes.
    pub const shake256Height20Bits256: XMSS = XMSS {
        scheme: &Scheme::new(
            "XMSS-SHAKE256_20_256",
            0x12,
            Variant::xmss,
            CoreHash::shake256N32,
        ),
    };

    /// Every XMSS set, in the order of the liboqs list.
    pub const schemes: &'static [&'static dyn StatefulSigning] = &[
        &XMSS::sha2Height10Bits256,
        &XMSS::sha2Height16Bits256,
        &XMSS::sha2Height20Bits256,
        &XMSS::shake128Height10Bits256,
        &XMSS::shake128Height16Bits256,
        &XMSS::shake128Height20Bits256,
        &XMSS::sha2Height10Bits512,
        &XMSS::sha2Height16Bits512,
        &XMSS::sha2Height20Bits512,
        &XMSS::shake256Height10Bits512,
        &XMSS::shake256Height16Bits512,
        &XMSS::shake256Height20Bits512,
        &XMSS::sha2Height10Bits192,
        &XMSS::sha2Height16Bits192,
        &XMSS::sha2Height20Bits192,
        &XMSS::shake256Height10Bits192,
        &XMSS::shake256Height16Bits192,
        &XMSS::shake256Height20Bits192,
        &XMSS::shake256Height10Bits256,
        &XMSS::shake256Height16Bits256,
        &XMSS::shake256Height20Bits256,
    ];
}

impl StatefulSigning for XMSS {
    fn description(&self) -> &'static StatefulSignatureDescription {
        self.scheme.description()
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        self.scheme.generateKeyPair(random)
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &mut SecretBytes,
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        let signature = self.scheme.sign(message, secretKey)?;
        self.releaseSignature(signature, secretKey.bytes(), persisting)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        self.scheme.isValidSignature(signature, message, publicKey)
    }

    fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        self.scheme.remainingSignatureCount(secretKey)
    }

    fn totalSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        self.scheme.totalSignatureCount(secretKey)
    }
}
