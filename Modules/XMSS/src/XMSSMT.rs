use crate::{CoreHash, Scheme, Variant};
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, StatefulSignatureDescription};
use alloc::vec::Vec;

/// XMSS^MT, the multi-tree variant of XMSS of RFC 8391, with one parameter set.
///
/// The 16 parameter sets are the XMSS^MT sets of liboqs, such as
/// `XMSSMT::sha2Height20Layers2` for `XMSSMT-SHA2_20/2_256`. A name gives the hash function,
/// the height of the hypertree and the number of layers of trees. Every set has n = 32 bytes.
/// Each set gives the bytes of the liboqs algorithm of the same name, whose C code keeps a BDS
/// traversal state for the current tree of each layer and for the next tree of each layer below
/// the top in the secret key.
///
/// A key pair draws 64 random bytes and then 32 more. A signature draws none: it uses the next
/// one-time key of the secret key, advances the key and saves it before it releases the
/// signature. A key makes 2^h - 1 signatures, as liboqs counts them.
pub struct XMSSMT {
    scheme: &'static Scheme,
}

impl XMSSMT {
    /// XMSSMT-SHA2_20/2_256: SHA-256, height 20 in 2 layers.
    pub const sha2Height20Layers2: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHA2_20/2_256",
            0x01,
            Variant::xmssmt,
            CoreHash::sha256N32,
        ),
    };

    /// XMSSMT-SHA2_20/4_256: SHA-256, height 20 in 4 layers.
    pub const sha2Height20Layers4: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHA2_20/4_256",
            0x02,
            Variant::xmssmt,
            CoreHash::sha256N32,
        ),
    };

    /// XMSSMT-SHA2_40/2_256: SHA-256, height 40 in 2 layers.
    pub const sha2Height40Layers2: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHA2_40/2_256",
            0x03,
            Variant::xmssmt,
            CoreHash::sha256N32,
        ),
    };

    /// XMSSMT-SHA2_40/4_256: SHA-256, height 40 in 4 layers.
    pub const sha2Height40Layers4: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHA2_40/4_256",
            0x04,
            Variant::xmssmt,
            CoreHash::sha256N32,
        ),
    };

    /// XMSSMT-SHA2_40/8_256: SHA-256, height 40 in 8 layers.
    pub const sha2Height40Layers8: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHA2_40/8_256",
            0x05,
            Variant::xmssmt,
            CoreHash::sha256N32,
        ),
    };

    /// XMSSMT-SHA2_60/3_256: SHA-256, height 60 in 3 layers.
    pub const sha2Height60Layers3: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHA2_60/3_256",
            0x06,
            Variant::xmssmt,
            CoreHash::sha256N32,
        ),
    };

    /// XMSSMT-SHA2_60/6_256: SHA-256, height 60 in 6 layers.
    pub const sha2Height60Layers6: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHA2_60/6_256",
            0x07,
            Variant::xmssmt,
            CoreHash::sha256N32,
        ),
    };

    /// XMSSMT-SHA2_60/12_256: SHA-256, height 60 in 12 layers.
    pub const sha2Height60Layers12: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHA2_60/12_256",
            0x08,
            Variant::xmssmt,
            CoreHash::sha256N32,
        ),
    };

    /// XMSSMT-SHAKE_20/2_256: SHAKE128, height 20 in 2 layers.
    pub const shake128Height20Layers2: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHAKE_20/2_256",
            0x11,
            Variant::xmssmt,
            CoreHash::shake128N32,
        ),
    };

    /// XMSSMT-SHAKE_20/4_256: SHAKE128, height 20 in 4 layers.
    pub const shake128Height20Layers4: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHAKE_20/4_256",
            0x12,
            Variant::xmssmt,
            CoreHash::shake128N32,
        ),
    };

    /// XMSSMT-SHAKE_40/2_256: SHAKE128, height 40 in 2 layers.
    pub const shake128Height40Layers2: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHAKE_40/2_256",
            0x13,
            Variant::xmssmt,
            CoreHash::shake128N32,
        ),
    };

    /// XMSSMT-SHAKE_40/4_256: SHAKE128, height 40 in 4 layers.
    pub const shake128Height40Layers4: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHAKE_40/4_256",
            0x14,
            Variant::xmssmt,
            CoreHash::shake128N32,
        ),
    };

    /// XMSSMT-SHAKE_40/8_256: SHAKE128, height 40 in 8 layers.
    pub const shake128Height40Layers8: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHAKE_40/8_256",
            0x15,
            Variant::xmssmt,
            CoreHash::shake128N32,
        ),
    };

    /// XMSSMT-SHAKE_60/3_256: SHAKE128, height 60 in 3 layers.
    pub const shake128Height60Layers3: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHAKE_60/3_256",
            0x16,
            Variant::xmssmt,
            CoreHash::shake128N32,
        ),
    };

    /// XMSSMT-SHAKE_60/6_256: SHAKE128, height 60 in 6 layers.
    pub const shake128Height60Layers6: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHAKE_60/6_256",
            0x17,
            Variant::xmssmt,
            CoreHash::shake128N32,
        ),
    };

    /// XMSSMT-SHAKE_60/12_256: SHAKE128, height 60 in 12 layers.
    pub const shake128Height60Layers12: XMSSMT = XMSSMT {
        scheme: &Scheme::new(
            "XMSSMT-SHAKE_60/12_256",
            0x18,
            Variant::xmssmt,
            CoreHash::shake128N32,
        ),
    };

    /// Every XMSS^MT set, in the order of the liboqs list.
    pub const schemes: &'static [&'static dyn StatefulSigning] = &[
        &XMSSMT::sha2Height20Layers2,
        &XMSSMT::sha2Height20Layers4,
        &XMSSMT::sha2Height40Layers2,
        &XMSSMT::sha2Height40Layers4,
        &XMSSMT::sha2Height40Layers8,
        &XMSSMT::sha2Height60Layers3,
        &XMSSMT::sha2Height60Layers6,
        &XMSSMT::sha2Height60Layers12,
        &XMSSMT::shake128Height20Layers2,
        &XMSSMT::shake128Height20Layers4,
        &XMSSMT::shake128Height40Layers2,
        &XMSSMT::shake128Height40Layers4,
        &XMSSMT::shake128Height40Layers8,
        &XMSSMT::shake128Height60Layers3,
        &XMSSMT::shake128Height60Layers6,
        &XMSSMT::shake128Height60Layers12,
    ];
}

impl StatefulSigning for XMSSMT {
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
