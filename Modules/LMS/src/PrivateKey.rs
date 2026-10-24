use crate::parameters::{
    identifierLength, maximumLevelCount, parameterSetLength, privateKeyLength, seedLength,
};
use crate::{LevelType, ParameterSet};
use OQSNativeEntities::OQSError;
use alloc::vec::Vec;

/// The place of the parameter set in the private key, after the count.
const parameterSetStart: usize = 8;

/// The place of the seed of the top tree, after the parameter set.
const seedStart: usize = parameterSetStart + parameterSetLength;

/// The place of the identifier I of the top tree, after the seed.
const identifierStart: usize = seedStart + seedLength;

/// The byte `PARM_SET_END` that ends the parameter set, and that hash-sigs writes over a whole
/// private key after its last signature.
const parameterSetEnd: u8 = 0xFF;

/// The private key of hash-sigs with the seed method 2 of liboqs, `PRIVATE_KEY_LEN` = 64
/// bytes: the count of signatures in 8 bytes, the parameter set in 8 bytes, the seed of the top
/// tree and its identifier I.
///
/// The serialized secret key of liboqs is this key followed by the aux data of the key pair.
#[derive(Clone, Debug)]
pub(crate) struct PrivateKey {
    /// The 64 bytes of the key.
    pub(crate) bytes: [u8; privateKeyLength],
    /// The types of the levels, the top level first.
    pub(crate) levels: Vec<LevelType>,
}

impl PrivateKey {
    /// The private key with the count 0 of a parameter set, a seed and an identifier, as
    /// `hss_generate_private_key` writes it.
    pub(crate) fn new(
        levels: &[LevelType],
        seed: &[u8; seedLength],
        identifier: &[u8; identifierLength],
    ) -> Self {
        let mut bytes = [0u8; privateKeyLength];
        bytes[parameterSetStart..seedStart]
            .copy_from_slice(&ParameterSet::new(levels).compressed());
        bytes[seedStart..identifierStart].copy_from_slice(seed);
        bytes[identifierStart..].copy_from_slice(identifier);
        PrivateKey {
            bytes,
            levels: levels.to_vec(),
        }
    }

    /// The private key at the start of a serialized secret key, as `oqs_deserialize_lms_key`
    /// and `hss_get_parameter_set` read it.
    ///
    /// A secret key shorter than the private key is a length error. The private key after its
    /// last signature, which hash-sigs fills with `0xFF`, and a count above the highest count
    /// of the parameter set are `OQSError::keyExhausted`. A parameter set with an unknown
    /// typecode, with no level or with a byte other than `0xFF` after its end is
    /// `OQSError::operationFailed`, the `OQS_ERROR` of the C code.
    pub(crate) fn ofSecretKey(secretKey: &[u8]) -> Result<PrivateKey, OQSError> {
        if secretKey.len() < privateKeyLength {
            return Err(OQSError::invalidLength {
                expected: privateKeyLength,
                actual: secretKey.len(),
            });
        }
        let bytes: [u8; privateKeyLength] =
            secretKey[..privateKeyLength].try_into().expect("64 bytes");
        if bytes.iter().all(|byte| *byte == parameterSetEnd) {
            return Err(OQSError::keyExhausted);
        }
        let parameterSet = &bytes[parameterSetStart..seedStart];
        let levelCount = parameterSet
            .iter()
            .position(|byte| *byte == parameterSetEnd)
            .unwrap_or(maximumLevelCount);
        let levels: Vec<LevelType> = parameterSet[..levelCount]
            .iter()
            .map(|code| LevelType::ofCompressedCode(*code))
            .collect::<Option<_>>()
            .ok_or(OQSError::operationFailed)?;
        // The C code checks the bytes after the end mark, and its loop starts one byte after
        // it, so the end mark itself needs no check here.
        let isEndPadded = parameterSet[levelCount..]
            .iter()
            .all(|byte| *byte == parameterSetEnd);
        if levels.is_empty() || !isEndPadded {
            return Err(OQSError::operationFailed);
        }
        let key = PrivateKey { bytes, levels };
        if key.count() > key.parameterSet().maximumCount() {
            return Err(OQSError::keyExhausted);
        }
        Ok(key)
    }

    /// The parameter set of the key.
    pub(crate) fn parameterSet(&self) -> ParameterSet<'_> {
        ParameterSet::new(&self.levels)
    }

    /// The count of signatures that the key has made, the index of its next signature.
    pub(crate) fn count(&self) -> u64 {
        u64::from_be_bytes(self.bytes[..8].try_into().expect("8 bytes"))
    }

    /// Sets the count, as `hss_advance_count` does before a signature.
    pub(crate) fn setCount(&mut self, count: u64) {
        self.bytes[..8].copy_from_slice(&count.to_be_bytes());
    }

    /// Fills the key with `0xFF`, as `hss_advance_count` does before the last signature.
    pub(crate) fn markExhausted(&mut self) {
        self.bytes = [parameterSetEnd; privateKeyLength];
    }

    /// The seed of the top tree.
    pub(crate) fn seed(&self) -> [u8; seedLength] {
        self.bytes[seedStart..identifierStart]
            .try_into()
            .expect("32 bytes")
    }

    /// The identifier I of the top tree.
    pub(crate) fn identifier(&self) -> [u8; identifierLength] {
        self.bytes[identifierStart..].try_into().expect("16 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::PrivateKey;
    use crate::{LevelType, OneTimeSignatureType, TreeType};
    use OQSNativeEntities::OQSError;

    /// A private key with a count and a parameter set, and the bytes 0x11 after them.
    fn key(count: u64, parameterSet: [u8; 8]) -> Vec<u8> {
        let mut bytes = vec![0x11u8; 64];
        bytes[..8].copy_from_slice(&count.to_be_bytes());
        bytes[8..16].copy_from_slice(&parameterSet);
        bytes
    }

    const end: u8 = 0xFF;

    #[test]
    fn keysThatHashSigsAcceptsAreRead() {
        // `OQS_LMS_NAMESPACE_hss_get_parameter_set` of the C oracle accepts each of these.
        let accepted = [
            (key(0, [0x51, end, end, end, end, end, end, end]), 1, 0),
            (key(31, [0x51, end, end, end, end, end, end, end]), 1, 31),
            (
                key(0, [0x51, 0x52, 0x53, 0x54, 0x61, 0x62, 0x63, 0x64]),
                8,
                0,
            ),
            (
                key(1023, [0x54, 0x54, end, end, end, end, end, end]),
                2,
                1023,
            ),
            (
                key(u64::MAX - 1, [0x91, 0x91, 0x91, end, end, end, end, end]),
                3,
                u64::MAX - 1,
            ),
        ];
        for (bytes, levelCount, count) in accepted {
            let privateKey = PrivateKey::ofSecretKey(&bytes).expect("a valid private key");
            assert_eq!(privateKey.levels.len(), levelCount);
            assert_eq!(privateKey.count(), count);
            assert_eq!(&privateKey.bytes[..], &bytes[..]);
        }
        let two = PrivateKey::ofSecretKey(&key(5, [0x63, 0x54, end, end, end, end, end, end]))
            .expect("a valid private key");
        assert_eq!(
            two.levels,
            [
                LevelType::new(TreeType::height10, OneTimeSignatureType::winternitz4),
                LevelType::new(TreeType::height5, OneTimeSignatureType::winternitz8),
            ]
        );
        assert_eq!(two.seed(), [0x11; 32]);
        assert_eq!(two.identifier(), [0x11; 16]);
        // The aux data after the private key may have any length.
        let mut longer = key(0, [0x51, end, end, end, end, end, end, end]);
        longer.extend_from_slice(&[7; 100]);
        assert!(PrivateKey::ofSecretKey(&longer).is_ok());
    }

    #[test]
    fn keysThatHashSigsRefusesAreErrors() {
        // `OQS_LMS_NAMESPACE_hss_get_parameter_set` of the C oracle refuses each of these.
        let malformed = [
            key(0, [end; 8]),
            key(0, [0xA1, end, end, end, end, end, end, end]),
            key(0, [0x55, end, end, end, end, end, end, end]),
            key(0, [0x51, end, 0x51, end, end, end, end, end]),
            key(0, [0x51, end, end, end, end, end, end, 0x00]),
        ];
        for bytes in malformed {
            assert_eq!(
                PrivateKey::ofSecretKey(&bytes).map(|_| ()),
                Err(OQSError::operationFailed),
                "{:02x?}",
                &bytes[8..16]
            );
        }
        // A count above the highest count of the parameter set has no signature left.
        let exhausted = [
            key(32, [0x51, end, end, end, end, end, end, end]),
            key(1024, [0x54, 0x54, end, end, end, end, end, end]),
            key(u64::MAX, [0x91, 0x91, 0x91, end, end, end, end, end]),
        ];
        for bytes in exhausted {
            assert_eq!(
                PrivateKey::ofSecretKey(&bytes).map(|_| ()),
                Err(OQSError::keyExhausted)
            );
        }
        // The key that hash-sigs fills with 0xFF after the last signature.
        assert_eq!(
            PrivateKey::ofSecretKey(&[end; 64]).map(|_| ()),
            Err(OQSError::keyExhausted)
        );
        let mut usedWithAuxiliaryData = vec![end; 64];
        usedWithAuxiliaryData.extend_from_slice(&[0; 10]);
        assert_eq!(
            PrivateKey::ofSecretKey(&usedWithAuxiliaryData).map(|_| ()),
            Err(OQSError::keyExhausted)
        );
        for length in [0, 1, 63] {
            assert_eq!(
                PrivateKey::ofSecretKey(&vec![0; length]).map(|_| ()),
                Err(OQSError::invalidLength {
                    expected: 64,
                    actual: length
                })
            );
        }
    }

    #[test]
    fn countsAndMarksChangeOnlyTheirBytes() {
        let levels = [LevelType::new(
            TreeType::height5,
            OneTimeSignatureType::winternitz8,
        )];
        let mut privateKey = PrivateKey::new(&levels, &[2; 32], &[3; 16]);
        let mut expected = vec![0u8; 8];
        expected.extend_from_slice(&[0x54, end, end, end, end, end, end, end]);
        expected.extend_from_slice(&[2; 32]);
        expected.extend_from_slice(&[3; 16]);
        assert_eq!(&privateKey.bytes[..], &expected[..]);
        privateKey.setCount(0x0102_0304_0506_0708);
        assert_eq!(&privateKey.bytes[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&privateKey.bytes[8..], &expected[8..]);
        privateKey.markExhausted();
        assert_eq!(privateKey.bytes, [end; 64]);
    }
}
