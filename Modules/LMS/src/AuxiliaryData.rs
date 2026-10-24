use crate::parameters::{auxiliaryDataLength, hashLength, seedLength};
use OQSNativeSHA2::SHA256;
use alloc::vec;
use alloc::vec::Vec;

/// The domain separator `D_DAUX` of the derivation of the key that authenticates the data.
const keyDerivationDomain: [u8; 2] = [0xFD, 0xFD];

/// The height of the subtrees of a top tree, `hss_smallest_subtree_size`. The saved depths of
/// the aux data step by it.
const subtreeHeight: u32 = 2;

/// The flag of a used marker, bit 31.
const usedFlag: u32 = 0x8000_0000;

/// The block length of SHA-256, which the HMAC pads its key to.
const blockLength: usize = 64;

/// The aux data of hash-sigs that a key pair of liboqs writes after the private key: nodes of
/// the top tree at some depths, which a loader may use to skip their computation, as
/// `hss_aux.c` writes them in a buffer of 10916 bytes.
///
/// The data is a 4-byte marker whose bit 31 is set and whose bit d is set for each saved depth
/// d, then the `2^d` nodes of each saved depth in ascending order of depth, then the HMAC of
/// all of that under a key derived from the seed, then zeros up to the end of the buffer.
/// liboqs never reads it back: each signature loads the private key without its aux data.
pub(crate) struct AuxiliaryData;

impl AuxiliaryData {
    /// The bit set of the saved depths of a top tree of a height, `hss_optimal_aux_level` for
    /// the 10916 bytes of liboqs: every second depth from the base of the topmost subtree, as
    /// long as the nodes, the marker and the HMAC fit. Zero means that nothing is saved.
    pub(crate) fn savedDepths(treeHeight: u32) -> u32 {
        let mut room = auxiliaryDataLength - 4 - hashLength;
        let mut depths = 0;
        let mut depth = match treeHeight % subtreeHeight {
            0 => subtreeHeight,
            rest => rest,
        };
        while depth < treeHeight {
            let length = hashLength << depth;
            if length > room {
                break;
            }
            room -= length;
            // The room keeps each saved depth below 9, so its bit cannot meet the flag, bit 31.
            depths |= usedFlag + (1 << depth);
            depth += subtreeHeight;
        }
        depths
    }

    /// The deepest saved depth of a top tree, or `None` when nothing is saved.
    pub(crate) fn deepestDepth(treeHeight: u32) -> Option<u32> {
        let depths = Self::savedDepths(treeHeight) & !usedFlag;
        (depths != 0).then(|| 31 - depths.leading_zeros())
    }

    /// The aux data of a top tree of a height, from the nodes of the top of the tree by node
    /// number down to the deepest saved depth, and the seed of the private key.
    pub(crate) fn bytes(
        treeHeight: u32,
        topNodes: &[[u8; hashLength]],
        seed: &[u8; seedLength],
    ) -> Vec<u8> {
        let mut data = vec![0u8; auxiliaryDataLength];
        let depths = Self::savedDepths(treeHeight);
        if depths == 0 {
            // `hss_store_aux_marker` marks unused aux data with one zero byte.
            return data;
        }
        data[..4].copy_from_slice(&depths.to_be_bytes());
        let mut length = 4;
        for depth in 0..treeHeight {
            if depths & (1 << depth) == 0 {
                continue;
            }
            for node in &topNodes[1 << depth..2 << depth] {
                data[length..length + hashLength].copy_from_slice(node);
                length += hashLength;
            }
        }
        let key = Self::authenticationKey(seed);
        let tag = Self::hmac(&key, &data[..length]);
        data[length..length + hashLength].copy_from_slice(&tag);
        data
    }

    /// The key of the HMAC, `compute_seed_derive`: the SHA-256 of 20 zero bytes, `D_DAUX` and
    /// the seed.
    fn authenticationKey(seed: &[u8; seedLength]) -> [u8; hashLength] {
        let mut hash = SHA256::new();
        hash.absorb(&[0u8; 20]);
        hash.absorb(&keyDerivationDomain);
        hash.absorb(seed);
        hash.finalize()
    }

    /// The HMAC-SHA256 of RFC 2104 with a key of 32 bytes, as `compute_hmac` computes it.
    fn hmac(key: &[u8; hashLength], data: &[u8]) -> [u8; hashLength] {
        let padded = |pad: u8| {
            let mut block = [pad; blockLength];
            for (byte, keyByte) in block.iter_mut().zip(key) {
                *byte ^= keyByte;
            }
            block
        };
        let mut inner = SHA256::new();
        inner.absorb(&padded(0x36));
        inner.absorb(data);
        let innerHash = inner.finalize();
        let mut outer = SHA256::new();
        outer.absorb(&padded(0x5C));
        outer.absorb(&innerHash);
        outer.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::AuxiliaryData;

    #[test]
    fn savedDepthsAreTheAuxLevelsOfHashSigsForTheBufferOfLiboqs() {
        // `hss_optimal_aux_level` of the C oracle for 10916 bytes and each top tree height.
        assert_eq!(AuxiliaryData::savedDepths(5), 0x8000_000A);
        assert_eq!(AuxiliaryData::savedDepths(10), 0x8000_0154);
        assert_eq!(AuxiliaryData::savedDepths(15), 0x8000_00AA);
        assert_eq!(AuxiliaryData::savedDepths(20), 0x8000_0154);
        assert_eq!(AuxiliaryData::savedDepths(25), 0x8000_00AA);
        assert_eq!(AuxiliaryData::deepestDepth(5), Some(3));
        assert_eq!(AuxiliaryData::deepestDepth(10), Some(8));
        assert_eq!(AuxiliaryData::deepestDepth(15), Some(7));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn hmacIsTheHMACSHA256OfRFC4231() {
        // HMAC pads a short key with zeros to the block length, so a key of RFC 4231 with zeros
        // up to 32 bytes gives the tag of its test case: test cases 1 and 2.
        let mut key = [0u8; 32];
        key[..20].fill(0x0B);
        assert_eq!(
            hex(&AuxiliaryData::hmac(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(b"Jefe");
        assert_eq!(
            hex(&AuxiliaryData::hmac(&key, b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
