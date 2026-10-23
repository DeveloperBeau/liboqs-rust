use crate::Parameters;
use crate::centralMap::CentralMap;
use crate::nibblePacking::NibblePacking;
use crate::parameters::{publicSeedLength, secretSeedLength};
use alloc::vec::Vec;

/// The parts of a secret key that a signature uses, `sk_gf16` of `snova.h`: the matrices A, B,
/// Q1 and Q2 of the public map, the secret matrices T12, the central map and the two seeds.
pub(crate) struct SigningKey {
    /// The matrices A, `m x alpha`.
    pub(crate) a: Vec<u8>,
    /// The matrices B, `m x alpha`.
    pub(crate) b: Vec<u8>,
    /// The matrices Q1, `m x alpha`.
    pub(crate) q1: Vec<u8>,
    /// The matrices Q2, `m x alpha`.
    pub(crate) q2: Vec<u8>,
    /// The secret matrices T12, `v x o`.
    pub(crate) t12: Vec<u8>,
    /// The blocks F11, F12 and F21.
    pub(crate) centralMap: CentralMap,
    /// The public seed.
    pub(crate) publicSeed: [u8; publicSeedLength],
    /// The secret seed.
    pub(crate) secretSeed: [u8; secretSeedLength],
}

impl SigningKey {
    /// The key of the bytes of an expanded secret key of the right length, `sk_unpack` of
    /// `snova_kernel.h`. The bytes are not checked, so any bytes give a key, as in the C code.
    pub(crate) fn unpacked(parameters: &Parameters, bytes: &[u8]) -> SigningKey {
        let squaredRank = parameters.squaredRank();
        let (vinegarCount, oilCount) = (parameters.vinegarCount, parameters.oilCount);
        let termMatrixCount = oilCount * parameters.termCount();
        let elementCount = parameters.expandedSecretKeyElementCount();
        let seedStart = elementCount.div_ceil(2);
        let elements = NibblePacking::unpackedInHalves(&bytes[..seedStart], elementCount);
        let mut position = 0;
        let mut take = |matrixCount: usize| -> Vec<u8> {
            let start = position;
            position += matrixCount * squaredRank;
            elements[start..position].to_vec()
        };
        let a = take(termMatrixCount);
        let b = take(termMatrixCount);
        let q1 = take(termMatrixCount);
        let q2 = take(termMatrixCount);
        let t12 = take(vinegarCount * oilCount);
        let f11 = take(oilCount * vinegarCount * vinegarCount);
        let f12 = take(oilCount * vinegarCount * oilCount);
        let f21 = take(oilCount * oilCount * vinegarCount);
        let seeds = &bytes[seedStart..];
        SigningKey {
            a,
            b,
            q1,
            q2,
            t12,
            centralMap: CentralMap { f11, f12, f21 },
            publicSeed: seeds[..publicSeedLength].try_into().expect("a public seed"),
            secretSeed: seeds[publicSeedLength..].try_into().expect("a secret seed"),
        }
    }

    /// The bytes of the expanded secret key, `sk_pack` of `snova_kernel.h`: the elements of A,
    /// B, Q1, Q2, T12, F11, F12 and F21 packed in halves, then the public seed and the secret
    /// seed.
    pub(crate) fn packed(&self) -> Vec<u8> {
        let centralMap = &self.centralMap;
        let elements = [
            self.a.as_slice(),
            &self.b,
            &self.q1,
            &self.q2,
            &self.t12,
            &centralMap.f11,
            &centralMap.f12,
            &centralMap.f21,
        ]
        .concat();
        // The count of elements is even for every set with an expanded key. For an odd count,
        // the C code would also pack the first byte of the public key structure after them.
        debug_assert_eq!(elements.len() % 2, 0);
        let mut bytes = NibblePacking::packedInHalves(&elements);
        bytes.extend_from_slice(&self.publicSeed);
        bytes.extend_from_slice(&self.secretSeed);
        bytes
    }
}
