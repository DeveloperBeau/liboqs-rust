use crate::parameters::{digestLength, publicSeedLength, saltLength, secretSeedLength};
use OQSNativeSHA3::SHAKE256;
use alloc::vec;
use alloc::vec::Vec;

/// The SHAKE256 hashes of the signature and the verification: the digest of the message, the
/// signed hash and the vinegar values of an attempt.
pub(crate) struct MessageHashing;

impl MessageHashing {
    /// The 64-byte digest of a message, `shake256` in the `sign` and `verify` functions of
    /// `oqs_snova.c`.
    pub(crate) fn digest(message: &[u8]) -> [u8; digestLength] {
        let mut digest = [0u8; digestLength];
        SHAKE256::hash(message, &mut digest);
        digest
    }

    /// The signed hash of a digest, `createSignedHash` of `snova_kernel.h`: SHAKE256 of the
    /// public seed, the digest and the salt.
    pub(crate) fn signedHash(
        publicSeed: &[u8; publicSeedLength],
        digest: &[u8; digestLength],
        salt: &[u8],
        length: usize,
    ) -> Vec<u8> {
        debug_assert_eq!(salt.len(), saltLength);
        let mut sponge = SHAKE256::new();
        sponge.absorb(publicSeed);
        sponge.absorb(digest);
        sponge.absorb(salt);
        let mut hash = vec![0u8; length];
        sponge.finalize().squeeze(&mut hash);
        hash
    }

    /// The bytes of the vinegar values of an attempt, in `sign_digest_core_opt`: SHAKE256 of the
    /// secret seed, the digest, the salt and the number of the attempt in one byte.
    pub(crate) fn vinegarBytes(
        secretSeed: &[u8; secretSeedLength],
        digest: &[u8; digestLength],
        salt: &[u8; saltLength],
        attempt: u8,
        length: usize,
    ) -> Vec<u8> {
        let mut sponge = SHAKE256::new();
        sponge.absorb(secretSeed);
        sponge.absorb(digest);
        sponge.absorb(salt);
        sponge.absorb(&[attempt]);
        let mut bytes = vec![0u8; length];
        sponge.finalize().squeeze(&mut bytes);
        bytes
    }
}
