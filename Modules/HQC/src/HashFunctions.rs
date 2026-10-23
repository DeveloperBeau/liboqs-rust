use crate::parameters::seedLength;
use OQSNativeSHA3::{SHA3256, SHA3512, SHAKE256, SHAKEReader};

/// The hash functions `G`, `H`, `I` and `J` and the expander of HQC, `symmetric.c` of the
/// reference code. Each one absorbs a domain byte after its input.
pub(crate) struct HashFunctions;

/// The domain byte of the expander, `HQC_XOF_DOMAIN`.
const expanderDomain: u8 = 1;
/// The domain byte of `G`, `HQC_G_FCT_DOMAIN`.
const sharedSecretDomain: u8 = 0;
/// The domain byte of `H`, `HQC_H_FCT_DOMAIN`.
const publicKeyDomain: u8 = 1;
/// The domain byte of `I`, `HQC_I_FCT_DOMAIN`.
const keyPairDomain: u8 = 2;
/// The domain byte of `J`, `HQC_J_FCT_DOMAIN`.
const rejectionDomain: u8 = 3;

impl HashFunctions {
    /// The output stream of the expander of a seed, `xof_init`: SHAKE256 of the seed and the
    /// domain byte 1.
    pub(crate) fn expander(seed: &[u8]) -> SHAKEReader {
        let mut function = SHAKE256::new();
        function.absorb(seed);
        function.absorb(&[expanderDomain]);
        function.finalize()
    }

    /// `H`, `hash_h`: SHA3-256 of the public key and the domain byte 1.
    pub(crate) fn publicKeyHash(publicKey: &[u8]) -> [u8; 32] {
        let mut hash = SHA3256::new();
        hash.absorb(publicKey);
        hash.absorb(&[publicKeyDomain]);
        hash.finalize()
    }

    /// `I`, `hash_i`: SHA3-512 of a seed and the domain byte 2, the seeds of the decryption key
    /// and of the encryption key.
    pub(crate) fn keyPairSeeds(seed: &[u8; seedLength]) -> [u8; 64] {
        let mut hash = SHA3512::new();
        hash.absorb(seed);
        hash.absorb(&[keyPairDomain]);
        hash.finalize()
    }

    /// `G`, `hash_g`: SHA3-512 of the public key hash, the message, the salt and the domain
    /// byte 0. The first 32 bytes are the shared secret and the last 32 the seed `theta` of the
    /// encryption.
    pub(crate) fn sharedSecretAndRandomness(
        publicKeyHash: &[u8; 32],
        message: &[u8],
        salt: &[u8],
    ) -> [u8; 64] {
        let mut hash = SHA3512::new();
        hash.absorb(publicKeyHash);
        hash.absorb(message);
        hash.absorb(salt);
        hash.absorb(&[sharedSecretDomain]);
        hash.finalize()
    }

    /// `J`, `hash_j`: SHA3-256 of the public key hash, `sigma`, the ciphertext and the domain
    /// byte 3, the shared secret of a rejected ciphertext.
    pub(crate) fn rejectionSecret(
        publicKeyHash: &[u8; 32],
        sigma: &[u8],
        ciphertext: &[u8],
    ) -> [u8; 32] {
        let mut hash = SHA3256::new();
        hash.absorb(publicKeyHash);
        hash.absorb(sigma);
        hash.absorb(ciphertext);
        hash.absorb(&[rejectionDomain]);
        hash.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::HashFunctions;
    use OQSNativeSHA3::{SHA3256, SHA3512, SHAKE256};

    #[test]
    fn eachFunctionHashesItsInputsAndThenItsDomainByte() {
        let seed = [9u8; 32];
        let mut stream = [0u8; 40];
        HashFunctions::expander(&seed).squeeze(&mut stream);
        let mut expected = [0u8; 40];
        SHAKE256::hash(&[&seed[..], &[1]].concat(), &mut expected);
        assert_eq!(stream, expected);
        assert_eq!(
            HashFunctions::publicKeyHash(b"key"),
            SHA3256::hash(b"key\x01")
        );
        assert_eq!(
            HashFunctions::keyPairSeeds(&seed),
            SHA3512::hash(&[&seed[..], &[2]].concat())
        );
        assert_eq!(
            HashFunctions::sharedSecretAndRandomness(&[1; 32], b"m", b"salt"),
            SHA3512::hash(&[&[1u8; 32][..], b"m", b"salt", &[0]].concat())
        );
        assert_eq!(
            HashFunctions::rejectionSecret(&[1; 32], b"sigma", b"c"),
            SHA3256::hash(&[&[1u8; 32][..], b"sigma", b"c", &[3]].concat())
        );
    }
}
