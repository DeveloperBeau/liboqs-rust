use crate::Parameters;
use OQSNativeSHA2::SHA512;

/// The hashes of `sntrup761.c`: the first 32 bytes of the SHA-512 of a prefix byte and an
/// input, `Hash_prefix`, and the confirmation and the session key built on it.
pub(crate) struct HashFunctions;

impl HashFunctions {
    /// The prefix of the session key of a decapsulation that rejects.
    pub(crate) const rejectedSessionPrefix: u8 = 0;

    /// The prefix of the session key of an accepted ciphertext.
    pub(crate) const sessionPrefix: u8 = 1;

    /// The prefix of the confirmation.
    const confirmationPrefix: u8 = 2;

    /// The prefix of the hash of the encoded short polynomial `r`.
    const inputPrefix: u8 = 3;

    /// The prefix of the hash of the public key, the cache of the secret key.
    const publicKeyPrefix: u8 = 4;

    /// The first 32 bytes of `SHA-512(prefix || input)`, `Hash_prefix`.
    pub(crate) fn prefixedHash(prefix: u8, parts: &[&[u8]]) -> [u8; Parameters::hashLength] {
        let mut hash = SHA512::new();
        hash.absorb(&[prefix]);
        for part in parts {
            hash.absorb(part);
        }
        let digest = hash.finalize();
        let mut output = [0u8; Parameters::hashLength];
        output.copy_from_slice(&digest[..Parameters::hashLength]);
        output
    }

    /// The hash of a public key, the cache of the secret key: `Hash_prefix(4, pk)`.
    pub(crate) fn publicKeyHash(publicKey: &[u8]) -> [u8; Parameters::hashLength] {
        Self::prefixedHash(Self::publicKeyPrefix, &[publicKey])
    }

    /// The confirmation at the end of a ciphertext, `HashConfirm`:
    /// `Hash_prefix(2, Hash_prefix(3, r) || cache)`.
    pub(crate) fn confirmation(
        encodedShort: &[u8],
        publicKeyHash: &[u8],
    ) -> [u8; Parameters::hashLength] {
        let inputHash = Self::prefixedHash(Self::inputPrefix, &[encodedShort]);
        Self::prefixedHash(Self::confirmationPrefix, &[&inputHash, publicKeyHash])
    }

    /// The session key of a ciphertext, `HashSession`:
    /// `Hash_prefix(b, Hash_prefix(3, r) || c)`.
    pub(crate) fn sessionKey(
        prefix: u8,
        encodedShort: &[u8],
        ciphertext: &[u8],
    ) -> [u8; Parameters::hashLength] {
        let inputHash = Self::prefixedHash(Self::inputPrefix, &[encodedShort]);
        Self::prefixedHash(prefix, &[&inputHash, ciphertext])
    }
}

#[cfg(test)]
mod tests {
    use super::HashFunctions;
    use OQSNativeSHA2::SHA512;

    #[test]
    fn aPrefixedHashIsTheStartOfTheSHA512OfThePrefixAndTheInput() {
        let expected = SHA512::hash(&[4, 1, 2, 3]);
        assert_eq!(
            HashFunctions::prefixedHash(4, &[&[1], &[2, 3]]),
            expected[..32]
        );
        assert_eq!(HashFunctions::publicKeyHash(&[1, 2, 3]), expected[..32]);
        // An empty input hashes the prefix byte alone.
        let three = SHA512::hash(&[3]);
        assert_eq!(HashFunctions::prefixedHash(3, &[]), three[..32]);
    }

    #[test]
    fn theConfirmationAndTheSessionKeyHashTheHashOfTheInput() {
        let input = [9u8; 191];
        let inner = SHA512::hash(&[&[3u8][..], &input].concat());
        let cache = [7u8; 32];
        let confirmation = SHA512::hash(&[&[2u8][..], &inner[..32], &cache].concat());
        assert_eq!(
            HashFunctions::confirmation(&input, &cache),
            confirmation[..32]
        );
        let ciphertext = [5u8; 1039];
        for prefix in [0u8, 1] {
            let session = SHA512::hash(&[&[prefix][..], &inner[..32], &ciphertext].concat());
            assert_eq!(
                HashFunctions::sessionKey(prefix, &input, &ciphertext),
                session[..32]
            );
        }
    }
}
