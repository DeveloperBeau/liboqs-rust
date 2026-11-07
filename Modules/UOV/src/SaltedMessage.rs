use OQSNativeSHA3::SHAKE256;
use alloc::vec;
use alloc::vec::Vec;

/// SHAKE256 of a message and the salt of its signature, `M || salt`, as `ov_sign` and
/// `_ov_verify` absorb it.
#[derive(Clone)]
pub(crate) struct SaltedMessage {
    hash: SHAKE256,
}

impl SaltedMessage {
    /// The hash of a message and a salt.
    pub(crate) fn new(message: &[u8], salt: &[u8]) -> Self {
        let mut hash = SHAKE256::new();
        hash.absorb(message);
        hash.absorb(salt);
        SaltedMessage { hash }
    }

    /// The value that the public map takes at the point of a valid signature: the first bytes
    /// of the output, one element for each equation.
    pub(crate) fn target(&self, length: usize) -> Vec<u8> {
        let mut target = vec![0u8; length];
        self.hash.clone().finalize().squeeze(&mut target);
        target
    }

    /// The hash of `M || salt || seed`, which each attempt of a signature continues with its
    /// counter byte to make the vinegar values.
    pub(crate) fn withSecretSeed(&self, secretSeed: &[u8]) -> SHAKE256 {
        let mut hash = self.hash.clone();
        hash.absorb(secretSeed);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::SaltedMessage;
    use OQSNativeSHA3::SHAKE256;

    #[test]
    fn theTargetIsSHAKE256OfTheMessageAndTheSalt() {
        let salted = SaltedMessage::new(b"message", b"0123456789abcdef");
        let mut expected = [0u8; 44];
        SHAKE256::hash(b"message0123456789abcdef", &mut expected);
        assert_eq!(salted.target(44), expected);
        // The target is the start of the same output stream for each length.
        assert_eq!(salted.target(32), expected[..32]);
    }

    #[test]
    fn theVinegarHashContinuesWithTheSecretSeed() {
        let salted = SaltedMessage::new(b"m", b"salt");
        let mut hash = salted.withSecretSeed(b"seed");
        hash.absorb(&[7]);
        let mut vinegar = [0u8; 20];
        hash.finalize().squeeze(&mut vinegar);
        let mut expected = [0u8; 20];
        SHAKE256::hash(b"msaltseed\x07", &mut expected);
        assert_eq!(vinegar, expected);
    }
}
