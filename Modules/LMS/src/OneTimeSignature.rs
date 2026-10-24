use crate::OneTimeSignatureType;
use crate::SeedDerivation;
use crate::parameters::{hashLength, identifierLength};
use OQSNativeSHA2::SHA256;
use alloc::vec::Vec;

/// The domain separator `D_PBLC` of the hash of a one-time public key.
const publicKeyDomain: [u8; 2] = [0x80, 0x80];

/// The domain separator `D_MESG` of the hash of a message.
const messageDomain: [u8; 2] = [0x81, 0x81];

/// The length of the input of a step of a hash chain: I, q, the chain index i, the step j and
/// the previous hash.
const chainInputLength: usize = identifierLength + 4 + 2 + 1 + hashLength;

/// The LM-OTS one-time signature of RFC 8554, Section 4, of one parameter set, as
/// `lm_ots_sign.c` and `lm_ots_verify.c` of hash-sigs compute it.
///
/// A key is the key of leaf q of a tree with an identifier I. Its private key elements come
/// from the `SeedDerivation` of the tree, so the type never holds a private key.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OneTimeSignature {
    kind: OneTimeSignatureType,
}

impl OneTimeSignature {
    /// The one-time signature of a type.
    pub(crate) const fn new(kind: OneTimeSignatureType) -> Self {
        OneTimeSignature { kind }
    }

    /// The input of the hash chains of leaf q, with the chain index and the step still zero.
    fn chainInput(identifier: &[u8; identifierLength], q: u32) -> [u8; chainInputLength] {
        let mut input = [0u8; chainInputLength];
        input[..identifierLength].copy_from_slice(identifier);
        input[identifierLength..identifierLength + 4].copy_from_slice(&q.to_be_bytes());
        input
    }

    /// Runs steps `first..last` of chain i on the hash at the end of an input, RFC 8554,
    /// Algorithm 1, step 4: `tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)`.
    fn runChain(input: &mut [u8; chainInputLength], i: u16, first: u32, last: u32) {
        input[identifierLength + 4..identifierLength + 6].copy_from_slice(&i.to_be_bytes());
        for step in first..last {
            input[identifierLength + 6] = step as u8;
            let next = SHA256::hash(input);
            input[identifierLength + 7..].copy_from_slice(&next);
        }
    }

    /// The public key K of the one-time key of leaf q, RFC 8554, Algorithm 1, as
    /// `lm_ots_generate_public_key`: the hash of I, q, `D_PBLC` and the end of each chain.
    pub(crate) fn publicKey(
        self,
        identifier: &[u8; identifierLength],
        q: u32,
        derivation: &SeedDerivation<'_>,
    ) -> [u8; hashLength] {
        let mut publicKeyHash = SHA256::new();
        publicKeyHash.absorb(identifier);
        publicKeyHash.absorb(&q.to_be_bytes());
        publicKeyHash.absorb(&publicKeyDomain);
        let mut derivationInput = derivation.input(q);
        let mut chain = Self::chainInput(identifier, q);
        for i in 0..self.kind.chainCount() as u16 {
            let element = SeedDerivation::value(&mut derivationInput, i);
            chain[identifierLength + 7..].copy_from_slice(&element);
            Self::runChain(&mut chain, i, 0, self.kind.largestDigit());
            publicKeyHash.absorb(&chain[identifierLength + 7..]);
        }
        publicKeyHash.finalize()
    }

    /// The message representative Q of RFC 8554, Algorithm 3, step 4:
    /// `H(I || u32str(q) || u16str(D_MESG) || C || message)`.
    pub(crate) fn messageHash(
        identifier: &[u8; identifierLength],
        q: u32,
        randomizer: &[u8],
        message: &[u8],
    ) -> [u8; hashLength] {
        let mut hash = SHA256::new();
        hash.absorb(identifier);
        hash.absorb(&q.to_be_bytes());
        hash.absorb(&messageDomain);
        hash.absorb(randomizer);
        hash.absorb(message);
        hash.finalize()
    }

    /// The digit i of a message representative with its checksum, `coef` of RFC 8554,
    /// Section 3.1.3, as `lm_ots_coef` computes it.
    pub(crate) fn coefficient(representative: &[u8; hashLength + 2], i: u32, w: u32) -> u32 {
        let index = (i * w / 8) as usize;
        let digitsPerByte = 8 / w;
        let shift = w * (!i & (digitsPerByte - 1));
        let mask = (1 << w) - 1;
        (u32::from(representative[index]) >> shift) & mask
    }

    /// The message representative followed by its checksum, RFC 8554, Algorithm 2, as
    /// `lm_ots_compute_checksum` adds it: the sum of `2^w - 1 - digit` over the digits of the
    /// hash, shifted left by ls, in 16 bits.
    pub(crate) fn withChecksum(self, messageHash: &[u8; hashLength]) -> [u8; hashLength + 2] {
        let w = self.kind.winternitz();
        let mut representative = [0u8; hashLength + 2];
        representative[..hashLength].copy_from_slice(messageHash);
        let digitCount = 8 * hashLength as u32 / w;
        let sum: u32 = (0..digitCount)
            .map(|i| self.kind.largestDigit() - Self::coefficient(&representative, i, w))
            .sum();
        let checksum = (sum << self.kind.checksumShift()) as u16;
        representative[hashLength..].copy_from_slice(&checksum.to_be_bytes());
        representative
    }

    /// Appends the signature of a message representative with the key of leaf q, RFC 8554,
    /// Algorithm 3, as `lm_ots_generate_signature` writes it: the typecode, the randomizer C,
    /// and for each chain i the element i advanced by the digit i.
    pub(crate) fn appendSignature(
        self,
        identifier: &[u8; identifierLength],
        q: u32,
        derivation: &SeedDerivation<'_>,
        randomizer: &[u8; hashLength],
        messageHash: &[u8; hashLength],
        signature: &mut Vec<u8>,
    ) {
        signature.extend_from_slice(&self.kind.code().to_be_bytes());
        signature.extend_from_slice(randomizer);
        let representative = self.withChecksum(messageHash);
        let w = self.kind.winternitz();
        let mut derivationInput = derivation.input(q);
        let mut chain = Self::chainInput(identifier, q);
        for i in 0..self.kind.chainCount() as u16 {
            let element = SeedDerivation::value(&mut derivationInput, i);
            chain[identifierLength + 7..].copy_from_slice(&element);
            let digit = Self::coefficient(&representative, u32::from(i), w);
            Self::runChain(&mut chain, i, 0, digit);
            signature.extend_from_slice(&chain[identifierLength + 7..]);
        }
    }

    /// The public key candidate of a signature of a message representative, RFC 8554,
    /// Algorithm 4b, as `lm_ots_validate_signature_compute` computes it, or `None` when the
    /// signature has another typecode than the type or another length.
    pub(crate) fn candidatePublicKey(
        self,
        identifier: &[u8; identifierLength],
        q: u32,
        messageHash: &[u8; hashLength],
        signature: &[u8],
    ) -> Option<[u8; hashLength]> {
        if signature.len() < 4 || signature[..4] != self.kind.code().to_be_bytes() {
            return None;
        }
        if signature.len() != self.kind.signatureLength() {
            return None;
        }
        let representative = self.withChecksum(messageHash);
        let w = self.kind.winternitz();
        let mut publicKeyHash = SHA256::new();
        publicKeyHash.absorb(identifier);
        publicKeyHash.absorb(&q.to_be_bytes());
        publicKeyHash.absorb(&publicKeyDomain);
        let mut chain = Self::chainInput(identifier, q);
        let elements = signature[4 + hashLength..].chunks_exact(hashLength);
        for (i, element) in (0u16..).zip(elements) {
            chain[identifierLength + 7..].copy_from_slice(element);
            let digit = Self::coefficient(&representative, u32::from(i), w);
            Self::runChain(&mut chain, i, digit, self.kind.largestDigit());
            publicKeyHash.absorb(&chain[identifierLength + 7..]);
        }
        Some(publicKeyHash.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::OneTimeSignature;
    use crate::testInputs::{identifierAndSeed, sequenceBytes};
    use crate::{OneTimeSignatureType, SeedDerivation};
    use OQSNativeAlgorithmTests::OutputDigest;

    const allTypes: [OneTimeSignatureType; 4] = [
        OneTimeSignatureType::winternitz1,
        OneTimeSignatureType::winternitz2,
        OneTimeSignatureType::winternitz4,
        OneTimeSignatureType::winternitz8,
    ];

    /// The signature of the message `the quick brown fox` with the key of leaf 5.
    fn signature(kind: OneTimeSignatureType) -> Vec<u8> {
        let (identifier, seed) = identifierAndSeed();
        let derivation = SeedDerivation::new(&identifier, &seed);
        let randomizer = derivation.randomizer(5);
        let messageHash =
            OneTimeSignature::messageHash(&identifier, 5, &randomizer, b"the quick brown fox");
        let mut signature = Vec::new();
        OneTimeSignature::new(kind).appendSignature(
            &identifier,
            5,
            &derivation,
            &randomizer,
            &messageHash,
            &mut signature,
        );
        signature
    }

    #[test]
    fn publicKeysAreThePublicKeysOfHashSigs() {
        // `OQS_LMS_NAMESPACE_lm_ots_generate_public_key` of the C oracle for leaf 5.
        let expected = [
            "ab51cb0d4fb213d37ef0a6c27b464929cff339b5ddd4a972c8f4ac6a73447826",
            "73c900713a39a17abeed75f95b79bfbc8649617b00a2d80756136afffa440d39",
            "4fcd6d47951ed43779b946c083f74a82694e68bc9e6fed37ac9f25d5470f4460",
            "764e3490fbfdf9aa985cd1a3ff3390a2e6e44766fa8892bd31e1805c129afeb4",
        ];
        let (identifier, seed) = identifierAndSeed();
        let derivation = SeedDerivation::new(&identifier, &seed);
        for (kind, publicKey) in allTypes.into_iter().zip(expected) {
            assert_eq!(
                OutputDigest::of(&OneTimeSignature::new(kind).publicKey(
                    &identifier,
                    5,
                    &derivation
                )),
                publicKey,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn signaturesAreTheSignaturesOfHashSigs() {
        // `OQS_LMS_NAMESPACE_lm_ots_generate_signature` of the C oracle for the message
        // `the quick brown fox`, which derives the randomizer C itself.
        let expected = [
            "2e9ececa0fada7c6df72028740f1509d9fcb0b5c2da51fbefbe02de6f3721d47",
            "6123576ca25d66fe4f2372cc8f22fb2e18a29bf39f923d0926befa43baea38dc",
            "1fc09a8965119fe0df8bf0fcc3f45762bbbdbd02f54c8a8f962fba203d425085",
            "04efc775c9f689deed744f24d20c42f321da60ed5183fe3ffdc634d672bc8953",
        ];
        for (kind, digest) in allTypes.into_iter().zip(expected) {
            let signature = signature(kind);
            assert_eq!(signature.len(), kind.signatureLength(), "{kind:?}");
            assert_eq!(OutputDigest::of(&signature), digest, "{kind:?}");
        }
    }

    #[test]
    fn theCandidateOfAValidSignatureIsThePublicKeyAndOfAnyChangeIsNot() {
        let (identifier, seed) = identifierAndSeed();
        let derivation = SeedDerivation::new(&identifier, &seed);
        for kind in allTypes {
            let oneTime = OneTimeSignature::new(kind);
            let publicKey = oneTime.publicKey(&identifier, 5, &derivation);
            let signature = signature(kind);
            let randomizer: [u8; 32] = signature[4..36].try_into().expect("32 bytes");
            let messageHash =
                OneTimeSignature::messageHash(&identifier, 5, &randomizer, b"the quick brown fox");
            assert_eq!(
                oneTime.candidatePublicKey(&identifier, 5, &messageHash, &signature),
                Some(publicKey),
                "{kind:?}"
            );
            let otherHash =
                OneTimeSignature::messageHash(&identifier, 5, &randomizer, b"the quick brown fix");
            assert_ne!(
                oneTime.candidatePublicKey(&identifier, 5, &otherHash, &signature),
                Some(publicKey),
                "{kind:?}"
            );
            assert_ne!(
                oneTime.candidatePublicKey(&identifier, 6, &messageHash, &signature),
                Some(publicKey),
                "{kind:?}"
            );
            let mut changed = signature.clone();
            *changed.last_mut().expect("a last byte") ^= 1;
            assert_ne!(
                oneTime.candidatePublicKey(&identifier, 5, &messageHash, &changed),
                Some(publicKey),
                "{kind:?}"
            );
            // Another typecode, and a length other than the length of the type.
            let mut otherType = signature.clone();
            otherType[3] ^= 7;
            assert_eq!(
                oneTime.candidatePublicKey(&identifier, 5, &messageHash, &otherType),
                None
            );
            assert_eq!(
                oneTime.candidatePublicKey(
                    &identifier,
                    5,
                    &messageHash,
                    &signature[..signature.len() - 1]
                ),
                None
            );
            let mut longer = signature.clone();
            longer.push(0);
            assert_eq!(
                oneTime.candidatePublicKey(&identifier, 5, &messageHash, &longer),
                None
            );
            assert_eq!(
                oneTime.candidatePublicKey(&identifier, 5, &messageHash, &[0, 0]),
                None
            );
        }
    }

    #[test]
    fn coefficientsAndChecksumsAreTheValuesOfHashSigs() {
        // `OQS_LMS_NAMESPACE_lm_ots_coef` and `lm_ots_compute_checksum` of the C oracle for a
        // hash Q of the sequence of the seed 3: the digits 0, 1, 5 and the last digit of the
        // hash, and the shifted checksum.
        let messageHash: [u8; 32] = sequenceBytes(32, 3).try_into().expect("32 bytes");
        let expected = [
            (OneTimeSignatureType::winternitz1, [0, 1, 0, 1], 15616),
            (OneTimeSignatureType::winternitz2, [1, 1, 0, 1], 11968),
            (OneTimeSignatureType::winternitz4, [5, 3, 13, 5], 7264),
            (OneTimeSignatureType::winternitz8, [83, 195, 180, 181], 3904),
        ];
        for (kind, digits, checksum) in expected {
            let w = kind.winternitz();
            let representative = OneTimeSignature::new(kind).withChecksum(&messageHash);
            assert_eq!(&representative[..32], &messageHash);
            assert_eq!(
                u16::from_be_bytes([representative[32], representative[33]]),
                checksum,
                "{kind:?}"
            );
            let last = 256 / w - 1;
            for (i, digit) in [0, 1, 5, last].into_iter().zip(digits) {
                assert_eq!(
                    OneTimeSignature::coefficient(&representative, i, w),
                    digit,
                    "{kind:?}, digit {i}"
                );
            }
        }
    }

    #[test]
    fn coefficientsReadTheBitsOfRFC8554FromTheHighBitDown() {
        // RFC 8554, Section 3.1.3: digit i is the w bits at bit position i w of the string,
        // counting from the high bit of the first byte.
        let mut representative = [0u8; 34];
        representative[0] = 0b1011_0010;
        representative[32] = 0b0100_0000;
        representative[33] = 0b0000_0110;
        assert_eq!(OneTimeSignature::coefficient(&representative, 0, 1), 1);
        assert_eq!(OneTimeSignature::coefficient(&representative, 1, 1), 0);
        assert_eq!(OneTimeSignature::coefficient(&representative, 6, 1), 1);
        assert_eq!(OneTimeSignature::coefficient(&representative, 0, 2), 0b10);
        assert_eq!(OneTimeSignature::coefficient(&representative, 3, 2), 0b10);
        assert_eq!(OneTimeSignature::coefficient(&representative, 1, 4), 0b0010);
        assert_eq!(
            OneTimeSignature::coefficient(&representative, 0, 8),
            0b1011_0010
        );
        // The last digits read the checksum bytes.
        assert_eq!(OneTimeSignature::coefficient(&representative, 33, 8), 6);
        assert_eq!(OneTimeSignature::coefficient(&representative, 256, 1), 0);
        assert_eq!(OneTimeSignature::coefficient(&representative, 257, 1), 1);
        assert_eq!(OneTimeSignature::coefficient(&representative, 264, 1), 0);
        assert_eq!(OneTimeSignature::coefficient(&representative, 133, 2), 0b00);
        assert_eq!(OneTimeSignature::coefficient(&representative, 134, 2), 0b01);
        assert_eq!(OneTimeSignature::coefficient(&representative, 135, 2), 0b10);
    }
}
