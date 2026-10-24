use crate::{BigEndian, HashAddress, KeyedHash, Parameters};

/// The largest number of chains of a WOTS+ key, len = 2 n + 3 for n = 64.
pub(crate) const maximumChainCount: usize = 131;

/// The WOTS+ one-time signatures of RFC 8391, Section 3, as `wots.c` computes them for w = 16.
///
/// A key has len chains of n-byte values. Its secret elements come from PRF_keygen of the secret
/// seed, and each step of a chain is the chaining function F at the address of the chain and the
/// step.
pub(crate) struct WOTS;

impl WOTS {
    /// The secret elements of a key, as `expand_seed`: the PRF_keygen of the secret seed at the
    /// address of each chain, with the hash step and the selector 0.
    fn expandSeed(
        hash: &KeyedHash,
        elements: &mut [u8],
        secretSeed: &[u8],
        address: &mut HashAddress,
    ) {
        let parameters = hash.parameters();
        address.setHash(0);
        address.setKeyAndMask(0);
        for (chain, element) in elements
            .chunks_exact_mut(parameters.hashLength)
            .take(parameters.chainCount)
            .enumerate()
        {
            address.setChain(chain as u32);
            hash.prfKeyGeneration(element, secretSeed, address);
        }
    }

    /// The chaining function of `gen_chain`, in place: the steps from `start` that stay below w.
    fn chain(
        hash: &KeyedHash,
        value: &mut [u8],
        start: u32,
        steps: u32,
        address: &mut HashAddress,
    ) {
        let end = start.wrapping_add(steps);
        let mut step = start;
        while step < end && step < Parameters::winternitzParameter {
            address.setHash(step);
            hash.chainHash(value, address);
            step += 1;
        }
    }

    /// The base-w digits of an input, high bits first, as `base_w` for w = 16.
    fn baseW(input: &[u8], digits: &mut [u32]) {
        let mut position = 0;
        let mut bits = 0;
        let mut total = 0u8;
        for digit in digits.iter_mut() {
            if bits == 0 {
                total = input[position];
                position += 1;
                bits += 8;
            }
            bits -= Parameters::digitBits;
            *digit = u32::from(total >> bits) & (Parameters::winternitzParameter - 1);
        }
    }

    /// The length of each chain for a message digest of n bytes, as `chain_lengths`: the base-w
    /// digits of the digest, then the digits of their checksum.
    pub(crate) fn chainLengths(parameters: &Parameters, digest: &[u8]) -> [u32; maximumChainCount] {
        let messageCount = parameters.messageChainCount;
        let mut lengths = [0u32; maximumChainCount];
        Self::baseW(digest, &mut lengths[..messageCount]);
        // `wots_checksum`: the sum of w - 1 - digit, shifted so that the unused bits of its two
        // bytes are the low bits.
        let mut checksum = 0u32;
        for digit in &lengths[..messageCount] {
            checksum += Parameters::winternitzParameter - 1 - digit;
        }
        let checksumBits = Parameters::checksumChainCount as u32 * Parameters::digitBits;
        checksum <<= 8 - checksumBits % 8;
        let mut checksumBytes = [0u8; 2];
        BigEndian::write(u64::from(checksum), &mut checksumBytes);
        Self::baseW(
            &checksumBytes,
            &mut lengths[messageCount..parameters.chainCount],
        );
        lengths
    }

    /// The public key of the WOTS+ key pair of a secret seed at an OTS address, as `wots_pkgen`:
    /// the end of each chain, len n bytes.
    pub(crate) fn publicKey(
        hash: &KeyedHash,
        publicKey: &mut [u8],
        secretSeed: &[u8],
        address: &mut HashAddress,
    ) {
        let parameters = hash.parameters();
        Self::expandSeed(hash, publicKey, secretSeed, address);
        for (chain, element) in publicKey
            .chunks_exact_mut(parameters.hashLength)
            .take(parameters.chainCount)
            .enumerate()
        {
            address.setChain(chain as u32);
            Self::chain(
                hash,
                element,
                0,
                Parameters::winternitzParameter - 1,
                address,
            );
        }
    }

    /// The signature of a digest of n bytes, as `wots_sign`: each chain up to the length of its
    /// digit, len n bytes.
    pub(crate) fn sign(
        hash: &KeyedHash,
        signature: &mut [u8],
        digest: &[u8],
        secretSeed: &[u8],
        address: &mut HashAddress,
    ) {
        let parameters = hash.parameters();
        let lengths = Self::chainLengths(parameters, digest);
        Self::expandSeed(hash, signature, secretSeed, address);
        for (chain, element) in signature
            .chunks_exact_mut(parameters.hashLength)
            .take(parameters.chainCount)
            .enumerate()
        {
            address.setChain(chain as u32);
            Self::chain(hash, element, 0, lengths[chain], address);
        }
    }

    /// The public key that a signature of a digest gives, as `wots_pk_from_sig`: each chain of
    /// the signature continued to its end.
    pub(crate) fn publicKeyFromSignature(
        hash: &KeyedHash,
        publicKey: &mut [u8],
        signature: &[u8],
        digest: &[u8],
        address: &mut HashAddress,
    ) {
        let parameters = hash.parameters();
        let hashLength = parameters.hashLength;
        let lengths = Self::chainLengths(parameters, digest);
        for (chain, (element, signed)) in publicKey
            .chunks_exact_mut(hashLength)
            .zip(signature.chunks_exact(hashLength))
            .take(parameters.chainCount)
            .enumerate()
        {
            address.setChain(chain as u32);
            element.copy_from_slice(signed);
            Self::chain(
                hash,
                element,
                lengths[chain],
                Parameters::winternitzParameter - 1 - lengths[chain],
                address,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WOTS;
    use crate::testInputs::{address, coreHashes, sequenceBytes};
    use crate::{KeyedHash, Parameters, Variant};
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The digests of the outputs of `wots_pkgen` and `wots_sign` of the C program for each core
    /// hash, in the order of `coreHashes`. `wots_pk_from_sig` gives the public key again.
    const answers: [[&str; 2]; 7] = [
        [
            "29d609b363ca4fe1ff1e4892ab5ae3630bc3d8c611212a2776c42b3a58e2e3e2",
            "885abeb19f8c1eda83c9025f3389912e6b64233759f0a8c833f1aa831456f0aa",
        ],
        [
            "1fcc01864d271123772fd0761133fe63333d06e37aab41a9a11cb7226725244c",
            "7165fef4947a31faaf78b0d937a5ccaff1bc8a73f7ccd17a42011b2e00a6c6ed",
        ],
        [
            "beb32342230aea683e579df2a30ea4e9121f3c885aea6f77897f0b125852443e",
            "1c146d7379513f6e4081fd700fe34dc589790106e228dca4104ac55cfe9a1c4c",
        ],
        [
            "a1ca08bb848a2d5972a1e46c252fe05de3a076d0c3f3a00ea9138d001d7444af",
            "5ea8aab773884ccc00b571487976d76a539d67fe99030bf5db0bf7c151b55e95",
        ],
        [
            "1b41613f2a0c26c93f66287bbc70a8f5a129690c326d644109b1c054a3d840d1",
            "aa33e907c319133b1a8339094fcf6e767d956c7a59f2a6b09437715ab2ba991a",
        ],
        [
            "d532dae1ad48f4e4d861c8e87d2f1df050dc27979f222722a0e2ca070543f88b",
            "f88a8b4a49210557a3d271569cdb7e735d6fb19564e536e3cc429f6b7a98fe91",
        ],
        [
            "4b3c46e2b106cc216bd42869db69289232335a92ce1e8068f53efe1be31a911f",
            "fd4e29978938213b3af56dc5558e9f39497277962b9dbba700a3c3359210887f",
        ],
    ];

    #[test]
    fn keysSignaturesAndRecoveredKeysAreThoseOfTheCFunctions() {
        for ((function, identifier), [publicKeyDigest, signatureDigest]) in
            coreHashes.iter().zip(answers)
        {
            let parameters = Parameters::of(Variant::xmss, *identifier).expect("a set");
            let hashLength = parameters.hashLength;
            let length = parameters.wotsSignatureLength;
            let name = alloc::format!("{function:?}");
            let hash = KeyedHash::new(&parameters, *function, &sequenceBytes(hashLength, 12));
            let secretSeed = sequenceBytes(hashLength, 11);
            // The OTS address of layer 1, tree 2 and key pair 3.
            let otsAddress = address([1, 0, 2, 0, 3, 0, 0, 0]);
            let mut publicKey = alloc::vec![0u8; length];
            let mut keyAddress = otsAddress;
            WOTS::publicKey(&hash, &mut publicKey, &secretSeed, &mut keyAddress);
            assert_eq!(
                OutputDigest::of(&publicKey),
                publicKeyDigest,
                "{name} wots_pkgen"
            );
            // The address leaves at the last chain, its last step and the mask selector.
            let lastChain = parameters.chainCount as u32 - 1;
            assert_eq!(
                keyAddress,
                address([1, 0, 2, 0, 3, lastChain, 14, 1]),
                "{name}"
            );
            let message = sequenceBytes(hashLength, 13);
            let mut signature = alloc::vec![0u8; length];
            WOTS::sign(
                &hash,
                &mut signature,
                &message,
                &secretSeed,
                &mut otsAddress.clone(),
            );
            assert_eq!(
                OutputDigest::of(&signature),
                signatureDigest,
                "{name} wots_sign"
            );
            let mut recovered = alloc::vec![0u8; length];
            WOTS::publicKeyFromSignature(
                &hash,
                &mut recovered,
                &signature,
                &message,
                &mut otsAddress.clone(),
            );
            assert_eq!(
                OutputDigest::of(&recovered),
                publicKeyDigest,
                "{name} wots_pk_from_sig"
            );
            // Another message gives another key.
            let mut other = alloc::vec![0u8; length];
            WOTS::publicKeyFromSignature(
                &hash,
                &mut other,
                &signature,
                &sequenceBytes(hashLength, 14),
                &mut otsAddress.clone(),
            );
            assert_ne!(other, recovered, "{name}");
        }
    }

    #[test]
    fn chainLengthsAreTheDigitsAndTheChecksumOfRFC8391() {
        let parameters = Parameters::of(Variant::xmss, 0x01).expect("XMSS-SHA2_10_256");
        // A digest of zeros has 64 digits 0, so the checksum is 64 * 15 = 960 = 0x3C0, whose
        // three digits are 3, C and 0.
        let lengths = WOTS::chainLengths(&parameters, &[0u8; 32]);
        assert!(lengths[..64].iter().all(|length| *length == 0));
        assert_eq!(lengths[64..67], [3, 12, 0]);
        // A digest of 0xF0 bytes gives the digits 15 and 0 in turn: the checksum is 32 * 15.
        let lengths = WOTS::chainLengths(&parameters, &[0xF0u8; 32]);
        assert_eq!(lengths[..4], [15, 0, 15, 0]);
        assert_eq!(lengths[64..67], [1, 14, 0]);
        // A digest of 0xFF bytes has the checksum 0.
        let lengths = WOTS::chainLengths(&parameters, &[0xFFu8; 32]);
        assert!(lengths[..64].iter().all(|length| *length == 15));
        assert_eq!(lengths[64..67], [0, 0, 0]);
        // For n = 24 the 48 digits of zeros give 720 = 0x2D0.
        let parameters = Parameters::of(Variant::xmss, 0x0d).expect("XMSS-SHA2_10_192");
        assert_eq!(
            WOTS::chainLengths(&parameters, &[0u8; 24])[48..51],
            [2, 13, 0]
        );
        // For n = 64 the 128 digits of zeros give 1920 = 0x780.
        let parameters = Parameters::of(Variant::xmss, 0x04).expect("XMSS-SHA2_10_512");
        assert_eq!(
            WOTS::chainLengths(&parameters, &[0u8; 64])[128..131],
            [7, 8, 0]
        );
    }
}
