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
    use crate::testInputs::{address, coreHashes, digest, pattern};
    use crate::{KeyedHash, Parameters, Variant};

    /// The SHA-256 of the outputs of `wots_pkgen`, `wots_sign` and `wots_pk_from_sig` of the C
    /// program for each core hash, in the order of `coreHashes`.
    const answers: [[&str; 2]; 7] = [
        [
            "bdd2b79eeadfbbdc2f00b1718756aa118872da7d99f6f69e463ddfaa06994d66",
            "edbd92866a5c8f99b83488ac827ed66da28cc7debf9be332a1321e41c28ffc5c",
        ],
        [
            "87834a0c79687f4718a48defe95d48f880ab363dce18c8556cc7bb49e6fd3668",
            "aa029e957fdf67d1976d2eb9eb03751ee25439c6f16e2843553224fd9b4a8631",
        ],
        [
            "69cd5bbea81915ab5384368d9709cd28d170ecc7a395a6dc560f8c6c6c1eae1e",
            "52fc835d63bf630eef6aa1703b6c855c2b865d91acc22f9e0920d16d935ced71",
        ],
        [
            "5eb0b3747c66357d4ce5a8196a1aeb134aad96d70c15ff0ad01d53136965e858",
            "f778c03f84d4e44c581bebc581a063968bb933f8e78ffed53a4aa3feb9804056",
        ],
        [
            "776d00d1cf6dc503428b03a1cc5219a8e144924093e0d9f588c6cce89d465ab1",
            "e24c444583c27b3710bc9d982355379a9bc37d3228442751e546108623f67449",
        ],
        [
            "3f6c4ea6ae0a510739b7ecd70372395a814192a5f3b27a133b3f50ed56f86b76",
            "b51601d337eff5542714cddab14e069c90e1b2247dbbc781fb9a4a47c37b7e19",
        ],
        [
            "aa389866a092d57986f23eb6baef137f2ee3aadc908b82553275f97ad4099c2d",
            "b406ff3ba6e621d070dce38a0c58a0b476982163e74d203126e7ceb0cde92bb0",
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
            let hash = KeyedHash::new(&parameters, *function, &pattern(hashLength, 12));
            let secretSeed = pattern(hashLength, 11);
            // The OTS address of layer 1, tree 2 and key pair 3.
            let otsAddress = address([1, 0, 2, 0, 3, 0, 0, 0]);
            let mut publicKey = alloc::vec![0u8; length];
            let mut keyAddress = otsAddress;
            WOTS::publicKey(&hash, &mut publicKey, &secretSeed, &mut keyAddress);
            assert_eq!(digest(&publicKey), publicKeyDigest, "{name} wots_pkgen");
            // The address leaves at the last chain, its last step and the mask selector.
            let lastChain = parameters.chainCount as u32 - 1;
            assert_eq!(
                keyAddress,
                address([1, 0, 2, 0, 3, lastChain, 14, 1]),
                "{name}"
            );
            let message = pattern(hashLength, 13);
            let mut signature = alloc::vec![0u8; length];
            WOTS::sign(
                &hash,
                &mut signature,
                &message,
                &secretSeed,
                &mut otsAddress.clone(),
            );
            assert_eq!(digest(&signature), signatureDigest, "{name} wots_sign");
            let mut recovered = alloc::vec![0u8; length];
            WOTS::publicKeyFromSignature(
                &hash,
                &mut recovered,
                &signature,
                &message,
                &mut otsAddress.clone(),
            );
            assert_eq!(
                digest(&recovered),
                publicKeyDigest,
                "{name} wots_pk_from_sig"
            );
            // Another message gives another key.
            let mut other = alloc::vec![0u8; length];
            WOTS::publicKeyFromSignature(
                &hash,
                &mut other,
                &signature,
                &pattern(hashLength, 14),
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
