use crate::{BigEndian, CoreHash, HashAddress, HashState, Parameters};

/// The domain value X of toByte(X, padding) for the chaining function F, `XMSS_HASH_PADDING_F`.
const chainDomain: u8 = 0;
/// The domain value of the tree hash H, `XMSS_HASH_PADDING_H`.
const nodeDomain: u8 = 1;
/// The domain value of the message hash H_msg, `XMSS_HASH_PADDING_HASH`.
const messageDomain: u8 = 2;
/// The domain value of the PRF, `XMSS_HASH_PADDING_PRF`.
const prfDomain: u8 = 3;
/// The domain value of the PRF of the WOTS+ key generation, `XMSS_HASH_PADDING_PRF_KEYGEN`.
const keyGenerationDomain: u8 = 4;

/// The zero bytes in front of a domain value: at most 63, for n = 64.
const zeros: [u8; 64] = [0; 64];

/// The keyed hash functions of `hash.c` for one public seed: the chaining function F, the tree
/// hash H with its bitmasks, the message hash H_msg and the two PRFs, each over the `CoreHash` of
/// the set.
///
/// Every key and bitmask of F and H is a PRF of the public seed, whose input starts with the same
/// n + padding bytes. The state after those bytes is computed once, so each such PRF costs one
/// compression less for the SHA-2 sets. The output is the same as the output of the C code.
pub(crate) struct KeyedHash<'parameters> {
    parameters: &'parameters Parameters,
    function: CoreHash,
    publicSeed: [u8; 64],
    publicSeedPRF: HashState,
}

impl<'parameters> KeyedHash<'parameters> {
    /// Makes the functions of a public seed of n bytes.
    pub(crate) fn new(
        parameters: &'parameters Parameters,
        function: CoreHash,
        publicSeed: &[u8],
    ) -> Self {
        let hashLength = parameters.hashLength;
        let mut seed = [0u8; 64];
        seed[..hashLength].copy_from_slice(&publicSeed[..hashLength]);
        let mut publicSeedPRF = HashState::new(function);
        Self::absorbDomain(&mut publicSeedPRF, parameters, prfDomain);
        publicSeedPRF.absorb(&seed[..hashLength]);
        KeyedHash {
            parameters,
            function,
            publicSeed: seed,
            publicSeedPRF,
        }
    }

    /// The parameters of the set.
    pub(crate) fn parameters(&self) -> &'parameters Parameters {
        self.parameters
    }

    /// The public seed.
    pub(crate) fn publicSeed(&self) -> &[u8] {
        &self.publicSeed[..self.parameters.hashLength]
    }

    /// Absorbs toByte(X, padding), the big-endian domain value of the padding length.
    fn absorbDomain(state: &mut HashState, parameters: &Parameters, domain: u8) {
        state.absorb(&zeros[..parameters.paddingLength - 1]);
        state.absorb(&[domain]);
    }

    /// PRF(KEY, M) of `prf` with a key of n bytes and an input of 32 bytes: the hash of
    /// toByte(3, padding), the key and the input. The output has n bytes.
    pub(crate) fn prf(&self, output: &mut [u8], input: &[u8; 32], key: &[u8]) {
        let mut state = HashState::new(self.function);
        Self::absorbDomain(&mut state, self.parameters, prfDomain);
        state.absorb(&key[..self.parameters.hashLength]);
        state.absorb(input);
        state.finish(output);
    }

    /// The PRF of the public seed and an address, the key or a bitmask of F and H.
    fn publicSeedPRF(&self, output: &mut [u8], address: &HashAddress) {
        let mut state = self.publicSeedPRF.clone();
        state.absorb(&address.bytes());
        state.finish(output);
    }

    /// PRF_keygen of `prf_keygen`: the hash of toByte(4, padding), the secret seed, the public
    /// seed and an address, one secret element of a WOTS+ key.
    pub(crate) fn prfKeyGeneration(
        &self,
        output: &mut [u8],
        secretSeed: &[u8],
        address: &HashAddress,
    ) {
        let hashLength = self.parameters.hashLength;
        let mut state = HashState::new(self.function);
        Self::absorbDomain(&mut state, self.parameters, keyGenerationDomain);
        state.absorb(&secretSeed[..hashLength]);
        state.absorb(self.publicSeed());
        state.absorb(&address.bytes());
        state.finish(output);
    }

    /// H_msg of `hash_message`: the hash of toByte(2, padding), the randomness R, the root, the
    /// index in n bytes and the message.
    pub(crate) fn messageHash(
        &self,
        output: &mut [u8],
        randomness: &[u8],
        root: &[u8],
        index: u64,
        message: &[u8],
    ) {
        let hashLength = self.parameters.hashLength;
        let mut indexBytes = [0u8; 64];
        BigEndian::write(index, &mut indexBytes[..hashLength]);
        let mut state = HashState::new(self.function);
        Self::absorbDomain(&mut state, self.parameters, messageDomain);
        state.absorb(&randomness[..hashLength]);
        state.absorb(&root[..hashLength]);
        state.absorb(&indexBytes[..hashLength]);
        state.absorb(message);
        state.finish(output);
    }

    /// The tree hash RAND_HASH of `thash_h`: the parent of two nodes of n bytes each, with the
    /// key and the two halves of the bitmask from the PRF of the public seed. The address leaves
    /// with the selector 2, as in the C code.
    pub(crate) fn nodeHash(&self, children: &[u8], address: &mut HashAddress) -> [u8; 64] {
        let hashLength = self.parameters.hashLength;
        let mut key = [0u8; 64];
        let mut masked = [0u8; 128];
        address.setKeyAndMask(0);
        self.publicSeedPRF(&mut key, address);
        address.setKeyAndMask(1);
        self.publicSeedPRF(&mut masked, address);
        address.setKeyAndMask(2);
        self.publicSeedPRF(&mut masked[hashLength..], address);
        for (byte, child) in masked.iter_mut().zip(&children[..2 * hashLength]) {
            *byte ^= child;
        }
        let mut state = HashState::new(self.function);
        Self::absorbDomain(&mut state, self.parameters, nodeDomain);
        state.absorb(&key[..hashLength]);
        state.absorb(&masked[..2 * hashLength]);
        let mut parent = [0u8; 64];
        state.finish(&mut parent);
        parent
    }

    /// The chaining function F of `thash_f` on a value of n bytes, in place, with the key and the
    /// bitmask from the PRF of the public seed. The address leaves with the selector 1.
    pub(crate) fn chainHash(&self, value: &mut [u8], address: &mut HashAddress) {
        let hashLength = self.parameters.hashLength;
        let mut key = [0u8; 64];
        let mut masked = [0u8; 64];
        address.setKeyAndMask(0);
        self.publicSeedPRF(&mut key, address);
        address.setKeyAndMask(1);
        self.publicSeedPRF(&mut masked, address);
        for (byte, input) in masked.iter_mut().zip(&value[..hashLength]) {
            *byte ^= input;
        }
        let mut state = HashState::new(self.function);
        Self::absorbDomain(&mut state, self.parameters, chainDomain);
        state.absorb(&key[..hashLength]);
        state.absorb(&masked[..hashLength]);
        state.finish(value);
    }
}

#[cfg(test)]
mod tests {
    use super::KeyedHash;
    use crate::testInputs::{address, coreHashes, hex, pattern};
    use crate::{HashAddress, Parameters, Variant};

    /// The outputs of `prf`, `prf_keygen`, `hash_message`, `thash_h` and `thash_f` of the C
    /// program for each core hash, in the order of `coreHashes`.
    const answers: [[&str; 5]; 7] = [
        [
            "29f8d6ad6e501cf0ba3dbc82cc88b2c82c0aa2759f369159c49068f1d4cc0116",
            "fb1ccad68b304b890aec6078967e28c6fa91616ad0c0a90c2bb7b21a4019602b",
            "38ae3a025051b68c8e7fd96c0703249e23afb918b5f07f8da2e953e1f20e4cc5",
            "a75ff6aa7f2f54e82df26ea68abc36be49e66cc8bcda596cb48aaa2f9de66287",
            "1b34d9181876e87f14c5e7ea68adbc8f997fff6dcec803a0569ae044e39c078a",
        ],
        [
            "f0d57c5bfcdc0d7fb9bface2a91fd7e6ba7457b0d0d1a23f",
            "2ef30d4821d231313ac5b4736a2726d804e7e37d5f33b0f6",
            "42695064f4c52b21849af8fcee430c893c1dffbd96853b37",
            "48a35f0a45844834c740e3a83d16cc08108f5fc65f79491c",
            "8021d7fc6f800475799e89b2bbde54b25da42fe653858596",
        ],
        [
            "d953b34b4c844eef4d552ae39b19d9d3825711571565bf08f95ec17891e413c6",
            "c8e5797d7b2f918d89320e0b0cb9a9b98a2e91ebd7845ece7cc44f6a9288ec43",
            "2d8265049d9fca3fbea09d61d6d7d771162e8a12dab0e242aa50c1e5cda09b07",
            "23a9794fa14e311798a84d6e71aad049055921860e92148dc50eb5ce7b481396",
            "e5feea322d00aeb380c1e1144616fa6755eeddd235434c54dbc878592e702301",
        ],
        [
            "cc179d20fb1c1b2988ec3ede34399e045f50541ac7df64fedf1b2b82e2b0fdca478fde606c5143c14b3cfd124b09747cc9e8b112afe8178511a353a101711c64",
            "c664e2747da17cbac0da4670bade7ec86495b28a90d5006ef3c0da93e8da1ae74cb60d0e56c0601f3dbcea205841bea592a2ba7e667c7183bd687a33b9948882",
            "caf9f6756960e2c6ef54ec13241870a59d0d951550d22568144c38aaec0573de9f20178ecc23824ef872978ab7752d636b463461c6c388b3bea55354e39d3531",
            "a1004ae7a9ab0cae2bcd528638e688d4e714d5f36807a0314382b04d10220008b385821ca7a533320f745b096c1e9100380a5865e0d3a980b33ba96a4ab0589c",
            "7ce4a444f4afad8b3c2c3d2e49123dfabbc69337e5175c7a8f49924f3763afcc7be515a767778dc49e6e62f7aae7704140c6e3e3ff3286fc40cfff5b84ba7e3c",
        ],
        [
            "7568d4d023067a1b1675bd1de0d4e9a46620137b1f329e7b016a9520f5eb8300b8592d6785a2dda5d993a9173495fe06b1d0b2f38e94638ed990316cad62700e",
            "2ec7278e1db787aebb0d1c411d6f8228a09c16a004b18b481b0fc870c7dfc5d55ec88a9fbc4656f830c258444225d3f0fdaf3c048d8f93f0962749c35579d924",
            "5692fbc34e46b41615256f395850fb2c7c175c648075186a144b11ae5259bdfcc9a529ff06b29ffd7f0877719c1822a8487a975e282fc5da48adde98c0aa09ca",
            "6d8b53536137f5f3614f10b2407c6f2fc2a71faf6219222901c6a8acb1588718b11491bcdfa212934a310667d95a49c2f196e9c129d64e5962833823e2737603",
            "8205dbb043a64ea4e85b5fbf8fe3856cd79e1585db8a2ea60b7bf6ebc3cf85559fcd07ffc6ed34b5c6675bfd70c0c8ab87e4e165ae876e2622eb4b56bce3e4ef",
        ],
        [
            "63c1d8ab13c5043fb4130f103c44c58870510d1512dfabf5",
            "4dfc9cbc4b8ed10620977c29ddcf2d0164fcc6954bab5a52",
            "f2c36821ff3292d5931df64bba2c2d06fac95f0f19ba53b8",
            "14b415eb587a98d95747ea3301d372b464ce594c10498ba7",
            "0b56b4b2ac6af020177c62780f32a381b2d47290fc666a30",
        ],
        [
            "c6d2a920aa2a180f4ea1e8e9d1e58e27538dd1b20cbb098d93d8e4e058f9733b",
            "a46d2ce4883d783d68e9167fe64e9fe2ad164b84f9aa2358f052af2b45071d3d",
            "c064223d40f7f07be4783c7d4d3bcaba09aa0e1abd869cab68d8add8cbb27d0c",
            "2194af96e590ecbbd16e9c5c70c591166e0e2202af39ae42d4e10b2acb3efbe7",
            "233045116be93cbec3e29bcc34bf1788a03d0e2305b7d345c323061005691c90",
        ],
    ];

    /// The address of 32 bytes, read as eight big-endian words.
    fn addressOfBytes(bytes: &[u8]) -> HashAddress {
        let words: [u32; 8] = core::array::from_fn(|index| {
            u32::from_be_bytes(bytes[4 * index..4 * index + 4].try_into().expect("4 bytes"))
        });
        address(words)
    }

    #[test]
    fn eachFunctionGivesTheOutputOfItsCFunctionForEachCoreHash() {
        for ((function, identifier), expected) in coreHashes.iter().zip(answers) {
            let parameters = Parameters::of(Variant::xmss, *identifier).expect("a set");
            let hashLength = parameters.hashLength;
            let name = alloc::format!("{function:?}");
            let mut output = [0u8; 64];
            // `prf(out, in, key)` with the input of label 1 and the key of label 2.
            let hash = KeyedHash::new(&parameters, *function, &pattern(hashLength, 9));
            let input: [u8; 32] = pattern(32, 1).try_into().expect("32 bytes");
            hash.prf(&mut output, &input, &pattern(hashLength, 2));
            assert_eq!(hex(&output[..hashLength]), expected[0], "{name} prf");
            // `prf_keygen(out, in, key)`: the input of label 3 is the public seed and the
            // address, and the key of label 4 is the secret seed.
            let input = pattern(hashLength + 32, 3);
            let keyGeneration = KeyedHash::new(&parameters, *function, &input[..hashLength]);
            keyGeneration.prfKeyGeneration(
                &mut output,
                &pattern(hashLength, 4),
                &addressOfBytes(&input[hashLength..]),
            );
            assert_eq!(hex(&output[..hashLength]), expected[1], "{name} prf_keygen");
            // `hash_message` of R, the root, the index 0x0102030405 and a message of 50 bytes.
            hash.messageHash(
                &mut output,
                &pattern(hashLength, 5),
                &pattern(hashLength, 6),
                0x01_0203_0405,
                &pattern(50, 7),
            );
            assert_eq!(
                hex(&output[..hashLength]),
                expected[2],
                "{name} hash_message"
            );
            // `thash_h` of the children of label 8 and the public seed of label 9.
            let mut nodeAddress = address([1, 2, 3, 2, 5, 6, 7, 0]);
            let parent = hash.nodeHash(&pattern(2 * hashLength, 8), &mut nodeAddress);
            assert_eq!(hex(&parent[..hashLength]), expected[3], "{name} thash_h");
            assert_eq!(nodeAddress, address([1, 2, 3, 2, 5, 6, 7, 2]), "{name}");
            // `thash_f` of the value of label 10.
            let mut chainAddress = address([1, 2, 3, 0, 5, 6, 7, 9]);
            let mut value = pattern(hashLength, 10);
            hash.chainHash(&mut value, &mut chainAddress);
            assert_eq!(hex(&value), expected[4], "{name} thash_f");
            assert_eq!(chainAddress, address([1, 2, 3, 0, 5, 6, 7, 1]), "{name}");
        }
    }
}
