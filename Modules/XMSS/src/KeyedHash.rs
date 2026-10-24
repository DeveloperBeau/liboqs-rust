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
    use crate::testInputs::{address, coreHashes, sequenceBytes};
    use crate::{HashAddress, Parameters, Variant};
    use OQSNativeAlgorithmTests::OutputDigest;

    /// The digests of the outputs of `prf`, `prf_keygen`, `hash_message`, `thash_h` and
    /// `thash_f` of the C program for each core hash, in the order of `coreHashes`.
    const answers: [[&str; 5]; 7] = [
        [
            "22d18e27c88476b304725def60af25bd46a78089433c720416388cb272828914",
            "942b0fb8253822200babd0ec761a356ccbda9f7649a5d6dccc84568f445fe594",
            "178f93eca0673026830075c7a1556e11b45a092c48443ca32aaf5d11b16ff53c",
            "78e955e91389e2e1b8c8ee60786e66fbba432a141fee67ff839cc4146a8e258d",
            "3575b31fe448146c35acbf0111c4e5e094174b34bc5c887157796518524d8f2a",
        ],
        [
            "23a1a0c563a9b5fd85c6a39532205aca045845e567630b8c55b4f9cd40f5743e",
            "2bb70cbf6f68f0689d237bb24d1e8207f782ba1c635b7895a6f2af3d7b622c1a",
            "5f391e68f4afe2e5f7b0d4814c4b32a6e556f523aea1b41cd173711d3e729b78",
            "fd801a14ad63de734dec9b458060066dad40ac4fddbbe0056cfcbae56ecb3d79",
            "84915a2176a6e17a5a082f1abb409d155e2d9e2f45f34b5a3f002df0194c1325",
        ],
        [
            "5de972fccf27287995f358eeabdaeaebbb13b7b65b3a98f21498407f53149821",
            "a085872e7131a35636e55161765061b6266b2ce80f7bd5e35b79118e72f39a30",
            "d3456bb67d67e4ac949084a0d7fa782301530a326dca61a7bcb4f97e45a7bc5e",
            "be9f1bbb078c134f7e33c155ed0abf6dcc45173b83151d758c766d4f8d1dc363",
            "5fd02f98619e5d1f028b5c1c7473eecec5682b2ff532ff2ed6e229a85c4e78c9",
        ],
        [
            "e9e354f22ea9f73af897ce40755edb6acc4e0eaa2a9067c33fb95c933037f406",
            "296234f26a7114c769cf7db3359d2f450ec10f6733bf90e0b076033eea37f507",
            "f2a2d4a2d5ada0d9545a77f63ea8f63e0ea95cb8203e010d2a83bfc2d8cd6b64",
            "1a7323e7456896c380f46c7ed4c18075aae38090ac0b4afee713abe20c91203e",
            "739ad805cfa6df8da4a3d829c9bc8ce9bfbb80699cbfde67cfdec75aaa4241d8",
        ],
        [
            "0bc47120671b50004215f428c115d98113767011463f06c0ebee193aa1f24ec5",
            "17cca6921e779527ff73f354879736a2801f088352c326426fa5d3f3a0e62f24",
            "7125094e2dded2e903df7d14df7c3ed7f2e10253653e5a5ee121d314cf0f7a68",
            "0f0eb6700a397aded45abf7a894f2226f942290e85a92fa44ec1a7563de3f166",
            "889c7cf679624133ce6418a0000a6f52d6c4f5e5ba3e304bb1a20a4e17a78851",
        ],
        [
            "7eddc7c1e03c1528b713b4e270f77a7654e51cae2211b35405e6b2d8130dd925",
            "6ce607a7ebbd1b2a039d9243c3178fdd2a1aa1b6e692f8bb5b25fde42c56a3d1",
            "cc9de5ab94969535b89999a2e081ac4ea39a81510d6c2873b0a84bf861345271",
            "812a1b606fdd86fb052068832cc5275dacfe3dbc19dd9b82a2303b271378a7d9",
            "78c6cae41d7cb358854f9f081aebbaff6bb44bd373d7ff156958911d397ec478",
        ],
        [
            "71cc480dc231ff986d612520f4188c479a16ec396c392953ca42442b55f0822e",
            "93b9f31b5c1a69ec0743f65ae1217f78e3cd0ec76dc561e42e9ba82942da4971",
            "9ce8bbec6dde4fac57cc8f0565ca05adfc42e078a8847c34306658f0d2a76b03",
            "43a166e4b341e7fae9a61842a25b9e30acdf840506623e4d1c4f0f6c9eb12951",
            "b26ac7d5ca5722aa0e7a138926599e87b63ba51a3bf93043f19a9b7de971b9e6",
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
            // `prf(out, in, key)` with the input of seed 1 and the key of seed 2.
            let hash = KeyedHash::new(&parameters, *function, &sequenceBytes(hashLength, 9));
            let input: [u8; 32] = sequenceBytes(32, 1).try_into().expect("32 bytes");
            hash.prf(&mut output, &input, &sequenceBytes(hashLength, 2));
            assert_eq!(
                OutputDigest::of(&output[..hashLength]),
                expected[0],
                "{name} prf"
            );
            // `prf_keygen(out, in, key)`: the input of seed 3 is the public seed and the
            // address, and the key of seed 4 is the secret seed.
            let input = sequenceBytes(hashLength + 32, 3);
            let keyGeneration = KeyedHash::new(&parameters, *function, &input[..hashLength]);
            keyGeneration.prfKeyGeneration(
                &mut output,
                &sequenceBytes(hashLength, 4),
                &addressOfBytes(&input[hashLength..]),
            );
            assert_eq!(
                OutputDigest::of(&output[..hashLength]),
                expected[1],
                "{name} prf_keygen"
            );
            // `hash_message` of R, the root, the index 0x0102030405 and a message of 50 bytes.
            hash.messageHash(
                &mut output,
                &sequenceBytes(hashLength, 5),
                &sequenceBytes(hashLength, 6),
                0x01_0203_0405,
                &sequenceBytes(50, 7),
            );
            assert_eq!(
                OutputDigest::of(&output[..hashLength]),
                expected[2],
                "{name} hash_message"
            );
            // `thash_h` of the children of seed 8 and the public seed of seed 9.
            let mut nodeAddress = address([1, 2, 3, 2, 5, 6, 7, 0]);
            let parent = hash.nodeHash(&sequenceBytes(2 * hashLength, 8), &mut nodeAddress);
            assert_eq!(
                OutputDigest::of(&parent[..hashLength]),
                expected[3],
                "{name} thash_h"
            );
            assert_eq!(nodeAddress, address([1, 2, 3, 2, 5, 6, 7, 2]), "{name}");
            // `thash_f` of the value of seed 10.
            let mut chainAddress = address([1, 2, 3, 0, 5, 6, 7, 9]);
            let mut value = sequenceBytes(hashLength, 10);
            hash.chainHash(&mut value, &mut chainAddress);
            assert_eq!(OutputDigest::of(&value), expected[4], "{name} thash_f");
            assert_eq!(chainAddress, address([1, 2, 3, 0, 5, 6, 7, 1]), "{name}");
        }
    }
}
