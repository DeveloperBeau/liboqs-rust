use crate::{Address, HashFamily, Parameters};
use OQSNativeSHA2::{SHA256, SHA512};
use OQSNativeSHA3::SHAKE256;

/// A hash value of `n` bytes in the first bytes of an array of the largest `n`.
pub(crate) type HashValue = [u8; Parameters::maximumHashLength];

/// The keys of one operation and the hash functions of FIPS 205, Section 11, which hash the
/// current address with their input. It is the `slh_var_t` of the C code.
///
/// A SHA-2 set hashes `PK.seed` padded to a whole block before each input, so the context keeps
/// the state after that block, as the C code does, and starts each hash from a copy of it.
pub(crate) struct HashContext {
    parameters: &'static Parameters,
    secretSeed: HashValue,
    secretPRFKey: HashValue,
    publicSeed: HashValue,
    publicRoot: HashValue,
    /// The address of the next hash.
    pub(crate) address: Address,
    /// SHA-256 after the block `PK.seed || toByte(0, 64 - n)`, for a SHA-2 set.
    seededSHA256: SHA256,
    /// SHA-512 after the block `PK.seed || toByte(0, 128 - n)`, for a SHA-2 set of category 3
    /// or 5.
    seededSHA512: SHA512,
}

/// A hash value that holds the bytes of a slice of at most `n` bytes, and zeros after them.
fn hashValue(bytes: &[u8]) -> HashValue {
    let mut value = [0u8; Parameters::maximumHashLength];
    value[..bytes.len()].copy_from_slice(bytes);
    value
}

impl HashContext {
    /// Makes the context of the four key parts, each of `n` bytes.
    pub(crate) fn new(
        parameters: &'static Parameters,
        secretSeed: &[u8],
        secretPRFKey: &[u8],
        publicSeed: &[u8],
        publicRoot: &[u8],
    ) -> Self {
        let n = parameters.hashLength;
        // The C code makes these states for the SHA2 sets only. A set that does not use a
        // state pays one compression for it, and the result is the same.
        let zeros = [0u8; 128];
        let mut seededSHA256 = SHA256::new();
        seededSHA256.absorb(&publicSeed[..n]);
        seededSHA256.absorb(&zeros[..64 - n]);
        let mut seededSHA512 = SHA512::new();
        seededSHA512.absorb(&publicSeed[..n]);
        seededSHA512.absorb(&zeros[..128 - n]);
        HashContext {
            parameters,
            secretSeed: hashValue(&secretSeed[..n]),
            secretPRFKey: hashValue(&secretPRFKey[..n]),
            publicSeed: hashValue(&publicSeed[..n]),
            publicRoot: hashValue(&publicRoot[..n]),
            address: Address::zero,
            seededSHA256,
            seededSHA512,
        }
    }

    /// Makes the context of a secret key `SK.seed || SK.prf || PK.seed || PK.root`.
    pub(crate) fn fromSecretKey(parameters: &'static Parameters, secretKey: &[u8]) -> Self {
        let n = parameters.hashLength;
        Self::new(
            parameters,
            &secretKey[..n],
            &secretKey[n..2 * n],
            &secretKey[2 * n..3 * n],
            &secretKey[3 * n..4 * n],
        )
    }

    /// Makes the context of a public key `PK.seed || PK.root`, whose secret parts are zero.
    pub(crate) fn fromPublicKey(parameters: &'static Parameters, publicKey: &[u8]) -> Self {
        let n = parameters.hashLength;
        let zeros = [0u8; Parameters::maximumHashLength];
        Self::new(
            parameters,
            &zeros[..n],
            &zeros[..n],
            &publicKey[..n],
            &publicKey[n..2 * n],
        )
    }

    /// The parameter set of the keys.
    pub(crate) fn parameters(&self) -> &'static Parameters {
        self.parameters
    }

    /// `PK.root`.
    pub(crate) fn publicRoot(&self) -> &[u8] {
        &self.publicRoot[..self.parameters.hashLength]
    }

    /// `F(PK.seed, ADRS, M_1)` of a value of `n` bytes.
    pub(crate) fn f(&self, value: &[u8]) -> HashValue {
        match self.parameters.hashFamily {
            HashFamily::shake => self.shakeHash(&[value]),
            HashFamily::sha2 => self.sha256Hash(&[value]),
        }
    }

    /// `H(PK.seed, ADRS, M_2)` of two values of `n` bytes.
    pub(crate) fn h(&self, left: &[u8], right: &[u8]) -> HashValue {
        self.t(&[left, right])
    }

    /// `T_l(PK.seed, ADRS, M_l)` of the parts of a message of `l n` bytes.
    pub(crate) fn t(&self, parts: &[&[u8]]) -> HashValue {
        match self.parameters.hashFamily {
            HashFamily::shake => self.shakeHash(parts),
            HashFamily::sha2 if self.parameters.usesSHA512() => self.sha512Hash(parts),
            HashFamily::sha2 => self.sha256Hash(parts),
        }
    }

    /// `PRF(PK.seed, SK.seed, ADRS)`, the secret value of the address.
    pub(crate) fn prf(&self) -> HashValue {
        self.f(&self.secretSeed[..self.parameters.hashLength])
    }

    /// `SHAKE256(PK.seed || ADRS || M, 8 n)`, FIPS 205, Section 11.1.
    fn shakeHash(&self, parts: &[&[u8]]) -> HashValue {
        let n = self.parameters.hashLength;
        let mut sponge = SHAKE256::new();
        sponge.absorb(&self.publicSeed[..n]);
        sponge.absorb(self.address.bytes());
        for part in parts {
            sponge.absorb(part);
        }
        let mut value = [0u8; Parameters::maximumHashLength];
        sponge.finalize().squeeze(&mut value[..n]);
        value
    }

    /// `Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRS^c || M))`, FIPS 205, Section 11.2.
    fn sha256Hash(&self, parts: &[&[u8]]) -> HashValue {
        let mut hash = self.seededSHA256.clone();
        hash.absorb(&self.address.compressed());
        for part in parts {
            hash.absorb(part);
        }
        hashValue(&hash.finalize()[..self.parameters.hashLength])
    }

    /// `Trunc_n(SHA-512(PK.seed || toByte(0, 128 - n) || ADRS^c || M))`, FIPS 205,
    /// Section 11.2.2.
    fn sha512Hash(&self, parts: &[&[u8]]) -> HashValue {
        let mut hash = self.seededSHA512.clone();
        hash.absorb(&self.address.compressed());
        for part in parts {
            hash.absorb(part);
        }
        hashValue(&hash.finalize()[..self.parameters.hashLength])
    }

    /// `PRF_msg(SK.prf, opt_rand, M)`, the randomizer `R` of a signature. With a context, the
    /// message is the message of the pure form, `toByte(0, 1) || toByte(|ctx|, 1) || ctx || M`.
    /// Without one it is the message of the internal function. A context has at most 255 bytes.
    pub(crate) fn prfMessage(
        &self,
        optionalRandomness: &[u8],
        context: Option<&[u8]>,
        message: &[u8],
    ) -> HashValue {
        let n = self.parameters.hashLength;
        let prefix = context.map(|context| [0, context.len() as u8]);
        let mut parts: [&[u8]; 4] = [&optionalRandomness[..n], &[], &[], message];
        if let (Some(prefix), Some(context)) = (&prefix, context) {
            parts[1] = prefix;
            parts[2] = context;
        }
        let key = &self.secretPRFKey[..n];
        match self.parameters.hashFamily {
            HashFamily::shake => {
                let mut sponge = SHAKE256::new();
                sponge.absorb(key);
                for part in parts {
                    sponge.absorb(part);
                }
                let mut value = [0u8; Parameters::maximumHashLength];
                sponge.finalize().squeeze(&mut value[..n]);
                value
            }
            HashFamily::sha2 if self.parameters.usesSHA512() => {
                hashValue(&hmacSHA512(key, &parts)[..n])
            }
            HashFamily::sha2 => hashValue(&hmacSHA256(key, &parts)[..n]),
        }
    }

    /// `H_msg(R, PK.seed, PK.root, M)`, the digest of `m` bytes of a message, with the message
    /// of the pure form when a context is given, as `prfMessage` takes it.
    pub(crate) fn messageDigest(
        &self,
        randomizer: &[u8],
        context: Option<&[u8]>,
        message: &[u8],
        digest: &mut [u8],
    ) {
        let n = self.parameters.hashLength;
        let prefix = context.map(|context| [0, context.len() as u8]);
        let mut parts: [&[u8]; 6] = [
            &randomizer[..n],
            &self.publicSeed[..n],
            &self.publicRoot[..n],
            &[],
            &[],
            message,
        ];
        if let (Some(prefix), Some(context)) = (&prefix, context) {
            parts[3] = prefix;
            parts[4] = context;
        }
        match self.parameters.hashFamily {
            HashFamily::shake => {
                let mut sponge = SHAKE256::new();
                for part in parts {
                    sponge.absorb(part);
                }
                sponge.finalize().squeeze(digest);
            }
            HashFamily::sha2 if self.parameters.usesSHA512() => {
                let mut hash = SHA512::new();
                for part in parts {
                    hash.absorb(part);
                }
                let inner = hash.finalize();
                mgf1SHA512(&[&randomizer[..n], &self.publicSeed[..n], &inner], digest);
            }
            HashFamily::sha2 => {
                let mut hash = SHA256::new();
                for part in parts {
                    hash.absorb(part);
                }
                let inner = hash.finalize();
                mgf1SHA256(&[&randomizer[..n], &self.publicSeed[..n], &inner], digest);
            }
        }
    }

    /// The chain function of FIPS 205, Algorithm 5: `steps` hashes `F` of a value, with the
    /// hash addresses `start` to `start + steps - 1`.
    pub(crate) fn chain(&mut self, value: &[u8], start: u32, steps: u32) -> HashValue {
        let n = self.parameters.hashLength;
        let mut result = hashValue(&value[..n]);
        for position in start..start + steps {
            self.address.setHashAddress(position);
            result = self.f(&result[..n]);
        }
        result
    }

    /// A WOTS+ chain from its secret value: the `PRF` of the chain, then `steps` hashes of the
    /// chain from position 0, as `wots_chain` of the C code does. The chain sets the hash
    /// address of each step, so the hash address 0 of the `PRF` needs no second reset.
    pub(crate) fn wotsChain(&mut self, steps: u32) -> HashValue {
        self.address.setType(Address::wotsPRF);
        self.address.setHashAddress(0);
        let secret = self.prf();
        self.address.setType(Address::wotsHash);
        self.chain(&secret, 0, steps)
    }

    /// The FORS secret value of the tree index of the address, `fors_SKgen` of FIPS 205,
    /// Algorithm 14. The address keeps the type `FORS_PRF`, as in the C code.
    pub(crate) fn forsSecret(&mut self) -> HashValue {
        self.address.setType(Address::forsPRF);
        self.address.setTreeHeight(0);
        self.prf()
    }

    /// The FORS leaf of the tree index of the address: `F` of its secret value, with the type
    /// `FORS_TREE` and the height 0.
    pub(crate) fn forsLeaf(&mut self) -> HashValue {
        let secret = self.forsSecret();
        self.address.setType(Address::forsTree);
        self.f(&secret[..self.parameters.hashLength])
    }
}

/// `HMAC-SHA-256(key, M)` of RFC 2104 for a key of at most 64 bytes, with the message in parts.
fn hmacSHA256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut pad = [0x36u8; 64];
    for (byte, keyByte) in pad.iter_mut().zip(key) {
        *byte ^= keyByte;
    }
    let mut inner = SHA256::new();
    inner.absorb(&pad);
    for part in parts {
        inner.absorb(part);
    }
    let innerDigest = inner.finalize();
    for byte in pad.iter_mut() {
        *byte ^= 0x36 ^ 0x5C;
    }
    let mut outer = SHA256::new();
    outer.absorb(&pad);
    outer.absorb(&innerDigest);
    outer.finalize()
}

/// `HMAC-SHA-512(key, M)` of RFC 2104 for a key of at most 128 bytes, with the message in
/// parts.
fn hmacSHA512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut pad = [0x36u8; 128];
    for (byte, keyByte) in pad.iter_mut().zip(key) {
        *byte ^= keyByte;
    }
    let mut inner = SHA512::new();
    inner.absorb(&pad);
    for part in parts {
        inner.absorb(part);
    }
    let innerDigest = inner.finalize();
    for byte in pad.iter_mut() {
        *byte ^= 0x36 ^ 0x5C;
    }
    let mut outer = SHA512::new();
    outer.absorb(&pad);
    outer.absorb(&innerDigest);
    outer.finalize()
}

/// `MGF1-SHA-256(seed, len)` of RFC 8017, Appendix B.2.1: the hashes of the seed and a 32-bit
/// big-endian counter, from 0, cut to the length of the output.
fn mgf1SHA256(seed: &[&[u8]], output: &mut [u8]) {
    for (counter, block) in output.chunks_mut(32).enumerate() {
        let mut hash = SHA256::new();
        for part in seed {
            hash.absorb(part);
        }
        hash.absorb(&(counter as u32).to_be_bytes());
        block.copy_from_slice(&hash.finalize()[..block.len()]);
    }
}

/// `MGF1-SHA-512(seed, len)` of RFC 8017, Appendix B.2.1.
fn mgf1SHA512(seed: &[&[u8]], output: &mut [u8]) {
    for (counter, block) in output.chunks_mut(64).enumerate() {
        let mut hash = SHA512::new();
        for part in seed {
            hash.absorb(part);
        }
        hash.absorb(&(counter as u32).to_be_bytes());
        block.copy_from_slice(&hash.finalize()[..block.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::{HashContext, hmacSHA256, hmacSHA512, mgf1SHA256, mgf1SHA512};
    use crate::{Address, parameterSets};
    use OQSNativeSHA2::{SHA256, SHA512};
    use OQSNativeSHA3::SHAKE256;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn hmacGivesTheValuesOfRFC4231() {
        // RFC 4231, test cases 1 and 2.
        let key = [0x0Bu8; 20];
        assert_eq!(
            hmacSHA256(&key, &[b"Hi ", b"There"]).to_vec(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        assert_eq!(
            hmacSHA512(&key, &[b"Hi There"]).to_vec(),
            hex(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            )
        );
        assert_eq!(
            hmacSHA256(b"Jefe", &[b"what do ya want ", b"", b"for nothing?"]).to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        assert_eq!(
            hmacSHA512(b"Jefe", &[b"what do ya want for nothing?"]).to_vec(),
            hex(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            )
        );
    }

    #[test]
    fn mgf1GivesTheHashesOfTheSeedAndTheCounter() {
        // The blocks of RFC 8017, Appendix B.2.1, made by hand from the hash functions.
        let mut output = [0u8; 70];
        mgf1SHA256(&[b"se", b"ed"], &mut output);
        let mut expected = Vec::new();
        for counter in 0u8..3 {
            let mut hash = SHA256::new();
            hash.absorb(&[b's', b'e', b'e', b'd', 0, 0, 0, counter]);
            expected.extend_from_slice(&hash.finalize());
        }
        assert_eq!(output.to_vec(), expected[..70].to_vec());
        let mut wide = [0u8; 49];
        mgf1SHA512(&[b"seed"], &mut wide);
        assert_eq!(wide.to_vec(), SHA512::hash(b"seed\0\0\0\0")[..49].to_vec());
    }

    #[test]
    fn mgf1SHA256GivesTheKnownAnswerOfPythonHashlib() {
        // MGF1-SHA-256 of `abc` for 40 bytes, from an independent model on Python hashlib.
        let mut output = [0u8; 40];
        mgf1SHA256(&[b"abc"], &mut output);
        assert_eq!(
            output.to_vec(),
            hex("cf2db1ac9867debdf8ce91f99f141e5544bf26ca36b3fd4f8e4035eec42cab0d46c386ebccef82ba")
        );
    }

    #[test]
    fn sha2FunctionsHashTheSeedBlockTheCompressedAddressAndTheInput() {
        // F of SHA2-128s and H of SHA2-192s, from FIPS 205, Section 11.2, without the stored
        // state of the seed block.
        let publicSeed: Vec<u8> = (0..32).collect();
        let mut context =
            HashContext::new(&parameterSets[0], &[1; 16], &[2; 16], &publicSeed, &[3; 16]);
        context.address.setLayerAddress(3);
        context.address.setTreeAddress(0x0102_0304_0506_0708);
        context.address.setType(Address::wotsHash);
        context.address.setHashAddress(9);
        let mut direct = SHA256::new();
        direct.absorb(&publicSeed[..16]);
        direct.absorb(&[0; 48]);
        direct.absorb(&context.address.compressed());
        direct.absorb(&[7; 16]);
        assert_eq!(&context.f(&[7; 16])[..16], &direct.finalize()[..16]);
        assert_eq!(context.f(&[7; 16])[16..], [0; 16]);
        let mut prfHash = SHA256::new();
        prfHash.absorb(&publicSeed[..16]);
        prfHash.absorb(&[0; 48]);
        prfHash.absorb(&context.address.compressed());
        prfHash.absorb(&[1; 16]);
        assert_eq!(&context.prf()[..16], &prfHash.finalize()[..16]);

        let wide = HashContext::new(&parameterSets[2], &[1; 24], &[2; 24], &publicSeed, &[3; 24]);
        let mut direct = SHA512::new();
        direct.absorb(&publicSeed[..24]);
        direct.absorb(&[0; 104]);
        direct.absorb(&wide.address.compressed());
        direct.absorb(&[5; 24]);
        direct.absorb(&[6; 24]);
        assert_eq!(&wide.h(&[5; 24], &[6; 24])[..24], &direct.finalize()[..24]);
        // F of every SHA-2 set is SHA-256, also for categories 3 and 5.
        let mut direct = SHA256::new();
        direct.absorb(&publicSeed[..24]);
        direct.absorb(&[0; 40]);
        direct.absorb(&wide.address.compressed());
        direct.absorb(&[5; 24]);
        assert_eq!(&wide.f(&[5; 24])[..24], &direct.finalize()[..24]);
    }

    #[test]
    fn shakeFunctionsHashTheSeedTheWholeAddressAndTheInput() {
        let publicSeed: Vec<u8> = (100..132).collect();
        let mut context = HashContext::new(
            &parameterSets[11],
            &[1; 32],
            &[2; 32],
            &publicSeed,
            &[3; 32],
        );
        context.address.setKeyPairAddress(77);
        let mut expected = [0u8; 32];
        let mut sponge = SHAKE256::new();
        sponge.absorb(&publicSeed);
        sponge.absorb(context.address.bytes());
        sponge.absorb(&[8; 32]);
        sponge.absorb(&[9; 32]);
        sponge.finalize().squeeze(&mut expected);
        assert_eq!(context.h(&[8; 32], &[9; 32]), expected);
        assert_eq!(context.t(&[&[8; 32], &[9; 32]]), expected);
    }

    #[test]
    fn chainOfZeroStepsIsTheValueAndEachStepIsOneF() {
        let mut context =
            HashContext::new(&parameterSets[6], &[1; 16], &[2; 16], &[4; 16], &[3; 16]);
        let value = [0x5Au8; 16];
        assert_eq!(&context.chain(&value, 3, 0)[..16], &value);
        let chained = context.chain(&value, 3, 2);
        context.address.setHashAddress(3);
        let first = context.f(&value);
        context.address.setHashAddress(4);
        assert_eq!(chained, context.f(&first[..16]));
    }

    #[test]
    fn pureContextAddsItsPrefixToTheMessageFunctions() {
        for set in [&parameterSets[0], &parameterSets[2], &parameterSets[6]] {
            let n = set.hashLength;
            let context = HashContext::new(set, &[1; 32], &[2; 32], &[4; 32], &[3; 32]);
            // The pure form with a context equals the internal form of the prefixed message.
            let mut prefixed = vec![0, 3];
            prefixed.extend_from_slice(b"ctx");
            prefixed.extend_from_slice(b"message");
            assert_eq!(
                context.prfMessage(&[9; 32], Some(b"ctx"), b"message"),
                context.prfMessage(&[9; 32], None, &prefixed)
            );
            let mut withContext = [0u8; 49];
            let mut internal = [0u8; 49];
            context.messageDigest(
                &[8; 32],
                Some(b"ctx"),
                b"message",
                &mut withContext[..set.digestLength],
            );
            context.messageDigest(&[8; 32], None, &prefixed, &mut internal[..set.digestLength]);
            assert_eq!(withContext, internal);
            // An empty context still adds its two prefix bytes.
            assert_ne!(
                context.prfMessage(&[9; 32], Some(b""), b"message"),
                context.prfMessage(&[9; 32], None, b"message")
            );
            assert_eq!(
                context.prfMessage(&[9; 32], None, b"message")[n..],
                [0; 32][n..]
            );
        }
    }
}
