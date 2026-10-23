use crate::parameters::{Parameters, publicSeedLength, secretSeedLength};
use crate::{BatchedMatrix, FieldArithmetic, KeyForm, OilMatrix};
use OQSNativeAES::AES128;
use OQSNativeEntities::SecretBytes;
use OQSNativeSHA3::SHAKE256;
use alloc::vec::Vec;

/// The key pairs of `ov_keypair.c` and the expansions of the compressed keys.
///
/// A classic secret key is the secret seed, the oil matrix O, the block P1 and the block
/// `S = (P1 + P1^T) O + P2`. SHAKE256 of the secret seed gives the public seed and O. AES-128 in
/// counter mode, keyed with the public seed, gives P1 and then P2. The block P3 of the public
/// key is the upper triangular fold of `O^T (P1 O + P2)`.
pub(crate) struct KeyGenerator;

/// The first counter block of the generator of the public blocks: the nonce and the 32-bit
/// counter of `prng_gen_publicinputs` are all zero.
const firstCounterBlock: [u8; 16] = [0; 16];

impl KeyGenerator {
    /// Fills the public seed and the oil matrix of a secret seed, as `generate_keypair` and
    /// `expand_sk` take them from one output of SHAKE256 of the seed.
    fn expandSecretSeed(
        secretSeed: &[u8],
        publicSeed: &mut [u8; publicSeedLength],
        oil: &mut [u8],
    ) {
        let mut reader = SHAKE256::absorbOnce(secretSeed);
        reader.squeeze(publicSeed);
        reader.squeeze(oil);
    }

    /// Fills the blocks P1 and P2 of a public seed, as `prng_gen_publicinputs` makes them: the
    /// keystream of AES-128 in counter mode with the seed as the key, from the counter block
    /// zero. The generator of the C code keeps the rest of a block for its next call, so P1
    /// and P2 in two calls are one stream.
    fn fillPublicBlocks(publicSeed: &[u8; publicSeedLength], blocks: &mut [u8]) {
        AES128::new(publicSeed).fillCounterKeystream(&firstCounterBlock, blocks);
    }

    /// The key pair of a secret seed in the form of a set: the public key and the secret key,
    /// as `generate_keypair`, `generate_keypair_pkc` and `generate_keypair_pkc_skc` make them.
    pub(crate) fn keyPair<F: FieldArithmetic>(
        parameters: &Parameters,
        secretSeed: &[u8; secretSeedLength],
    ) -> (Vec<u8>, SecretBytes) {
        let entryLength = parameters.oilLength();
        let vinegarBlockLength = parameters.vinegarBlockLength();
        let mut publicSeed = [0u8; publicSeedLength];
        let mut secretKey = SecretBytes::zeroed(parameters.expandedSecretKeyLength());
        let mut classicPublicKey = Vec::new();
        let oilBlock = {
            let (seed, rest) = secretKey.mutableBytes().split_at_mut(secretSeedLength);
            seed.copy_from_slice(secretSeed);
            let (oilBytes, blocks) = rest.split_at_mut(parameters.oilMatrixLength());
            Self::expandSecretSeed(secretSeed, &mut publicSeed, oilBytes);
            // P1 and then P2, which the linear block S starts from.
            Self::fillPublicBlocks(&publicSeed, blocks);
            if parameters.form == KeyForm::classic {
                // The classic public key keeps P1 and P2 as the generator gives them.
                classicPublicKey.reserve_exact(parameters.expandedPublicKeyLength());
                classicPublicKey.extend_from_slice(blocks);
            }
            let (vinegarBlock, linearBlock) = blocks.split_at_mut(vinegarBlockLength);
            let oil = OilMatrix::<F>::new(oilBytes, parameters.vinegarCount(), parameters.oilCount);
            // `calculate_F2_P3`: S = P1 O + P2, then P3 = UT(O^T S), then S += P1^T O.
            BatchedMatrix::addTriangleProduct(linearBlock, vinegarBlock, &oil, entryLength);
            let oilBlock = BatchedMatrix::foldedTransposedProduct(&oil, linearBlock, entryLength);
            BatchedMatrix::addTransposedTriangleProduct(
                linearBlock,
                vinegarBlock,
                &oil,
                entryLength,
            );
            oilBlock
        };
        match parameters.form {
            KeyForm::classic => {
                classicPublicKey.extend_from_slice(&oilBlock);
                (classicPublicKey, secretKey)
            }
            KeyForm::compressedPublicKey => {
                (Self::compressedPublicKey(&publicSeed, &oilBlock), secretKey)
            }
            KeyForm::compressedKeys => {
                // The expanded secret key is wiped when it is dropped, as the C code frees it
                // with `OQS_MEM_secure_free`.
                let publicKey = Self::compressedPublicKey(&publicSeed, &oilBlock);
                (publicKey, SecretBytes::new(secretSeed.to_vec()))
            }
        }
    }

    /// The compressed public key: the public seed and P3.
    fn compressedPublicKey(publicSeed: &[u8; publicSeedLength], oilBlock: &[u8]) -> Vec<u8> {
        let mut publicKey = Vec::with_capacity(publicSeedLength + oilBlock.len());
        publicKey.extend_from_slice(publicSeed);
        publicKey.extend_from_slice(oilBlock);
        publicKey
    }

    /// The classic secret key of a secret seed, as `expand_sk` makes it for a signature with a
    /// compressed secret key: S is `P2 + (P1 + P1^T) O`.
    pub(crate) fn expandedSecretKey<F: FieldArithmetic>(
        parameters: &Parameters,
        secretSeed: &[u8],
    ) -> SecretBytes {
        let mut publicSeed = [0u8; publicSeedLength];
        let mut secretKey = SecretBytes::zeroed(parameters.expandedSecretKeyLength());
        let (seed, rest) = secretKey.mutableBytes().split_at_mut(secretSeedLength);
        seed.copy_from_slice(secretSeed);
        let (oilBytes, blocks) = rest.split_at_mut(parameters.oilMatrixLength());
        Self::expandSecretSeed(secretSeed, &mut publicSeed, oilBytes);
        Self::fillPublicBlocks(&publicSeed, blocks);
        let (vinegarBlock, linearBlock) = blocks.split_at_mut(parameters.vinegarBlockLength());
        let oil = OilMatrix::<F>::new(oilBytes, parameters.vinegarCount(), parameters.oilCount);
        BatchedMatrix::addSymmetricProduct(linearBlock, vinegarBlock, &oil, parameters.oilLength());
        secretKey
    }

    /// The classic public key of a compressed public key, as `expand_pk` makes it: P1 and P2
    /// from the public seed, then P3.
    pub(crate) fn expandedPublicKey(parameters: &Parameters, compressedKey: &[u8]) -> Vec<u8> {
        let (seed, oilBlock) = compressedKey.split_at(publicSeedLength);
        let publicSeed: &[u8; publicSeedLength] = seed.try_into().expect("16 bytes");
        let mut publicKey = Vec::with_capacity(parameters.expandedPublicKeyLength());
        publicKey.resize(
            parameters.vinegarBlockLength() + parameters.mixedBlockLength(),
            0,
        );
        Self::fillPublicBlocks(publicSeed, &mut publicKey);
        publicKey.extend_from_slice(oilBlock);
        publicKey
    }
}

#[cfg(test)]
mod tests {
    use super::KeyGenerator;
    use crate::FieldArithmetic;
    use crate::gf16::GF16;
    use crate::gf256::GF256;
    use crate::parameters::{
        Parameters, ovIII, ovIIICompressedPublicKey, ovIp, ovIpCompressedPublicKey, ovIs,
        ovIsCompressedPublicKey, ovV, ovVCompressedPublicKey, publicSeedLength,
    };
    use crate::testInputs::{digest, sequence};
    use OQSNativeAES::AES128;
    use OQSNativeSHA3::SHAKE256;

    #[test]
    fn theGeneratorOfThePublicBlocksIsOneStreamFromTheCounterZero() {
        // `prng_gen_publicinputs` with the seed of the sequence 32, in calls of 7, 100, 16 and
        // 33 bytes and in one call of 156 bytes, gives the same bytes, from liboqs 0.16.0.
        let seed: [u8; 16] = sequence(16, 32).try_into().expect("16 bytes");
        let mut blocks = vec![0u8; 156];
        KeyGenerator::fillPublicBlocks(&seed, &mut blocks);
        assert_eq!(
            digest(&blocks),
            "519530989c84c4395a7e5829b487ad605a4c603d018040006c253796be94b180"
        );
        // Block n is AES-128 of the counter block with n in its last four bytes, big-endian.
        let mut counterBlocks = [0u8; 48];
        counterBlocks[15] = 0;
        counterBlocks[31] = 1;
        counterBlocks[47] = 2;
        let mut expected = [0u8; 48];
        AES128::new(&seed).encryptBlocks(&counterBlocks, &mut expected);
        assert_eq!(blocks[..48], expected);
    }

    #[test]
    fn theStreamOfTheZeroKeyIsTheAESOfTheCounterBlocks() {
        // AES-128 with the zero key of the blocks 0, 1 and 2: E(K, 0^128) of the GCM test case
        // 2, E(K, Y0) of the tag of the GCM test case 1, and E(K, Y1) of the ciphertext of the
        // GCM test case 2, in the GCM specification of McGrew and Viega.
        let mut blocks = [0u8; 48];
        KeyGenerator::fillPublicBlocks(&[0; 16], &mut blocks);
        let expected: Vec<u8> = [
            "66e94bd4ef8a2c3b884cfa59ca342b2e",
            "58e2fccefa7e3061367f1d57a4e7455a",
            "0388dace60b6a392f328c2b971b2fe78",
        ]
        .concat()
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
        })
        .collect();
        assert_eq!(blocks.to_vec(), expected);
    }

    /// The answers of the C program for a shape: `expand_sk` of the seed 33, `expand_pk` of
    /// the compressed key 34, and `generate_keypair` and `generate_keypair_pkc` of the seed 35.
    struct Answers {
        expandedSecretKey: &'static str,
        expandedPublicKey: &'static str,
        classicPublicKey: &'static str,
        secretKey: &'static str,
        compressedPublicKey: &'static str,
    }

    fn checkShape<F: FieldArithmetic>(
        classic: &Parameters,
        compressed: &Parameters,
        answers: &Answers,
    ) {
        let name = classic.description.name;
        let secretKey = KeyGenerator::expandedSecretKey::<F>(classic, &sequence(32, 33));
        assert_eq!(
            digest(secretKey.bytes()),
            answers.expandedSecretKey,
            "{name}"
        );
        let compressedKey = sequence(classic.compressedPublicKeyLength(), 34);
        let publicKey = KeyGenerator::expandedPublicKey(classic, &compressedKey);
        assert_eq!(publicKey.len(), classic.expandedPublicKeyLength());
        assert_eq!(digest(&publicKey), answers.expandedPublicKey, "{name}");
        let seed: [u8; 32] = sequence(32, 35).try_into().expect("32 bytes");
        let (publicKey, secretKey) = KeyGenerator::keyPair::<F>(classic, &seed);
        assert_eq!(digest(&publicKey), answers.classicPublicKey, "{name}");
        assert_eq!(digest(secretKey.bytes()), answers.secretKey, "{name}");
        let (compressedPublicKey, compressedSecretKey) =
            KeyGenerator::keyPair::<F>(compressed, &seed);
        assert_eq!(
            digest(&compressedPublicKey),
            answers.compressedPublicKey,
            "{name}"
        );
        assert_eq!(compressedSecretKey.bytes(), secretKey.bytes());
        // The classic public key is the expansion of the compressed one, and the classic
        // secret key is the expansion of its seed.
        assert_eq!(
            KeyGenerator::expandedPublicKey(classic, &compressedPublicKey),
            publicKey
        );
        assert_eq!(
            KeyGenerator::expandedSecretKey::<F>(classic, &seed).bytes(),
            secretKey.bytes()
        );
        // The public seed is the first output of SHAKE256 of the secret seed.
        let mut publicSeed = [0u8; publicSeedLength];
        SHAKE256::hash(&seed, &mut publicSeed);
        assert_eq!(compressedPublicKey[..publicSeedLength], publicSeed);
    }

    #[test]
    fn theKeysOfTheShapeOfOVIsAreTheKeysOfTheCCode() {
        checkShape::<GF16>(
            &ovIs,
            &ovIsCompressedPublicKey,
            &Answers {
                expandedSecretKey: "ad15699dc6d3d6e49ba6fbb0bc5a38537e07ae0967360e5987b30b93b52386f4",
                expandedPublicKey: "53efcc4a67fc0349df7d4da8eb88598bc85a811e986347231c9d2679bda020dd",
                classicPublicKey: "3f990b0236c9cbe5b05c4c0e5d8acc1c0ae01f9e524bc452fffd34cde10ec30c",
                secretKey: "d9332ff945e3ddc613044b27b0b3653b38e019a75d67b05733d236c6da99dd77",
                compressedPublicKey: "ebf295b78ccfc33ca71a8d70592c74b2070c311f886c0732412eaa60f0cc0e9d",
            },
        );
    }

    #[test]
    fn theKeysOfTheShapeOfOVIpAreTheKeysOfTheCCode() {
        checkShape::<GF256>(
            &ovIp,
            &ovIpCompressedPublicKey,
            &Answers {
                expandedSecretKey: "18b29e28d0bfa91b86ebe35e3233c53d78a3724cc87b70f983f1e0374bef7bb6",
                expandedPublicKey: "8ce2ee3f0c8e3fb5a9f01171b3e9c698e45c5813cf751abe6c17ce3385ff3723",
                classicPublicKey: "ca1ea6c30174a6fe390e5dc09e2b5ca90c60f1d94540546b233a69ec7b6837b7",
                secretKey: "15fa6f4c7d1ca8fc8c57120b0e9547b2541ba621e8c8b6d0317556be3eef3478",
                compressedPublicKey: "3701bb96a20b494b17ab1bd4c163d810f24b176433b08fb78a1e05357362cdd0",
            },
        );
    }

    #[test]
    fn theKeysOfTheShapeOfOVIIIAreTheKeysOfTheCCode() {
        checkShape::<GF256>(
            &ovIII,
            &ovIIICompressedPublicKey,
            &Answers {
                expandedSecretKey: "26251aec7e134b3777deafe1c84b3203e236750357dbccb6918095daa704d760",
                expandedPublicKey: "a638836fc968d7d8eaee459621c91de9d38c70256bfd18c395717a2042ff1f2e",
                classicPublicKey: "c916094e37c7e942d0b79ee506c1fbc5da5b7c63adb0e8c986444ac68d0fa938",
                secretKey: "c1529967b8235d668d53bafca21e1de6c501fae61c02ca4ed2509e8c107f715b",
                compressedPublicKey: "ea64418ce318bceb839fac915a360a625b5e8e64fad11783d7d56fbfac514fd6",
            },
        );
    }

    #[test]
    fn theKeysOfTheShapeOfOVVAreTheKeysOfTheCCode() {
        checkShape::<GF256>(
            &ovV,
            &ovVCompressedPublicKey,
            &Answers {
                expandedSecretKey: "6640567b9af4076a47f42cb720d6368a7953b9ea2c3d6e1a3e041572344b8caa",
                expandedPublicKey: "6ab6459f003dd85e4bf93434e518c17704c3a5f75e949ba5fe01fb83e09c0791",
                classicPublicKey: "93bf510173007c4569a7c70cfab0259dd3947a7a39509ba7777f2014e6106f39",
                secretKey: "05d8e2d40665b23c711f1d6bdacacbc31c23970d98c9d3ba9b206a33f91df0ac",
                compressedPublicKey: "929ad000bd56aeb7765b146ece7796bcf45f71c93ba51d958c15e352acf33a18",
            },
        );
    }
}
