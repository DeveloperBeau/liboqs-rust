//! The correctness test of liboqs `tests/test_kem.c`, and the rejection paths of BIKE, for each
//! parameter set.

use OQSNativeAlgorithmTests::KEMCorrectnessTest;
use OQSNativeBIKE::BIKE;
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSHA3::{SHA3256, SHA3384};

const parameterSets: [&BIKE; 3] = [&BIKE::bikeL1, &BIKE::bikeL3, &BIKE::bikeL5];

/// The block length `r` and the weight `d` of each set.
fn blockFacts(mechanism: &BIKE) -> (usize, usize) {
    match mechanism.description().name {
        "BIKE-L1" => (12323, 71),
        "BIKE-L3" => (24659, 103),
        _ => (40973, 137),
    }
}

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

/// The secret of the rejection seed `sigma`, the last 32 bytes of the secret key, for a
/// ciphertext: the first 32 bytes of `SHA3-384(sigma || c)`.
fn rejectionSecret(secretKey: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hash = SHA3384::new();
    hash.absorb(&secretKey[secretKey.len() - 32..]);
    hash.absorb(ciphertext);
    hash.finalize()[..32].try_into().expect("32 bytes")
}

fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A random source that records the length of each request, and gives the bytes 0, 1, 2 and
/// so on.
#[derive(Default)]
struct RecordingRandom {
    requests: Vec<usize>,
    next: u8,
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.requests.push(bytes.len());
        for byte in bytes.iter_mut() {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }
}

#[test]
fn testKEMPassesForEveryParameterSet() {
    for (index, mechanism) in parameterSets.into_iter().enumerate() {
        assert_eq!(
            KEMCorrectnessTest::run(mechanism, &mut random(index as u8)),
            Ok(())
        );
    }
}

#[test]
fn encapsulationAndDecapsulationAgreeOnTheSharedSecret() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        for seed in 0..3 {
            let mut random = random(seed);
            let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
            assert_eq!(keyPair.publicKey.len(), description.publicKeyLength);
            assert_eq!(keyPair.secretKey.bytes().len(), description.secretKeyLength);
            let encapsulation = mechanism
                .encapsulate(&keyPair.publicKey, &mut random)
                .expect("encapsulation");
            assert_eq!(encapsulation.ciphertext.len(), description.ciphertextLength);
            let recovered = mechanism
                .decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())
                .expect("decapsulation");
            assert_eq!(
                recovered.bytes(),
                encapsulation.sharedSecret.bytes(),
                "{} seed {seed}",
                description.name
            );
        }
    }
}

#[test]
fn aChangedCiphertextGivesTheSecretOfSigma() {
    for mechanism in parameterSets {
        let (r, _) = blockFacts(mechanism);
        let mut random = random(20);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let secretKey = keyPair.secretKey.bytes();
        let byteCount = mechanism.description().publicKeyLength;
        // A coefficient of c0, the last coefficient of c0 below r, a coefficient of c0 from r up
        // in its last byte, and a bit of the mask c1.
        let changes = [
            (0, 0),
            ((r - 1) / 8, (r - 1) % 8),
            (byteCount - 1, 7),
            (byteCount + 5, 3),
            (byteCount + 31, 7),
        ];
        for (position, bit) in changes {
            let mut changed = encapsulation.ciphertext.clone();
            changed[position] ^= 1 << bit;
            let secret = mechanism
                .decapsulate(&changed, secretKey)
                .expect("decapsulation");
            assert_eq!(
                secret.bytes(),
                rejectionSecret(secretKey, &changed),
                "{} byte {position} bit {bit}",
                mechanism.description().name
            );
        }
    }
}

#[test]
fn aCiphertextWithTheSameBitChangedInTwoBytesIsRejected() {
    for mechanism in parameterSets {
        let mut random = random(21);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let secretKey = keyPair.secretKey.bytes();
        let byteCount = mechanism.description().publicKeyLength;
        // Bytes 0 and 8 of c0 hold bit 0 of its words 0 and 1, and the same bytes of c1 hold
        // the same bit of the message, so each pair of differences cancels in an exclusive or.
        for (first, second) in [(0, 8), (byteCount, byteCount + 8), (0, byteCount)] {
            let mut changed = encapsulation.ciphertext.clone();
            changed[first] ^= 0x01;
            changed[second] ^= 0x01;
            let secret = mechanism
                .decapsulate(&changed, secretKey)
                .expect("decapsulation");
            assert_eq!(
                secret.bytes(),
                rejectionSecret(secretKey, &changed),
                "{} bytes {first} and {second}",
                mechanism.description().name
            );
            assert_ne!(secret.bytes(), encapsulation.sharedSecret.bytes());
        }
    }
}

#[test]
fn decapsulationReadsNeitherTheBlockH1NorSigmaForAValidCiphertext() {
    for mechanism in parameterSets {
        let (_, d) = blockFacts(mechanism);
        let byteCount = mechanism.description().publicKeyLength;
        let mut random = random(22);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        // The block h1 follows the positions and h0, and sigma ends the key.
        let mut changed = keyPair.secretKey.bytes().to_vec();
        let h1Start = 8 * d + byteCount;
        for byte in changed[h1Start..h1Start + byteCount].iter_mut() {
            *byte ^= 0xA5;
        }
        let length = changed.len();
        changed[length - 1] ^= 0x01;
        let secret = mechanism
            .decapsulate(&encapsulation.ciphertext, &changed)
            .expect("decapsulation");
        assert_eq!(secret.bytes(), encapsulation.sharedSecret.bytes());
    }
}

#[test]
fn aChangedSecretKeyGivesTheSecretOfSigma() {
    for mechanism in parameterSets {
        let (_, d) = blockFacts(mechanism);
        let byteCount = mechanism.description().publicKeyLength;
        let mut random = random(23);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let secretKey = keyPair.secretKey.bytes();
        // Every position of h0 zero, a byte of h0, and a byte of the public key in the key.
        let mut positions = secretKey.to_vec();
        positions[..4 * d].fill(0);
        let mut block = secretKey.to_vec();
        block[8 * d] ^= 0xFF;
        let mut publicKey = secretKey.to_vec();
        publicKey[8 * d + 2 * byteCount] ^= 0x10;
        for (index, changed) in [positions, block, publicKey].into_iter().enumerate() {
            let secret = mechanism
                .decapsulate(&encapsulation.ciphertext, &changed)
                .expect("BIKE does not check the secret key");
            assert_eq!(
                secret.bytes(),
                rejectionSecret(&changed, &encapsulation.ciphertext),
                "{} change {index}",
                mechanism.description().name
            );
        }
    }
}

#[test]
fn aPositionPlusRWithinTheReachOfTheRotationCountsAsThePosition() {
    // The copies of the syndrome repeat it every r coefficients up to the largest rotation,
    // 64 (2 largestRotationStep - 1) + 63, so a position p + r below that reach rotates as p.
    // The C code does the same, and does not check the positions.
    for mechanism in parameterSets {
        let (r, d) = blockFacts(mechanism);
        let wordCount = r.div_ceil(64);
        let reach = 64 * (2 * (wordCount / 2).next_power_of_two() - 1) + 63;
        let mut random = random(24);
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        let mut changed = keyPair.secretKey.bytes().to_vec();
        let mut movedCount = 0;
        for bytes in changed[..8 * d].chunks_exact_mut(4) {
            let position = u32::from_le_bytes(bytes.try_into().expect("4 bytes")) as usize;
            if position + r <= reach {
                bytes.copy_from_slice(&((position + r) as u32).to_le_bytes());
                movedCount += 1;
            }
        }
        assert!(movedCount > 0, "{}", mechanism.description().name);
        let secret = mechanism
            .decapsulate(&encapsulation.ciphertext, &changed)
            .expect("decapsulation");
        assert_eq!(secret.bytes(), encapsulation.sharedSecret.bytes());
    }
}

#[test]
fn decapsulationsOfHostileInputsGiveTheSecretsOfTheCLibrary() {
    // liboqs 0.16.0 with the keys of the NIST generator seeded with the bytes 0 to 47: the
    // SHA3-256 of the public and the secret key, the SHA3-256 of the ciphertext and the shared
    // secret of the generator seeded with ones, and the shared secrets of the ciphertext of ones,
    // of the zero ciphertext, of a block c0 of ones below r with a zero mask, and of the valid
    // ciphertext under the key whose positions repeat 0, r - 1, r, 64 R_QWORDS, 2^32 - 1 and
    // 64 (2 largestRotationStep) + 5.
    let expected = [
        [
            "ad72c8aa8bdc2c5e6968b0e0e01b7d3f611c82d3f561a12b7e7110d7020883b4",
            "88b5b7a116f42d03db8f91108e0a6c5833fb5f369fa1d43d09db993371914e02",
            "c4850fd5f1e8349250309dd83f6ec2beafdec388b12801a8eea246934c9b2a28",
            "83cc7cd572fdc8ad2bfe08f2de158e9bf439db9a580e354271621984313e912c",
            "89d5a8ad2f12961969aebe8b17fc5b4e72e29130f85b521faefc671d25d4b618",
            "5083a7aec6d8d321303d692c2c8d2969c7085058c7494690006350b4a9fb21cc",
            "815df59a850d907faf2dbde954a8a941b84e54e3be8995b7a9b528c954e5820b",
            "d86f4d93af33ca3f8e55a059575de937c919443c138de80aff1771c67e17aed2",
        ],
        [
            "cb839c7c542e7297160019397ddedeb417a71adb1eae1a644c89c9d70c85a82a",
            "8c8a6bccc4c14038a9bbf1082ea376b403bd9c4201397b4d44fdacd66f90ee35",
            "8dceae234caeff4e33fc57286539b1ec39fe4540dce627b9dba954870bb73d30",
            "a57614db8a09bb200de5f58d23777e9562653eeb83b05d394c57ec5ac46d6de0",
            "379c53bf6df3bab273f1994a2ca36b90cd9fe6c9bdc4082b5849d0b8816dacb8",
            "10acef5d74f7cf9d9c111c7b174193463e07289a6dfb88eee7b2113938f65434",
            "939a10d57bdf18f0fe3b35052606f7059a78b6399398e75eb6d9fd538663d0bb",
            "a5c9442c85a549f2c63e175dd5070acaa5f1f03ecca1c3cd5d55faacc3ef0f0f",
        ],
        [
            "0b0e7fcadfd26cf8f692d3b96c8272fc10119a0baf4a45bbeb7b5b72ff42cd6d",
            "27ee75e3979908738ddf0dcef40f02521ba27f7f00cd2ffc72dd973505a9db52",
            "c35fdfdf6589e13c48d0a7c34fd7ea056cae3669d9489e8cc3f16986346238a7",
            "70d5b6e19cabf59fe50a1a8840815c6d921e5ea1ab4fbf14f48a33d2dd20cb6c",
            "c63812f8840a13bbb3620bf6b3da0ab4cd79f47de11875d62d0f32d166d1ee33",
            "719a2a6633ff898d7480e4ac5a0ffe0ea717e5cb97cd8c2a929902001b6a4773",
            "2b5f819c6e4f5df45583aea1a6c7c8b9e33f43d070a3d4098cfaff90aa5edafb",
            "151d69c87eac9884ab03d7a069b0bb9ca30f25d530bc7a6e55a56aafb636f93f",
        ],
    ];
    let entropy: [u8; 48] = core::array::from_fn(|index| index as u8);
    for (mechanism, expected) in parameterSets.into_iter().zip(expected) {
        let name = mechanism.description().name;
        let (r, d) = blockFacts(mechanism);
        let byteCount = mechanism.description().publicKeyLength;
        let wordCount = r.div_ceil(64);
        let keyPair = mechanism
            .generateKeyPair(&mut NISTKATRandom::new(&entropy, None))
            .expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        assert_eq!(hexadecimal(&SHA3256::hash(&keyPair.publicKey)), expected[0]);
        assert_eq!(hexadecimal(&SHA3256::hash(secretKey)), expected[1]);
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random(1))
            .expect("encapsulation");
        assert_eq!(
            hexadecimal(&SHA3256::hash(&encapsulation.ciphertext)),
            expected[2]
        );
        assert_eq!(hexadecimal(encapsulation.sharedSecret.bytes()), expected[3]);
        let ones = vec![0xFFu8; byteCount + 32];
        let zeros = vec![0u8; byteCount + 32];
        let mut reducedOnes = zeros.clone();
        reducedOnes[..byteCount].fill(0xFF);
        reducedOnes[byteCount - 1] &= (1 << (r % 8)) - 1;
        let step = (wordCount / 2).next_power_of_two() as u32;
        let edges = [
            0,
            r as u32 - 1,
            r as u32,
            64 * wordCount as u32,
            u32::MAX,
            64 * 2 * step + 5,
        ];
        let mut edgeKey = secretKey.to_vec();
        for (index, bytes) in edgeKey[..8 * d].chunks_exact_mut(4).enumerate() {
            bytes.copy_from_slice(&edges[index % edges.len()].to_le_bytes());
        }
        let cases = [
            (&ones, secretKey, expected[4]),
            (&zeros, secretKey, expected[5]),
            (&reducedOnes, secretKey, expected[6]),
            (&encapsulation.ciphertext, edgeKey.as_slice(), expected[7]),
        ];
        for (index, (ciphertext, key, expected)) in cases.into_iter().enumerate() {
            let secret = mechanism
                .decapsulate(ciphertext, key)
                .expect("decapsulation");
            assert_eq!(hexadecimal(secret.bytes()), expected, "{name} case {index}");
            // Each of them is a rejection.
            assert_eq!(secret.bytes(), rejectionSecret(key, ciphertext));
        }
    }
}

#[test]
fn eachInputOfAWrongLengthIsALengthError() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let keyPair = mechanism.generateKeyPair(&mut random(1)).expect("key pair");
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random(2))
            .expect("encapsulation");
        let lengthError =
            |expected: usize, actual: usize| Err(OQSError::invalidLength { expected, actual });
        assert_eq!(
            mechanism
                .encapsulate(&keyPair.publicKey[1..], &mut random(2))
                .map(|_| ()),
            lengthError(description.publicKeyLength, description.publicKeyLength - 1)
        );
        let mut longKey = keyPair.publicKey.clone();
        longKey.push(0);
        assert_eq!(
            mechanism.encapsulate(&longKey, &mut random(2)).map(|_| ()),
            lengthError(description.publicKeyLength, description.publicKeyLength + 1)
        );
        let mut longCiphertext = encapsulation.ciphertext.clone();
        longCiphertext.push(0);
        assert_eq!(
            mechanism
                .decapsulate(&longCiphertext, keyPair.secretKey.bytes())
                .map(|_| ()),
            lengthError(
                description.ciphertextLength,
                description.ciphertextLength + 1
            )
        );
        assert_eq!(
            mechanism
                .decapsulate(&encapsulation.ciphertext, &keyPair.secretKey.bytes()[2..])
                .map(|_| ()),
            lengthError(description.secretKeyLength, description.secretKeyLength - 2)
        );
        // The ciphertext is checked before the secret key.
        assert_eq!(
            mechanism
                .decapsulate(&encapsulation.ciphertext[1..], &[])
                .map(|_| ()),
            lengthError(
                description.ciphertextLength,
                description.ciphertextLength - 1
            )
        );
    }
}

#[test]
fn aPublicKeyOfTheWrongLengthDrawsNoRandomBytes() {
    for mechanism in parameterSets {
        let mut random = RecordingRandom::default();
        assert!(mechanism.encapsulate(&[0u8; 7], &mut random).is_err());
        assert!(random.requests.is_empty());
    }
}

#[test]
fn bikeHasNoSeededForms() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        assert_eq!(
            (
                description.keyPairSeedLength,
                description.encapsulationSeedLength
            ),
            (0, 0)
        );
        assert_eq!(
            mechanism.generateKeyPairFromSeed(&[0u8; 64]).map(|_| ()),
            Err(OQSError::seedNotSupported)
        );
        let keyPair = mechanism.generateKeyPair(&mut random(3)).expect("key pair");
        assert_eq!(
            mechanism
                .encapsulateWithSeed(&keyPair.publicKey, &[0u8; 32])
                .map(|_| ()),
            Err(OQSError::seedNotSupported)
        );
    }
}

#[test]
fn eachOperationDrawsOneRequestOf64Bytes() {
    // `get_seeds` of the C code draws both seeds in one call of `OQS_randombytes`.
    for mechanism in parameterSets {
        let mut random = RecordingRandom::default();
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        assert_eq!(random.requests, [64]);
        mechanism
            .encapsulate(&keyPair.publicKey, &mut random)
            .expect("encapsulation");
        assert_eq!(random.requests, [64, 64]);
    }
}

#[test]
fn encapsulationUsesOnlyTheFirst32BytesOfItsRequest() {
    struct HalfRandom(u8);
    impl RandomGenerating for HalfRandom {
        fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = if index < 32 { index as u8 } else { self.0 };
            }
        }
    }
    for mechanism in parameterSets {
        let keyPair = mechanism.generateKeyPair(&mut random(4)).expect("key pair");
        let first = mechanism
            .encapsulate(&keyPair.publicKey, &mut HalfRandom(0x00))
            .expect("encapsulation");
        let second = mechanism
            .encapsulate(&keyPair.publicKey, &mut HalfRandom(0xFF))
            .expect("encapsulation");
        assert_eq!(first.ciphertext, second.ciphertext);
        assert_eq!(first.sharedSecret.bytes(), second.sharedSecret.bytes());
        // The key pair uses all 64 bytes: the last 32 are sigma.
        let firstKeys = mechanism
            .generateKeyPair(&mut HalfRandom(0x00))
            .expect("key pair");
        let secondKeys = mechanism
            .generateKeyPair(&mut HalfRandom(0xFF))
            .expect("key pair");
        assert_eq!(firstKeys.publicKey, secondKeys.publicKey);
        let length = firstKeys.secretKey.bytes().len();
        assert_eq!(
            firstKeys.secretKey.bytes()[..length - 32],
            secondKeys.secretKey.bytes()[..length - 32]
        );
        assert_eq!(firstKeys.secretKey.bytes()[length - 32..], [0x00; 32]);
        assert_eq!(secondKeys.secretKey.bytes()[length - 32..], [0xFF; 32]);
    }
}

#[test]
fn theSecretKeyHoldsThePositionsTheBlocksThePublicKeyAndSigma() {
    for mechanism in parameterSets {
        let (r, d) = blockFacts(mechanism);
        let byteCount = mechanism.description().publicKeyLength;
        let mut random = RecordingRandom::default();
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        let secretKey = keyPair.secretKey.bytes();
        for block in 0..2 {
            let mut positions: Vec<usize> = secretKey[4 * d * block..4 * d * (block + 1)]
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("4 bytes")) as usize)
                .collect();
            positions.sort_unstable();
            positions.dedup();
            assert_eq!(positions.len(), d);
            assert!(positions.iter().all(|position| *position < r));
            // The bytes of the block have their bits at the positions and nowhere else.
            let blockStart = 8 * d + block * byteCount;
            let blockBytes = &secretKey[blockStart..blockStart + byteCount];
            let ones: Vec<usize> = (0..8 * byteCount)
                .filter(|bit| blockBytes[bit / 8] >> (bit % 8) & 1 == 1)
                .collect();
            assert_eq!(ones, positions);
        }
        let publicKeyStart = 8 * d + 2 * byteCount;
        assert_eq!(
            &secretKey[publicKeyStart..publicKeyStart + byteCount],
            keyPair.publicKey.as_slice()
        );
        // sigma is the second half of the request, the bytes 32 to 63.
        let sigma: Vec<u8> = (32..64).collect();
        assert_eq!(&secretKey[publicKeyStart + byteCount..], sigma.as_slice());
        // A public key is reduced below r.
        assert_eq!(keyPair.publicKey[byteCount - 1] >> (r % 8), 0);
    }
}
