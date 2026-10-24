//! The correctness test of liboqs `tests/test_kem.c`, and the rejection paths of Classic
//! McEliece, for each parameter set.

use OQSNativeAlgorithmTests::{FuzzRandom, KEMCorrectnessTest};
use OQSNativeClassicMcEliece::ClassicMcEliece;
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{KeyPair, OQSError};
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeSHA3::SHAKE256;
use std::sync::OnceLock;

const parameterSets: [&ClassicMcEliece; 10] = [
    &ClassicMcEliece::classicMcEliece348864,
    &ClassicMcEliece::classicMcEliece348864f,
    &ClassicMcEliece::classicMcEliece460896,
    &ClassicMcEliece::classicMcEliece460896f,
    &ClassicMcEliece::classicMcEliece6688128,
    &ClassicMcEliece::classicMcEliece6688128f,
    &ClassicMcEliece::classicMcEliece6960119,
    &ClassicMcEliece::classicMcEliece6960119f,
    &ClassicMcEliece::classicMcEliece8192128,
    &ClassicMcEliece::classicMcEliece8192128f,
];

/// The facts of `params.h` of a set: the field bits `m`, the code length `n` and the error
/// weight `t`.
fn codeFacts(mechanism: &ClassicMcEliece) -> (u32, usize, usize) {
    let name = mechanism.description().name;
    match &name["Classic-McEliece-".len()..] {
        "348864" | "348864f" => (12, 3488, 64),
        "460896" | "460896f" => (13, 4608, 96),
        "6688128" | "6688128f" => (13, 6688, 128),
        "6960119" | "6960119f" => (13, 6960, 119),
        _ => (13, 8192, 128),
    }
}

/// The bytes of the control bits of the Benes network, `COND_BYTES`.
fn controlBitsLength(fieldBits: u32) -> usize {
    (2 * fieldBits as usize - 1) << (fieldBits - 4)
}

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

/// A key pair of each set, made once for the tests of this file.
fn sharedKeyPair(index: usize) -> &'static KeyPair {
    static keyPairs: [OnceLock<KeyPair>; 10] = [const { OnceLock::new() }; 10];
    keyPairs[index].get_or_init(|| {
        parameterSets[index]
            .generateKeyPair(&mut random(40 + index as u8))
            .expect("key pair")
    })
}

/// `SHAKE256(prefix || vector || ciphertext)`, 32 bytes: the shared secret of `operations.c`
/// for the byte 1 and an error vector, or for the byte 0 and the value `s` of the secret key.
fn sharedSecret(prefix: u8, vector: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut sponge = SHAKE256::new();
    sponge.absorb(&[prefix]);
    sponge.absorb(vector);
    sponge.absorb(ciphertext);
    let mut secret = vec![0u8; 32];
    sponge.finalize().squeeze(&mut secret);
    secret
}

/// A random source that records the length of each request, and gives seeded SplitMix64 bytes.
/// Bytes that repeat, such as a counter, can make every attempt of the error vector fail.
struct RecordingRandom {
    requests: Vec<usize>,
    bytes: FuzzRandom,
}

impl Default for RecordingRandom {
    fn default() -> Self {
        RecordingRandom {
            requests: Vec::new(),
            bytes: FuzzRandom::seeded(0x5245_4351),
        }
    }
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.requests.push(bytes.len());
        self.bytes.fillRandomBytes(bytes);
    }
}

/// A random source that gives one fixed byte for its first requests and then the bytes of a
/// recording source, and records the length of each request.
struct ScriptedRandom {
    fixedByte: u8,
    fixedRequests: usize,
    later: RecordingRandom,
    requests: Vec<usize>,
}

impl ScriptedRandom {
    fn new(fixedByte: u8, fixedRequests: usize) -> Self {
        ScriptedRandom {
            fixedByte,
            fixedRequests,
            later: RecordingRandom::default(),
            requests: Vec::new(),
        }
    }
}

impl RandomGenerating for ScriptedRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.requests.push(bytes.len());
        if self.requests.len() <= self.fixedRequests {
            bytes.fill(self.fixedByte);
        } else {
            self.later.fillRandomBytes(bytes);
        }
    }
}

/// GF(2^m) by the schoolbook method, written for the tests from the field polynomials of the
/// Classic McEliece specification, `x^12 + x^3 + 1` and `x^13 + x^4 + x^3 + x + 1`.
struct Field {
    bits: u32,
}

impl Field {
    fn product(&self, left: u16, right: u16) -> u16 {
        let polynomial: u32 = if self.bits == 12 { 0x1009 } else { 0x201B };
        let mut product = 0u32;
        for bit in 0..self.bits {
            if (right >> bit) & 1 == 1 {
                product ^= u32::from(left) << bit;
            }
        }
        for bit in (self.bits..2 * self.bits).rev() {
            if (product >> bit) & 1 == 1 {
                product ^= polynomial << (bit - self.bits);
            }
        }
        product as u16
    }

    fn power(&self, value: u16, exponent: u32) -> u16 {
        (0..32).rev().fold(1, |power, bit| {
            let square = self.product(power, power);
            if (exponent >> bit) & 1 == 1 {
                self.product(square, value)
            } else {
                square
            }
        })
    }

    /// The inverse, the power `2^m - 2`.
    fn inverse(&self, value: u16) -> u16 {
        self.power(value, (1 << self.bits) - 2)
    }

    /// The square root, the power `2^(m - 1)`.
    fn squareRoot(&self, value: u16) -> u16 {
        self.power(value, 1 << (self.bits - 1))
    }

    /// The field element of a place of the identity network: its `m` bits reversed.
    fn reversed(&self, value: usize) -> u16 {
        (0..self.bits).fold(0, |reversed, bit| {
            (reversed << 1) + ((value >> bit) & 1) as u16
        })
    }
}

/// A secret key whose decryption is known by hand: the Goppa polynomial `y^t + c`, control
/// bits of zero, which give the identity network and the support `L_i = bitrev(i)` with
/// `L_0 = 0`, and a value `s` of a counting pattern. The seed and the pivots are zero, because
/// the decapsulation does not read them.
fn identityNetworkKey(mechanism: &ClassicMcEliece, constantTerm: u16) -> Vec<u8> {
    let (bits, length, weight) = codeFacts(mechanism);
    let mut key = vec![0u8; 40];
    key.extend(constantTerm.to_le_bytes());
    key.resize(40 + 2 * weight + controlBitsLength(bits), 0);
    key.extend((0..length / 8).map(|index| (index * 37 + 11) as u8));
    assert_eq!(key.len(), mechanism.description().secretKeyLength);
    key
}

/// The value `s` at the end of a secret key.
fn rejectionValue(mechanism: &ClassicMcEliece, secretKey: &[u8]) -> Vec<u8> {
    let (_, length, _) = codeFacts(mechanism);
    secretKey[secretKey.len() - length / 8..].to_vec()
}

/// The bits of positions in a vector of bytes.
fn bitsAt(positions: &[usize], byteCount: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; byteCount];
    for position in positions {
        bytes[position / 8] |= 1 << (position % 8);
    }
    bytes
}

/// The places from 1 up whose support element is not a root of `y^t + c`, so that the double
/// syndrome sees them.
fn visiblePlaces(mechanism: &ClassicMcEliece, constantTerm: u16, count: usize) -> Vec<usize> {
    let (bits, _, weight) = codeFacts(mechanism);
    let field = Field { bits };
    let places: Vec<usize> = (1..)
        .filter(|place| field.power(field.reversed(*place), weight as u32) != constantTerm)
        .take(count)
        .collect();
    let rowCount = bits as usize * weight;
    assert!(places.iter().all(|place| *place < rowCount));
    places
}

/// The decapsulation of the ciphertext of the error positions with an identity network key, and
/// the shared secrets of acceptance and of rejection.
fn decapsulatedPositions(
    mechanism: &ClassicMcEliece,
    constantTerm: u16,
    positions: &[usize],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (_, length, _) = codeFacts(mechanism);
    let description = mechanism.description();
    let secretKey = identityNetworkKey(mechanism, constantTerm);
    let ciphertext = bitsAt(positions, description.ciphertextLength);
    let secret = mechanism
        .decapsulate(&ciphertext, &secretKey)
        .expect("decapsulation");
    let accepted = sharedSecret(1, &bitsAt(positions, length / 8), &ciphertext);
    let rejected = sharedSecret(0, &rejectionValue(mechanism, &secretKey), &ciphertext);
    (secret.bytes().to_vec(), accepted, rejected)
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
fn aCiphertextOfTErrorsIsAcceptedAndGivesTheSecretOfItsErrorVector() {
    // With t errors the locator has t roots, the weight is t and the double syndromes are
    // equal. An error at place 0, whose support element is 0, is found as well.
    for mechanism in parameterSets.iter().step_by(2) {
        let (_, _, weight) = codeFacts(mechanism);
        let name = mechanism.description().name;
        for positions in [(1..=weight).collect::<Vec<_>>(), (0..weight).collect()] {
            let (secret, accepted, rejected) = decapsulatedPositions(mechanism, 1, &positions);
            assert_ne!(accepted, rejected);
            assert_eq!(secret, accepted, "{name}");
        }
    }
}

#[test]
fn anErrorVectorOfWeightTMinusOneIsRejectedByTheWeightCheckAlone() {
    // t - 1 errors, one of them at place 0: the locator x sigma(x) has its extra root at 0,
    // which is already an error, so the decoded vector is the error vector, its double syndrome
    // is the double syndrome of the ciphertext, and only its weight differs from t.
    for mechanism in parameterSets.iter().step_by(2) {
        let (_, _, weight) = codeFacts(mechanism);
        let positions: Vec<usize> = (0..weight - 1).collect();
        let (secret, _, rejected) = decapsulatedPositions(mechanism, 1, &positions);
        assert_eq!(secret, rejected, "{}", mechanism.description().name);
    }
}

#[test]
fn anErrorVectorWhoseDoubleSyndromeDiffersIsRejectedByTheSyndromeCheckAlone() {
    // t - 1 errors away from place 0: the locator x sigma(x) adds the root 0, so the decoded
    // vector has weight t, and its double syndrome differs from the one of the ciphertext in
    // the value 0 only, by 1 / g(0)^2.
    for mechanism in parameterSets.iter().step_by(2) {
        let (_, _, weight) = codeFacts(mechanism);
        let positions: Vec<usize> = (1..weight).collect();
        let (secret, _, rejected) = decapsulatedPositions(mechanism, 1, &positions);
        assert_eq!(secret, rejected, "{}", mechanism.description().name);
    }
}

#[test]
fn aWeightAndASyndromeValueThatDifferInTheSameBitsAreRejected() {
    // t - 2 errors away from place 0: the decoded vector adds place 0 and has weight t - 1, and
    // its double syndrome differs in the value 0 by 1 / g(0)^2. The constant term c of the
    // Goppa polynomial makes 1 / c^2 equal to (t - 1) xor t, so the weight difference and the
    // syndrome difference have the same bits in the 16-bit unit of the check. A fold with an
    // exclusive or would cancel them and accept the ciphertext, and the or of the C code
    // rejects it.
    for mechanism in parameterSets.iter().step_by(2) {
        let (bits, _, weight) = codeFacts(mechanism);
        let field = Field { bits };
        let difference = ((weight - 1) ^ weight) as u16;
        let constantTerm = field.squareRoot(field.inverse(difference));
        assert_eq!(
            field.inverse(field.product(constantTerm, constantTerm)),
            difference
        );
        let positions = visiblePlaces(mechanism, constantTerm, weight - 2);
        let (secret, accepted, rejected) =
            decapsulatedPositions(mechanism, constantTerm, &positions);
        assert_ne!(secret, accepted);
        assert_eq!(secret, rejected, "{}", mechanism.description().name);
    }
}

#[test]
fn aChangedCiphertextGivesTheSecretOfS() {
    for (index, mechanism) in parameterSets.into_iter().enumerate() {
        let keyPair = sharedKeyPair(index);
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random(50))
            .expect("encapsulation");
        let secretKey = keyPair.secretKey.bytes();
        let last = encapsulation.ciphertext.len() - 1;
        // The first bit, a bit in the middle, and the last bit that is not padding.
        let lastBit = if mechanism.description().name.contains("6960119") {
            2
        } else {
            7
        };
        for (position, bit) in [(0, 0), (last / 2, 5), (last, lastBit)] {
            let mut changed = encapsulation.ciphertext.clone();
            changed[position] ^= 1 << bit;
            let secret = mechanism
                .decapsulate(&changed, secretKey)
                .expect("decapsulation");
            assert_eq!(
                secret.bytes(),
                sharedSecret(0, &rejectionValue(mechanism, secretKey), &changed),
                "{} byte {position} bit {bit}",
                mechanism.description().name
            );
        }
    }
}

#[test]
fn decapsulationReadsNeitherTheSeedNorThePivotsAndReadsSOnlyForARejection() {
    for (index, mechanism) in parameterSets.into_iter().enumerate() {
        let keyPair = sharedKeyPair(index);
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut random(51))
            .expect("encapsulation");
        let mut changed = keyPair.secretKey.bytes().to_vec();
        for byte in changed[..40].iter_mut() {
            *byte ^= 0xA5;
        }
        let length = changed.len();
        changed[length - 1] ^= 0x01;
        let secret = mechanism
            .decapsulate(&encapsulation.ciphertext, &changed)
            .expect("decapsulation");
        assert_eq!(secret.bytes(), encapsulation.sharedSecret.bytes());
        // A rejected ciphertext hashes the changed value s.
        let mut ciphertext = encapsulation.ciphertext.clone();
        ciphertext[1] ^= 0x10;
        let secret = mechanism
            .decapsulate(&ciphertext, &changed)
            .expect("decapsulation");
        assert_eq!(
            secret.bytes(),
            sharedSecret(0, &rejectionValue(mechanism, &changed), &ciphertext)
        );
    }
}

#[test]
fn theSecretKeyHoldsTheSeedThePivotsThePolynomialAndTheValueS() {
    // The secret key is the seed of the attempt that gave the key, the pivots, the Goppa
    // polynomial, the control bits and s, the first n / 8 bytes of SHAKE256(64 || seed).
    for (index, mechanism) in parameterSets.into_iter().enumerate() {
        let (bits, length, weight) = codeFacts(mechanism);
        let name = mechanism.description().name;
        let secretKey = sharedKeyPair(index).secretKey.bytes();
        let mut input = vec![64u8];
        input.extend_from_slice(&secretKey[..32]);
        let mut expanded = vec![0u8; length / 8];
        SHAKE256::hash(&input, &mut expanded);
        assert_eq!(
            &secretKey[secretKey.len() - length / 8..],
            expanded,
            "{name}"
        );
        let pivots = u64::from_le_bytes(secretKey[32..40].try_into().expect("8 bytes"));
        if name.ends_with('f') {
            assert_eq!(pivots.count_ones(), 32, "{name}");
        } else {
            assert_eq!(pivots, 0xFFFF_FFFF, "{name}");
        }
        for coefficient in secretKey[40..40 + 2 * weight].chunks_exact(2) {
            assert!(u16::from_le_bytes([coefficient[0], coefficient[1]]) >> bits == 0);
        }
    }
}

#[test]
fn aFailedAttemptOfTheKeyPairTakesTheNextSeedWithoutANewRequest() {
    // The seed of the next attempt is the last 32 bytes of SHAKE256(64 || seed) of the
    // attempt. In liboqs 0.16.0, a key pair of Classic-McEliece-348864 from the seed of 32
    // bytes 0x01 succeeds at the attempt 2, counted from 0, and from the bytes 0x03 at the
    // attempt 0.
    struct FixedSeed {
        byte: u8,
        requestCount: usize,
    }
    impl RandomGenerating for FixedSeed {
        fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
            self.requestCount += 1;
            bytes.fill(self.byte);
        }
    }
    let mechanism = &ClassicMcEliece::classicMcEliece348864;
    for (byte, attempt) in [(0x01u8, 2), (0x03, 0)] {
        let mut source = FixedSeed {
            byte,
            requestCount: 0,
        };
        let keyPair = mechanism.generateKeyPair(&mut source).expect("key pair");
        assert_eq!(source.requestCount, 1);
        let mut seed = [byte; 32];
        for _ in 0..attempt {
            let mut input = vec![64u8];
            input.extend_from_slice(&seed);
            let mut expanded = vec![0u8; 3488 / 8 + 4 * 4096 + 2 * 64 + 32];
            SHAKE256::hash(&input, &mut expanded);
            seed.copy_from_slice(&expanded[expanded.len() - 32..]);
        }
        assert_eq!(&keyPair.secretKey.bytes()[..32], &seed, "seed byte {byte}");
    }
}

#[test]
fn aKeyPairDrawsOneRequestOf32Bytes() {
    for mechanism in [
        &ClassicMcEliece::classicMcEliece348864,
        &ClassicMcEliece::classicMcEliece348864f,
    ] {
        let mut random = RecordingRandom::default();
        mechanism.generateKeyPair(&mut random).expect("key pair");
        assert_eq!(random.requests, [32]);
    }
}

#[test]
fn anEncapsulationDrawsOneRequestForEachAttemptOfTheErrorVector() {
    // `gen_e` draws 4 t bytes for each attempt, or 2 t bytes for the 8192128 sets, whose
    // values all lie below n.
    for mechanism in parameterSets {
        let (_, length, weight) = codeFacts(mechanism);
        let name = mechanism.description().name;
        let request = if length == 8192 {
            2 * weight
        } else {
            4 * weight
        };
        let publicKey = vec![0u8; mechanism.description().publicKeyLength];
        let mut random = RecordingRandom::default();
        let plain = mechanism
            .encapsulate(&publicKey, &mut random)
            .expect("encapsulation");
        let attempts = random.requests.len();
        assert!(attempts >= 1);
        assert_eq!(random.requests, vec![request; attempts], "{name}");
        // Zero bytes give t equal positions, and bytes of 0xFF give values of all ones, which
        // lie at or above n or repeat. Each such attempt draws a new request, and the
        // encapsulation goes on with the bytes of the plain run.
        for fixedByte in [0x00, 0xFF] {
            let mut scripted = ScriptedRandom::new(fixedByte, 2);
            let retried = mechanism
                .encapsulate(&publicKey, &mut scripted)
                .expect("encapsulation");
            assert_eq!(scripted.requests, vec![request; attempts + 2], "{name}");
            assert_eq!(retried.ciphertext, plain.ciphertext);
            assert_eq!(retried.sharedSecret.bytes(), plain.sharedSecret.bytes());
        }
    }
}

#[test]
fn aCiphertextWithAPaddingBitIsRefusedByThe6960119Sets() {
    // The ciphertext of 1547 bits ends in bit 2 of its last byte. `check_c_padding` refuses
    // the bits 3 to 7, and the other sets have no padding.
    for mechanism in parameterSets {
        let description = mechanism.description();
        let isPadded = description.name.contains("6960119");
        let secretKey = identityNetworkKey(mechanism, 1);
        let last = description.ciphertextLength - 1;
        let bits: &[u8] = if isPadded { &[2, 3, 4, 7] } else { &[7] };
        for bit in bits {
            let mut ciphertext = vec![0u8; description.ciphertextLength];
            ciphertext[last] = 1 << bit;
            let result = mechanism.decapsulate(&ciphertext, &secretKey).map(|_| ());
            if isPadded && *bit >= 3 {
                assert_eq!(result, Err(OQSError::operationFailed), "bit {bit}");
            } else {
                assert_eq!(result, Ok(()), "{} bit {bit}", description.name);
            }
        }
    }
}

#[test]
fn aPublicKeyWithAPaddingBitIsRefusedByThe6960119SetsAfterTheRandomRequest() {
    // Each row of the public key has 5413 bits and ends in bit 4 of its last byte.
    // `check_pk_padding` refuses the bits 5 to 7 of the last byte of any row, after `encrypt`
    // has drawn its random bytes. It gathers the last bytes of the rows with an or, so the same
    // padding bit in two rows is refused too, where an exclusive or would cancel the two bits.
    for mechanism in parameterSets {
        let description = mechanism.description();
        let (bits, _, weight) = codeFacts(mechanism);
        let lastRow = bits as usize * weight - 1;
        let rowLength = description.publicKeyLength / (lastRow + 1);
        let isPadded = description.name.contains("6960119");
        let cases = [
            (vec![0], 4),
            (vec![0], 5),
            (vec![7], 6),
            (vec![lastRow], 7),
            (vec![2, lastRow], 6),
        ];
        for (rows, bit) in cases {
            let mut publicKey = vec![0u8; description.publicKeyLength];
            for row in &rows {
                publicKey[row * rowLength + rowLength - 1] = 1 << bit;
            }
            let mut random = RecordingRandom::default();
            let result = mechanism.encapsulate(&publicKey, &mut random).map(|_| ());
            assert!(!random.requests.is_empty());
            if isPadded && bit >= 5 {
                assert_eq!(
                    result,
                    Err(OQSError::operationFailed),
                    "rows {rows:?} bit {bit}"
                );
            } else {
                assert_eq!(
                    result,
                    Ok(()),
                    "{} rows {rows:?} bit {bit}",
                    description.name
                );
            }
        }
    }
}

#[test]
fn eachInputOfAWrongLengthIsALengthError() {
    for mechanism in parameterSets {
        let description = mechanism.description();
        let lengthError =
            |expected: usize, actual: usize| Err(OQSError::invalidLength { expected, actual });
        let publicKey = vec![0u8; description.publicKeyLength];
        let secretKey = vec![0u8; description.secretKeyLength];
        let ciphertext = vec![0u8; description.ciphertextLength];
        let mut random = RecordingRandom::default();
        assert_eq!(
            mechanism
                .encapsulate(&publicKey[1..], &mut random)
                .map(|_| ()),
            lengthError(description.publicKeyLength, description.publicKeyLength - 1)
        );
        let mut longKey = publicKey.clone();
        longKey.push(0);
        assert_eq!(
            mechanism.encapsulate(&longKey, &mut random).map(|_| ()),
            lengthError(description.publicKeyLength, description.publicKeyLength + 1)
        );
        // A public key of a wrong length draws no random bytes.
        assert!(random.requests.is_empty());
        let mut longCiphertext = ciphertext.clone();
        longCiphertext.push(0);
        assert_eq!(
            mechanism
                .decapsulate(&longCiphertext, &secretKey)
                .map(|_| ()),
            lengthError(
                description.ciphertextLength,
                description.ciphertextLength + 1
            )
        );
        assert_eq!(
            mechanism
                .decapsulate(&ciphertext, &secretKey[2..])
                .map(|_| ()),
            lengthError(description.secretKeyLength, description.secretKeyLength - 2)
        );
        // The ciphertext is checked before the secret key.
        assert_eq!(
            mechanism.decapsulate(&ciphertext[1..], &[]).map(|_| ()),
            lengthError(
                description.ciphertextLength,
                description.ciphertextLength - 1
            )
        );
    }
}

#[test]
fn classicMcElieceHasNoSeededForms() {
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
            mechanism.generateKeyPairFromSeed(&[0u8; 32]).map(|_| ()),
            Err(OQSError::seedNotSupported)
        );
        let publicKey = vec![0u8; description.publicKeyLength];
        assert_eq!(
            mechanism
                .encapsulateWithSeed(&publicKey, &[0u8; 32])
                .map(|_| ()),
            Err(OQSError::seedNotSupported)
        );
    }
}
