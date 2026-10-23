//! The correctness test of liboqs `tests/test_kem.c`, and the rejection paths of NTRU, for each
//! parameter set.
//!
//! NTRU decapsulation does not encrypt again. `owcpa_dec` checks the unused bits of the last
//! ciphertext byte, the blinding polynomial `r` and, for NTRU-HPS, the type of the message `m`,
//! and joins the three results with an or. `crypto_kem_dec` then selects
//! `SHA3-256(rejection key || c)` for a failed check, and else `SHA3-256(r || m)` of the packed
//! polynomials. The tests build ciphertexts that fail one check, two checks or none, from the
//! public key and the random bytes of an encapsulation, with arithmetic written here from the
//! definitions: `c + delta x^j h` changes `r` by `delta x^j`, and `c + x^j - x^k` changes `m`
//! by `x^j - x^k`.

use OQSNativeAlgorithmTests::KEMCorrectnessTest;
use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;
use OQSNativeNTRU::NTRU;
use OQSNativeSHA3::SHA3256;

/// Every set, in liboqs order.
const everySet: [&NTRU; 6] = [
    &NTRU::ntruHPS2048509,
    &NTRU::ntruHPS2048677,
    &NTRU::ntruHPS4096821,
    &NTRU::ntruHPS40961229,
    &NTRU::ntruHRSS701,
    &NTRU::ntruHRSS1373,
];

fn random(seed: u8) -> NISTKATRandom {
    NISTKATRandom::new(&[seed; 48], None)
}

/// A random source that gives the bytes of the NIST DRBG and records each request.
struct RecordingRandom {
    source: NISTKATRandom,
    requests: Vec<Vec<u8>>,
}

impl RecordingRandom {
    fn new(seed: u8) -> Self {
        RecordingRandom {
            source: random(seed),
            requests: Vec::new(),
        }
    }

    fn requestLengths(&self) -> Vec<usize> {
        self.requests.iter().map(Vec::len).collect()
    }
}

impl RandomGenerating for RecordingRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.source.fillRandomBytes(bytes);
        self.requests.push(bytes.to_vec());
    }
}

/// The facts of `params.h` of a set that the tests need.
struct SetFacts {
    /// The number `n` of coefficients.
    count: usize,
    /// The bits of the modulus `q`.
    modulusBits: usize,
    /// True for NTRU-HPS, false for NTRU-HRSS.
    isHPS: bool,
}

impl SetFacts {
    fn of(mechanism: &NTRU) -> SetFacts {
        let (count, modulusBits, isHPS) = match mechanism.description().name {
            "NTRU-HPS-2048-509" => (509, 11, true),
            "NTRU-HPS-2048-677" => (677, 11, true),
            "NTRU-HPS-4096-821" => (821, 12, true),
            "NTRU-HPS-4096-1229" => (1229, 12, true),
            "NTRU-HRSS-701" => (701, 13, false),
            _ => (1373, 14, false),
        };
        SetFacts {
            count,
            modulusBits,
            isHPS,
        }
    }

    fn modulus(&self) -> i64 {
        1 << self.modulusBits
    }

    /// The bytes of a packed polynomial modulo 3, `ceil((n - 1) / 5)`.
    fn ternaryLength(&self) -> usize {
        (self.count - 1).div_ceil(5)
    }

    /// The bytes of a packed polynomial modulo `q`, `ceil(logq (n - 1) / 8)`.
    fn packedLength(&self) -> usize {
        (self.modulusBits * (self.count - 1)).div_ceil(8)
    }

    /// True when the last byte of a ciphertext has bits past the last coefficient.
    fn hasUnusedBits(&self) -> bool {
        !(self.modulusBits * (self.count - 1)).is_multiple_of(8)
    }

    /// The coefficients of a packing modulo `q`: `logq` bits each, low bit first, for the
    /// coefficients below `n - 1`. The last coefficient is minus the sum of the others for a
    /// sum-zero packing, and 0 else.
    fn unpacked(&self, bytes: &[u8], isSumZero: bool) -> Vec<i64> {
        let mut values = vec![0i64; self.count];
        for (index, value) in values[..self.count - 1].iter_mut().enumerate() {
            for bit in 0..self.modulusBits {
                let position = index * self.modulusBits + bit;
                *value |= i64::from((bytes[position / 8] >> (position % 8)) & 1) << bit;
            }
        }
        if isSumZero {
            let sum: i64 = values.iter().sum();
            values[self.count - 1] = (-sum).rem_euclid(self.modulus());
        }
        values
    }

    /// The packing modulo `q` of the coefficients below `n - 1`.
    fn packed(&self, values: &[i64]) -> Vec<u8> {
        let mut bytes = vec![0u8; self.packedLength()];
        for (index, value) in values[..self.count - 1].iter().enumerate() {
            let value = value.rem_euclid(self.modulus());
            for bit in 0..self.modulusBits {
                let position = index * self.modulusBits + bit;
                bytes[position / 8] |= (((value >> bit) & 1) as u8) << (position % 8);
            }
        }
        bytes
    }

    /// The packing of a polynomial modulo 3, five coefficients below `n - 1` in each byte as
    /// the digits in base 3, the first coefficient in the lowest digit.
    fn ternaryPacked(&self, polynomial: &[u8]) -> Vec<u8> {
        polynomial[..self.count - 1]
            .chunks(5)
            .map(|group| {
                group
                    .iter()
                    .rev()
                    .fold(0u8, |value, coefficient| 3 * value + coefficient)
            })
            .collect()
    }

    /// The polynomial modulo 3 of `n - 1` bytes, each byte modulo 3, `sample_iid`.
    fn independentPolynomial(&self, bytes: &[u8]) -> Vec<u8> {
        let mut polynomial: Vec<u8> = bytes[..self.count - 1]
            .iter()
            .map(|byte| byte % 3)
            .collect();
        polynomial.push(0);
        polynomial
    }

    /// The fixed type of NTRU-HPS: the 30-bit fields of the bytes, low bit first, each with a
    /// mark of 1 for the first `q / 16 - 1` and of 2 for the next `q / 16 - 1`, sorted as signed
    /// 32-bit words. The marks in sorted order are the coefficients.
    fn fixedTypePolynomial(&self, bytes: &[u8]) -> Vec<u8> {
        let half = (self.modulus() / 16 - 1) as usize;
        let mut keys: Vec<i32> = (0..self.count - 1)
            .map(|index| {
                let mut field = 0u32;
                for bit in 0..30 {
                    let position = 30 * index + bit;
                    field |= u32::from((bytes[position / 8] >> (position % 8)) & 1) << bit;
                }
                let mark = if index < half {
                    1
                } else if index < 2 * half {
                    2
                } else {
                    0
                };
                ((field << 2) | mark) as i32
            })
            .collect();
        keys.sort_unstable();
        let mut polynomial: Vec<u8> = keys.iter().map(|key| (key & 3) as u8).collect();
        polynomial.push(0);
        polynomial
    }

    /// The independent polynomial with the even coefficients negated when `<x r, r> < 0`,
    /// `sample_iid_plus`.
    fn correlatedPolynomial(&self, bytes: &[u8]) -> Vec<u8> {
        let polynomial = self.independentPolynomial(bytes);
        let signed: Vec<i64> = polynomial
            .iter()
            .map(|value| signedTernary(*value))
            .collect();
        let correlation: i64 = signed.windows(2).map(|pair| pair[0] * pair[1]).sum();
        signed
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let value = if correlation < 0 && index % 2 == 0 {
                    -value
                } else {
                    *value
                };
                value.rem_euclid(3) as u8
            })
            .collect()
    }

    /// The blinding polynomial `r` and the message `m` of the random bytes of an
    /// encapsulation, `sample_rm`.
    fn blindingAndMessage(&self, request: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (first, second) = request.split_at(self.count - 1);
        let message = if self.isHPS {
            self.fixedTypePolynomial(second)
        } else {
            self.independentPolynomial(second)
        };
        (self.independentPolynomial(first), message)
    }

    /// The shared secret of a valid ciphertext: the SHA3-256 of the packed `r` and `m`.
    fn messageSecret(&self, blinding: &[u8], message: &[u8]) -> Vec<u8> {
        let mut hash = SHA3256::new();
        hash.absorb(&self.ternaryPacked(blinding));
        hash.absorb(&self.ternaryPacked(message));
        hash.finalize().to_vec()
    }

    /// The product of two polynomials modulo `x^n - 1`, with integer coefficients.
    fn cyclicProduct(&self, left: &[i64], right: &[i64]) -> Vec<i64> {
        let mut product = vec![0i64; self.count];
        for (leftIndex, leftValue) in left.iter().enumerate() {
            if *leftValue == 0 {
                continue;
            }
            for (rightIndex, rightValue) in right.iter().enumerate() {
                product[(leftIndex + rightIndex) % self.count] += leftValue * rightValue;
            }
        }
        product
    }

    /// A polynomial modulo `Phi_n` and a modulus, with the last coefficient 0.
    fn reducedModuloPhi(&self, polynomial: &[i64], modulus: i64) -> Vec<i64> {
        let last = polynomial[self.count - 1];
        polynomial
            .iter()
            .map(|value| (value - last).rem_euclid(modulus))
            .collect()
    }
}

/// The coefficients 0, 1 and 2 as 0, 1 and -1.
fn signedTernary(value: u8) -> i64 {
    match value {
        1 => 1,
        2 => -1,
        _ => 0,
    }
}

/// The implicit-rejection secret of `crypto_kem_dec`: the SHA3-256 of the rejection key, the
/// last 32 bytes of the secret key, and the ciphertext.
fn rejectionSecret(secretKey: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut hash = SHA3256::new();
    hash.absorb(&secretKey[secretKey.len() - 32..]);
    hash.absorb(ciphertext);
    hash.finalize().to_vec()
}

/// A key pair, an encapsulation and the facts of the random bytes of the encapsulation.
struct Exchange {
    publicKey: Vec<u8>,
    secretKey: Vec<u8>,
    ciphertext: Vec<u8>,
    sharedSecret: Vec<u8>,
    blinding: Vec<u8>,
    message: Vec<u8>,
}

fn exchange(mechanism: &NTRU, seed: u8) -> Exchange {
    exchangeWithKeyRandom(mechanism, &mut random(seed), seed.wrapping_add(100))
}

/// A key pair of a random source and an encapsulation of the seed of `RecordingRandom`.
fn exchangeWithKeyRandom(
    mechanism: &NTRU,
    keyRandom: &mut dyn RandomGenerating,
    encapsulationSeed: u8,
) -> Exchange {
    let facts = SetFacts::of(mechanism);
    let keyPair = mechanism.generateKeyPair(keyRandom).expect("key pair");
    let mut recording = RecordingRandom::new(encapsulationSeed);
    let encapsulation = mechanism
        .encapsulate(&keyPair.publicKey, &mut recording)
        .expect("encapsulation");
    let (blinding, message) = facts.blindingAndMessage(&recording.requests[0]);
    Exchange {
        publicKey: keyPair.publicKey,
        secretKey: keyPair.secretKey.bytes().to_vec(),
        ciphertext: encapsulation.ciphertext,
        sharedSecret: encapsulation.sharedSecret.bytes().to_vec(),
        blinding,
        message,
    }
}

impl Exchange {
    /// The ciphertext `c + delta x^j h` modulo `q`, whose blinding polynomial is
    /// `r + delta x^j` and whose message is `m`.
    fn withBlindingChange(&self, facts: &SetFacts, changes: &[(usize, i64)]) -> Vec<u8> {
        let mut c = facts.unpacked(&self.ciphertext, true);
        let h = facts.unpacked(&self.publicKey, true);
        let count = facts.count;
        for (place, delta) in changes {
            for (index, coefficient) in c.iter_mut().enumerate() {
                *coefficient += delta * h[(index + count - place) % count];
            }
        }
        facts.packed(&c)
    }

    /// The ciphertext `c + x^j - x^k` of NTRU-HPS, whose message is `m + x^j - x^k` when
    /// `m[j]` is 0 or 2 and `m[k]` is 0 or 1, and whose blinding polynomial is `r`.
    fn withMessageChange(&self, facts: &SetFacts, raised: usize, lowered: usize) -> Vec<u8> {
        let mut c = facts.unpacked(&self.ciphertext, true);
        c[raised] += 1;
        c[lowered] -= 1;
        facts.packed(&c)
    }

    /// The ciphertext `c + d + k Phi_n` of NTRU-HPS, with `k n + d(1) = 0` modulo `q`, so that
    /// its sum stays 0. When `f(1) = 0`, its message is `m + d` and its blinding polynomial is
    /// `r`: `f Phi_n` is `f(1) Phi_n`, and `r h + k Phi_n` is `r h` modulo `Phi_n`.
    fn withUnbalancedMessageChange(&self, facts: &SetFacts, changes: &[(usize, i64)]) -> Vec<u8> {
        let q = facts.modulus();
        let count = facts.count as i64;
        let inverseOfN = (1..q)
            .find(|value| (value * count).rem_euclid(q) == 1)
            .expect("n is odd");
        let sum: i64 = changes.iter().map(|(_, delta)| delta).sum();
        let multiple = (-sum * inverseOfN).rem_euclid(q);
        let mut c = facts.unpacked(&self.ciphertext, true);
        for coefficient in &mut c {
            *coefficient += multiple;
        }
        for (place, delta) in changes {
            c[*place] += delta;
        }
        facts.packed(&c)
    }

    /// The places below `n - 1` where a polynomial has a coefficient.
    fn placesOf(polynomial: &[u8], value: u8) -> Vec<usize> {
        (0..polynomial.len() - 1)
            .filter(|place| polynomial[*place] == value)
            .collect()
    }
}

fn decapsulated(mechanism: &NTRU, ciphertext: &[u8], secretKey: &[u8]) -> Vec<u8> {
    mechanism
        .decapsulate(ciphertext, secretKey)
        .expect("no error")
        .bytes()
        .to_vec()
}

#[test]
fn testKEMPassesForEveryParameterSet() {
    for (index, mechanism) in everySet.into_iter().enumerate() {
        assert_eq!(
            KEMCorrectnessTest::run(mechanism, &mut random(index as u8)),
            Ok(()),
            "seed {index}"
        );
    }
}

#[test]
fn encapsulationAndDecapsulationAgreeOnTheSharedSecret() {
    for mechanism in everySet {
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
            assert_eq!(encapsulation.sharedSecret.bytes().len(), 32);
            assert_eq!(
                decapsulated(
                    mechanism,
                    &encapsulation.ciphertext,
                    keyPair.secretKey.bytes()
                ),
                encapsulation.sharedSecret.bytes(),
                "{}, seed {seed}",
                description.name
            );
        }
    }
}

#[test]
fn eachOperationDrawsTheRequestsOfTheCCode() {
    // `crypto_kem_keypair` draws the bytes of f and g and then the 32-byte key of the
    // rejection, and `crypto_kem_enc` draws the bytes of r and m in one request.
    let sampleLengths = [2413, 3211, 3895, 5833, 1400, 2744];
    for (mechanism, sampleLength) in everySet.into_iter().zip(sampleLengths) {
        let name = mechanism.description().name;
        let mut keyRandom = RecordingRandom::new(1);
        let keyPair = mechanism.generateKeyPair(&mut keyRandom).expect("key pair");
        assert_eq!(
            keyRandom.requestLengths(),
            vec![sampleLength, 32],
            "{name}, seed 1"
        );
        // The rejection key ends the secret key.
        let secretKey = keyPair.secretKey.bytes();
        assert_eq!(
            &secretKey[secretKey.len() - 32..],
            keyRandom.requests[1].as_slice(),
            "{name}"
        );
        let mut encapsulationRandom = RecordingRandom::new(2);
        mechanism
            .encapsulate(&keyPair.publicKey, &mut encapsulationRandom)
            .expect("encapsulation");
        assert_eq!(
            encapsulationRandom.requestLengths(),
            vec![sampleLength],
            "{name}, seed 2"
        );
        // A public key of a wrong length draws no random bytes.
        let mut unused = RecordingRandom::new(3);
        assert!(
            mechanism
                .encapsulate(&keyPair.publicKey[1..], &mut unused)
                .is_err()
        );
        assert!(unused.requests.is_empty(), "{name}");
    }
}

#[test]
fn theKeysHoldHAndTheInversesOfFAndH() {
    // h = 3 g / f modulo q and Phi_n, with g of NTRU-HRSS times x - 1. The secret key holds
    // f, f^-1 modulo 3 and h^-1 modulo q.
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        let name = mechanism.description().name;
        let mut recording = RecordingRandom::new(4);
        let keyPair = mechanism.generateKeyPair(&mut recording).expect("key pair");
        let request = &recording.requests[0];
        let (first, second) = request.split_at(facts.count - 1);
        let (f, g) = if facts.isHPS {
            (
                facts.independentPolynomial(first),
                facts.fixedTypePolynomial(second),
            )
        } else {
            (
                facts.correlatedPolynomial(first),
                facts.correlatedPolynomial(second),
            )
        };
        let secretKey = keyPair.secretKey.bytes();
        let length = facts.ternaryLength();
        assert_eq!(
            &secretKey[..length],
            facts.ternaryPacked(&f).as_slice(),
            "{name}"
        );
        let f: Vec<i64> = f.iter().map(|value| signedTernary(*value)).collect();
        let mut g: Vec<i64> = g.iter().map(|value| signedTernary(*value)).collect();
        if !facts.isHPS {
            let shifted = facts.cyclicProduct(&g, &{
                let mut xMinusOne = vec![0i64; facts.count];
                xMinusOne[0] = -1;
                xMinusOne[1] = 1;
                xMinusOne
            });
            g = shifted;
        }
        // f^-1 f = 1 modulo 3 and Phi_n.
        let inverseOfF: Vec<i64> = (0..facts.count)
            .map(|index| {
                if index == facts.count - 1 {
                    return 0;
                }
                let byte = secretKey[length + index / 5];
                i64::from(byte / 3u8.pow((index % 5) as u32) % 3)
            })
            .collect();
        let one = facts.reducedModuloPhi(&facts.cyclicProduct(&f, &inverseOfF), 3);
        assert_eq!(one[0], 1, "{name}");
        assert!(one[1..].iter().all(|value| *value == 0), "{name}");
        // h f = 3 g modulo q and Phi_n.
        let q = facts.modulus();
        let h = facts.unpacked(&keyPair.publicKey, true);
        let hf = facts.reducedModuloPhi(&facts.cyclicProduct(&h, &f), q);
        let threeG: Vec<i64> = g.iter().map(|value| 3 * value).collect();
        assert_eq!(hf, facts.reducedModuloPhi(&threeG, q), "{name}");
        // h^-1 h = 1 modulo q and Phi_n.
        let inverseOfH = facts.unpacked(&secretKey[2 * length..], false);
        let one = facts.reducedModuloPhi(&facts.cyclicProduct(&h, &inverseOfH), q);
        assert_eq!(one[0], 1, "{name}");
        assert!(one[1..].iter().all(|value| *value == 0), "{name}");
    }
}

#[test]
fn theSharedSecretIsTheHashOfThePackedBlindingAndMessage() {
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        let exchange = exchange(mechanism, 5);
        let name = mechanism.description().name;
        assert_eq!(
            exchange.sharedSecret,
            facts.messageSecret(&exchange.blinding, &exchange.message),
            "{name}, seed 105"
        );
        // The ciphertext is r h + Lift(m), so c - r h is the lift of m: small, and m modulo 3
        // and Phi_n.
        let q = facts.modulus();
        let c = facts.unpacked(&exchange.ciphertext, true);
        let h = facts.unpacked(&exchange.publicKey, true);
        let r: Vec<i64> = exchange
            .blinding
            .iter()
            .map(|value| signedTernary(*value))
            .collect();
        let rh = facts.cyclicProduct(&r, &h);
        let lift: Vec<i64> = c
            .iter()
            .zip(&rh)
            .map(|(c, rh)| {
                let value = (c - rh).rem_euclid(q);
                if value > q / 2 { value - q } else { value }
            })
            .collect();
        assert!(lift.iter().all(|value| value.abs() <= 2), "{name}");
        let message: Vec<i64> = exchange
            .message
            .iter()
            .map(|value| i64::from(*value))
            .collect();
        assert_eq!(
            facts.reducedModuloPhi(&lift, 3),
            facts.reducedModuloPhi(&message, 3),
            "{name}"
        );
        if facts.isHPS {
            let half = (q / 16 - 1) as usize;
            assert_eq!(Exchange::placesOf(&exchange.message, 1).len(), half);
            assert_eq!(Exchange::placesOf(&exchange.message, 2).len(), half);
        }
    }
}

#[test]
fn aChangedCiphertextGivesTheRejectionSecret() {
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        let exchange = exchange(mechanism, 6);
        let name = mechanism.description().name;
        let length = exchange.ciphertext.len();
        // The first bit, a middle byte, and the highest bit of the last coefficient.
        let lastBit = facts.modulusBits * (facts.count - 1) - 1;
        for (position, bit) in [(0, 0), (length / 2, 3), (lastBit / 8, lastBit % 8)] {
            let mut changed = exchange.ciphertext.clone();
            changed[position] ^= 1 << bit;
            let secret = decapsulated(mechanism, &changed, &exchange.secretKey);
            assert_eq!(
                secret,
                rejectionSecret(&exchange.secretKey, &changed),
                "{name}, byte {position}, bit {bit}"
            );
            assert_ne!(secret, exchange.sharedSecret, "{name}, byte {position}");
        }
        // The unchanged ciphertext gives the shared secret, not the rejection secret.
        let secret = decapsulated(mechanism, &exchange.ciphertext, &exchange.secretKey);
        assert_eq!(secret, exchange.sharedSecret, "{name}");
        assert_ne!(
            secret,
            rejectionSecret(&exchange.secretKey, &exchange.ciphertext),
            "{name}"
        );
    }
}

#[test]
fn theUnusedBitsOfTheLastCiphertextByteAreChecked() {
    // 508 * 11, 676 * 11 and 700 * 13 bits leave four bits of the last byte unused. A set bit
    // there does not change the coefficients, so only the ciphertext check fails.
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        let exchange = exchange(mechanism, 7);
        let name = mechanism.description().name;
        if !facts.hasUnusedBits() {
            assert_eq!(
                8 * exchange.ciphertext.len(),
                facts.modulusBits * (facts.count - 1),
                "{name}"
            );
            continue;
        }
        let last = exchange.ciphertext.len() - 1;
        for bit in [4, 7] {
            let mut changed = exchange.ciphertext.clone();
            changed[last] ^= 1 << bit;
            assert_eq!(
                facts.unpacked(&changed, true),
                facts.unpacked(&exchange.ciphertext, true)
            );
            assert_eq!(
                decapsulated(mechanism, &changed, &exchange.secretKey),
                rejectionSecret(&exchange.secretKey, &changed),
                "{name}, bit {bit}"
            );
        }
    }
}

#[test]
fn aBlindingPolynomialOutsideTheTernaryValuesIsRejected() {
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        let exchange = exchange(mechanism, 8);
        let name = mechanism.description().name;
        let ones = Exchange::placesOf(&exchange.blinding, 1);
        let zeros = Exchange::placesOf(&exchange.blinding, 0);
        let minusOnes = Exchange::placesOf(&exchange.blinding, 2);
        // `owcpa_check_r` gathers two tests of each coefficient with an or. A coefficient 2
        // fails only the test of the bit 2 of `r + 2`, -2 only the test of the bits from 2 up
        // to logq - 1 of `r + 1`, and 3 fails both. Two equal failures must not cancel.
        for (label, changes) in [
            ("a coefficient 2", vec![(ones[0], 1)]),
            ("a coefficient 3", vec![(ones[1], 2)]),
            ("a coefficient -2", vec![(minusOnes[0], -1)]),
            ("two coefficients 2", vec![(ones[2], 1), (ones[3], 1)]),
            ("two coefficients 3", vec![(ones[4], 2), (ones[5], 2)]),
            (
                "two coefficients -2",
                vec![(minusOnes[2], -1), (minusOnes[3], -1)],
            ),
        ] {
            let changed = exchange.withBlindingChange(&facts, &changes);
            assert_eq!(
                decapsulated(mechanism, &changed, &exchange.secretKey),
                rejectionSecret(&exchange.secretKey, &changed),
                "{name}, {label}"
            );
        }
        // 0 to 1 and -1 to 0 keep r in the message space, so the decapsulation accepts the
        // changed r with the same m.
        for (place, delta, newValue) in [(zeros[0], 1, 1u8), (minusOnes[1], 1, 0u8)] {
            let changed = exchange.withBlindingChange(&facts, &[(place, delta)]);
            let mut blinding = exchange.blinding.clone();
            blinding[place] = newValue;
            assert_eq!(
                decapsulated(mechanism, &changed, &exchange.secretKey),
                facts.messageSecret(&blinding, &exchange.message),
                "{name}, coefficient {place}"
            );
        }
    }
}

#[test]
fn aMessageOfTheWrongTypeIsRejectedByNTRUHPS() {
    // The lift of NTRU-HPS is the message itself, so `c + x^j - x^k` lifts `m + x^j - x^k`.
    // NTRU-HRSS has no check of `m`: see the zero key in
    // `anyKeyOfTheRightLengthGivesAResultAsTheCCodeGivesIt`.
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        if !facts.isHPS {
            continue;
        }
        let exchange = exchange(mechanism, 9);
        let name = mechanism.description().name;
        let zeros = Exchange::placesOf(&exchange.message, 0);
        let ones = Exchange::placesOf(&exchange.message, 1);
        let minusOnes = Exchange::placesOf(&exchange.message, 2);
        // m[j] = 0 to 1 with m[k] = 0 to -1 adds a 1 and a -1: the weight grows by 2.
        let changed = exchange.withMessageChange(&facts, zeros[0], zeros[1]);
        assert_eq!(
            decapsulated(mechanism, &changed, &exchange.secretKey),
            rejectionSecret(&exchange.secretKey, &changed),
            "{name}, a heavier message"
        );
        // m[j] = -1 to 0 with m[k] = 1 to 0 removes a 1 and a -1.
        let changed = exchange.withMessageChange(&facts, minusOnes[0], ones[0]);
        assert_eq!(
            decapsulated(mechanism, &changed, &exchange.secretKey),
            rejectionSecret(&exchange.secretKey, &changed),
            "{name}, a lighter message"
        );
        // m[j] = 0 to 1 with m[k] = 1 to 0 moves a 1, which keeps the type.
        let changed = exchange.withMessageChange(&facts, zeros[2], ones[1]);
        let mut message = exchange.message.clone();
        message[zeros[2]] = 1;
        message[ones[1]] = 0;
        assert_eq!(
            decapsulated(mechanism, &changed, &exchange.secretKey),
            facts.messageSecret(&exchange.blinding, &message),
            "{name}, a moved coefficient"
        );
    }
}

/// The entropy of the first key pair whose `f` sums to 0: a counter in the first two bytes.
/// About one `f` in 50 has `f(1) = 0`.
fn zeroSumEntropy(facts: &SetFacts) -> [u8; 48] {
    (0u16..)
        .map(|counter| {
            let mut entropy = [0x5A; 48];
            entropy[..2].copy_from_slice(&counter.to_le_bytes());
            entropy
        })
        .find(|entropy| {
            // The bytes of f are the first n - 1 bytes of the request of a key pair.
            let mut bytes = vec![0u8; facts.count - 1];
            NISTKATRandom::new(entropy, None).fillRandomBytes(&mut bytes);
            let sum: i64 = facts
                .independentPolynomial(&bytes)
                .iter()
                .map(|value| signedTernary(*value))
                .sum();
            sum == 0
        })
        .expect("a key pair with f(1) = 0")
}

#[test]
fn anUnbalancedMessageIsRejectedByNTRUHPS() {
    // `owcpa_check_m` tests that m has as many coefficients 1 as -1, and that it has
    // q / 16 - 1 coefficients -1, and joins the two tests with an or. A message change of a
    // sum-zero ciphertext keeps the balance, so these ciphertexts add `k Phi_n` to a key with
    // f(1) = 0. One more 1 breaks only the balance. Three 1s and one -1 fewer break both, and
    // the two tests differ from their targets by the same value: 124 ^ 126 = 252 ^ 254 = 2 for
    // q = 2048, and 252 ^ 254 = 508 ^ 510 = 2 for q = 4096. An exclusive or would cancel them.
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        if !facts.isHPS {
            continue;
        }
        let name = mechanism.description().name;
        let mut keyRandom = NISTKATRandom::new(&zeroSumEntropy(&facts), None);
        let exchange = exchangeWithKeyRandom(mechanism, &mut keyRandom, 120);
        let zeros = Exchange::placesOf(&exchange.message, 0);
        let ones = Exchange::placesOf(&exchange.message, 1);
        let minusOnes = Exchange::placesOf(&exchange.message, 2);
        for (label, changes) in [
            ("one more 1", vec![(zeros[0], 1)]),
            (
                "three 1s and one -1 fewer",
                vec![
                    (ones[0], -1),
                    (ones[1], -1),
                    (ones[2], -1),
                    (minusOnes[0], 1),
                ],
            ),
        ] {
            let changed = exchange.withUnbalancedMessageChange(&facts, &changes);
            assert_eq!(
                decapsulated(mechanism, &changed, &exchange.secretKey),
                rejectionSecret(&exchange.secretKey, &changed),
                "{name}, {label}"
            );
        }
    }
}

#[test]
fn twoFailedChecksStillReject() {
    // The checks join with an or. An exclusive or would accept a ciphertext that fails two.
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        let exchange = exchange(mechanism, 10);
        let name = mechanism.description().name;
        let ones = Exchange::placesOf(&exchange.blinding, 1);
        let blindingChange = exchange.withBlindingChange(&facts, &[(ones[0], 1)]);
        let mut cases = Vec::new();
        if facts.hasUnusedBits() {
            let mut changed = blindingChange.clone();
            let last = changed.len() - 1;
            changed[last] |= 0x80;
            cases.push(("the ciphertext and r", changed));
        }
        if facts.isHPS {
            let zeros = Exchange::placesOf(&exchange.message, 0);
            let mut c = facts.unpacked(&blindingChange, true);
            c[zeros[0]] += 1;
            c[zeros[1]] -= 1;
            cases.push(("m and r", facts.packed(&c)));
            if facts.hasUnusedBits() {
                let mut changed = exchange.withMessageChange(&facts, zeros[0], zeros[1]);
                let last = changed.len() - 1;
                changed[last] |= 0x80;
                cases.push(("the ciphertext and m", changed));
            }
        }
        assert!(!cases.is_empty() || name == "NTRU-HRSS-1373");
        for (label, changed) in cases {
            assert_eq!(
                decapsulated(mechanism, &changed, &exchange.secretKey),
                rejectionSecret(&exchange.secretKey, &changed),
                "{name}, {label}"
            );
        }
    }
}

#[test]
fn eachPartOfTheSecretKeyHasItsRoleInDecapsulation() {
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        let exchange = exchange(mechanism, 11);
        let name = mechanism.description().name;
        let changedAt = |position: usize| {
            let mut secretKey = exchange.secretKey.clone();
            secretKey[position] ^= 0x01;
            secretKey
        };
        // The rejection key changes only the rejection secret.
        let last = exchange.secretKey.len() - 1;
        let otherKey = changedAt(last);
        assert_eq!(
            decapsulated(mechanism, &exchange.ciphertext, &otherKey),
            exchange.sharedSecret,
            "{name}"
        );
        let mut changed = exchange.ciphertext.clone();
        changed[0] ^= 1;
        let rejected = decapsulated(mechanism, &changed, &otherKey);
        assert_eq!(rejected, rejectionSecret(&otherKey, &changed), "{name}");
        assert_ne!(
            rejected,
            rejectionSecret(&exchange.secretKey, &changed),
            "{name}"
        );
        // A changed f, f^-1 or h^-1 loses m or r, so a check fails.
        let length = facts.ternaryLength();
        for position in [0, length, 2 * length + 1] {
            let secretKey = changedAt(position);
            assert_eq!(
                decapsulated(mechanism, &exchange.ciphertext, &secretKey),
                rejectionSecret(&secretKey, &exchange.ciphertext),
                "{name}, byte {position}"
            );
        }
    }
}

#[test]
fn anyKeyOfTheRightLengthGivesAResultAsTheCCodeGivesIt() {
    for mechanism in everySet {
        let facts = SetFacts::of(mechanism);
        let description = mechanism.description();
        let name = description.name;
        // The zero secret key decrypts the zero ciphertext to r = 0 and m = 0. NTRU-HRSS takes
        // that pair, and NTRU-HPS refuses the weight of m.
        let secretKey = vec![0u8; description.secretKeyLength];
        let ciphertext = vec![0u8; description.ciphertextLength];
        let expected = if facts.isHPS {
            rejectionSecret(&secretKey, &ciphertext)
        } else {
            let zero = vec![0u8; facts.count];
            facts.messageSecret(&zero, &zero)
        };
        assert_eq!(
            decapsulated(mechanism, &ciphertext, &secretKey),
            expected,
            "{name}"
        );
        let encapsulation = mechanism
            .encapsulate(&vec![0xFFu8; description.publicKeyLength], &mut random(12))
            .expect("no key check");
        assert_eq!(
            encapsulation.ciphertext.len(),
            description.ciphertextLength,
            "{name}"
        );
    }
}

#[test]
fn eachInputOfAWrongLengthIsALengthError() {
    for mechanism in everySet {
        let description = mechanism.description();
        let name = description.name;
        let lengthError =
            |expected: usize, actual: usize| Err(OQSError::invalidLength { expected, actual });
        let publicKeyLength = description.publicKeyLength;
        let ciphertextLength = description.ciphertextLength;
        let secretKeyLength = description.secretKeyLength;
        for actual in [publicKeyLength - 1, publicKeyLength + 1, 0] {
            assert_eq!(
                mechanism
                    .encapsulate(&vec![0u8; actual], &mut random(13))
                    .map(|_| ()),
                lengthError(publicKeyLength, actual),
                "{name}"
            );
        }
        let secretKey = vec![0u8; secretKeyLength];
        for actual in [ciphertextLength - 1, ciphertextLength + 1, 0] {
            assert_eq!(
                mechanism
                    .decapsulate(&vec![0u8; actual], &secretKey)
                    .map(|_| ()),
                lengthError(ciphertextLength, actual),
                "{name}"
            );
        }
        let ciphertext = vec![0u8; ciphertextLength];
        for actual in [secretKeyLength - 2, secretKeyLength + 1] {
            assert_eq!(
                mechanism
                    .decapsulate(&ciphertext, &vec![0u8; actual])
                    .map(|_| ()),
                lengthError(secretKeyLength, actual),
                "{name}"
            );
        }
        // The ciphertext is checked first.
        assert_eq!(
            mechanism
                .decapsulate(&ciphertext[1..], &secretKey[1..])
                .map(|_| ()),
            lengthError(ciphertextLength, ciphertextLength - 1),
            "{name}"
        );
    }
}

#[test]
fn theSeededFormsAreNotSupportedAsInLiboqs() {
    for mechanism in everySet {
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
        assert_eq!(
            mechanism
                .encapsulateWithSeed(&vec![0u8; description.publicKeyLength], &[0u8; 32])
                .map(|_| ()),
            Err(OQSError::seedNotSupported)
        );
    }
}

#[test]
fn eachSetHasTheFactsOfItsCFile() {
    // `kem_ntru_<set>.c`: one version text, IND-CCA, and the level of the set.
    let version = "https://github.com/jschanck/ntru/tree/6d96ed37 reference implementation";
    let names = [
        "NTRU-HPS-2048-509",
        "NTRU-HPS-2048-677",
        "NTRU-HPS-4096-821",
        "NTRU-HPS-4096-1229",
        "NTRU-HRSS-701",
        "NTRU-HRSS-1373",
    ];
    let levels = [1, 3, 5, 5, 3, 5];
    for ((mechanism, name), level) in everySet.into_iter().zip(names).zip(levels) {
        let description = mechanism.description();
        assert_eq!(description.name, name);
        assert_eq!(description.algorithmVersion, version, "{name}");
        assert_eq!(description.claimedNISTLevel, level, "{name}");
        assert!(description.isINDCCASecure, "{name}");
        assert_eq!(description.sharedSecretLength, 32, "{name}");
    }
}
