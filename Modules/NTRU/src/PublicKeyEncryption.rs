use crate::{Packing, Parameters, PolynomialInversion, PolynomialRing, Sampler, Variant};
use alloc::vec::Vec;

/// The deterministic public-key encryption of NTRU, OW-CPA, `owcpa.c`.
///
/// The public key is `h = 3 g / f` modulo `q` and `Phi_n`, packed with the sum-zero form. The
/// secret key is `f` and `f^-1` modulo 3, and `h^-1` modulo `q`. A ciphertext is
/// `c = r h + Lift(m)`. Decryption recovers `m` from `c f` modulo 3 and `r` from
/// `(c - Lift(m)) h^-1`, and checks the ciphertext, `r` and, for NTRU-HPS, `m`. When every
/// check passes, `c` is the encryption of `(r, m)`, so the KEM needs no second encryption.
pub(crate) struct PublicKeyEncryption<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> PublicKeyEncryption<'parameters> {
    /// Makes the scheme of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        PublicKeyEncryption { parameters }
    }

    /// The public key and the secret key of the uniform bytes of a key pair, `owcpa_keypair`.
    pub(crate) fn keyPair(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let parameters = self.parameters;
        let ring = PolynomialRing::new(parameters);
        let packing = Packing::new(parameters);
        let (mut f, mut g) = Sampler::new(parameters).keyPolynomials(seed);
        let inverseOfF = PolynomialInversion::inverseModuloThree(&f);
        // The capacity of the whole secret key of the KEM, so that adding the rejection key
        // leaves no copy of the key in freed memory.
        let mut secretKey = Vec::with_capacity(parameters.description.secretKeyLength);
        secretKey.extend_from_slice(&packing.ternaryBytes(&f));
        secretKey.extend_from_slice(&packing.ternaryBytes(&inverseOfF));
        ring.liftTernaryCoefficients(&mut f);
        ring.liftTernaryCoefficients(&mut g);
        match parameters.variant {
            Variant::hps => {
                for coefficient in g.iter_mut() {
                    *coefficient = coefficient.wrapping_mul(3);
                }
            }
            Variant::hrss => {
                // g = 3 (x - 1) g, from the top coefficient down.
                for index in (1..g.len()).rev() {
                    g[index] = g[index - 1].wrapping_sub(g[index]).wrapping_mul(3);
                }
                g[0] = g[0].wrapping_mul(3).wrapping_neg();
            }
        }
        let product = ring.product(&g, &f);
        let inverseOfProduct = PolynomialInversion::inverseModuloModulus(&ring, &product);
        let partial = ring.product(&inverseOfProduct, &f);
        let inverseOfH = ring.productModuloPhi(&partial, &f);
        secretKey.extend_from_slice(&packing.modulusBytes(&inverseOfH));
        let partial = ring.product(&inverseOfProduct, &g);
        let h = ring.product(&partial, &g);
        (packing.modulusBytes(&h), secretKey)
    }

    /// The ciphertext of a blinding polynomial `r`, lifted to 0, 1 and `q - 1`, and of a
    /// message `m` modulo 3, `owcpa_enc`.
    pub(crate) fn encrypt(&self, blinding: &[u16], message: &[u16], publicKey: &[u8]) -> Vec<u8> {
        let ring = PolynomialRing::new(self.parameters);
        let packing = Packing::new(self.parameters);
        let h = packing.sumZeroPolynomial(publicKey);
        let mut ciphertext = ring.product(blinding, &h);
        for (coefficient, lifted) in ciphertext.iter_mut().zip(ring.lift(message)) {
            *coefficient = coefficient.wrapping_add(lifted);
        }
        packing.modulusBytes(&ciphertext)
    }

    /// The packed `r` and `m` of a ciphertext, and 1 when a check fails or else 0,
    /// `owcpa_dec`. The bytes are those of the C code also when a check fails.
    pub(crate) fn decrypt(&self, ciphertext: &[u8], secretKey: &[u8]) -> (Vec<u8>, u8) {
        let parameters = self.parameters;
        let ring = PolynomialRing::new(parameters);
        let packing = Packing::new(parameters);
        let ternaryLength = parameters.ternaryLength();
        let c = packing.sumZeroPolynomial(ciphertext);
        let mut f = packing.ternaryPolynomial(&secretKey[..ternaryLength]);
        ring.liftTernaryCoefficients(&mut f);
        let productModuloThree = ring.ternaryFromModulus(&ring.product(&c, &f));
        let inverseOfF = packing.ternaryPolynomial(&secretKey[ternaryLength..2 * ternaryLength]);
        let message = ring.ternaryProduct(&productModuloThree, &inverseOfF);
        let mut failure = self.ciphertextFailure(ciphertext);
        if parameters.variant == Variant::hps {
            failure |= self.messageFailure(&message);
        }
        // b = c - Lift(m), and r = b / h modulo q and Phi_n.
        let difference: Vec<u16> = c
            .iter()
            .zip(ring.lift(&message))
            .map(|(coefficient, lifted)| coefficient.wrapping_sub(lifted))
            .collect();
        let inverseOfH = packing.modulusPolynomial(
            &secretKey[2 * ternaryLength..2 * ternaryLength + parameters.packedLength()],
        );
        let mut blinding = ring.productModuloPhi(&difference, &inverseOfH);
        failure |= self.blindingFailure(&blinding);
        ring.lowerTrinaryCoefficients(&mut blinding);
        let mut packed = packing.ternaryBytes(&blinding);
        packed.extend_from_slice(&packing.ternaryBytes(&message));
        (packed, failure)
    }

    /// 1 when the bits of the last ciphertext byte past the last coefficient are not all 0,
    /// and else 0, `owcpa_check_ciphertext`.
    pub(crate) fn ciphertextFailure(&self, ciphertext: &[u8]) -> u8 {
        let parameters = self.parameters;
        let usedBits = (parameters.modulusBits as usize * parameters.packedCoefficientCount()) % 8;
        let unusedBits = u16::from(ciphertext[ciphertext.len() - 1]) & (0xFF_u16 << (8 - usedBits));
        (0u16.wrapping_sub(unusedBits) >> 15) as u8
    }

    /// 1 when a coefficient of `r` below `n - 1` is not 0, 1 or `q - 1` modulo `q`, or the last
    /// one is not 0, and else 0, `owcpa_check_r`.
    pub(crate) fn blindingFailure(&self, blinding: &[u16]) -> u8 {
        let modulus = u32::from(self.parameters.modulus());
        let last = blinding.len() - 1;
        let mut bits = 0u32;
        for coefficient in &blinding[..last] {
            let value = u32::from(*coefficient);
            // 0 exactly for -1, 0, 1 and 2 modulo q.
            bits |= (value + 1) & (modulus - 4);
            // 4 for 2, and 0 for -1, 0 and 1.
            bits |= (value + 2) & 4;
        }
        bits |= u32::from(blinding[last]);
        ((!bits).wrapping_add(1) >> 31) as u8 & 1
    }

    /// 1 when the message does not have `q / 16 - 1` coefficients 1 and as many coefficients
    /// 2, and else 0, `owcpa_check_m` of NTRU-HPS.
    pub(crate) fn messageFailure(&self, message: &[u16]) -> u8 {
        let mut ones = 0u16;
        let mut twos = 0u16;
        for coefficient in message {
            ones = ones.wrapping_add(coefficient & 1);
            twos = twos.wrapping_add(coefficient & 2);
        }
        let mut bits = u32::from(ones ^ (twos >> 1));
        bits |= u32::from(twos ^ self.parameters.weight());
        ((!bits).wrapping_add(1) >> 31) as u8 & 1
    }
}

#[cfg(test)]
mod tests {
    use super::PublicKeyEncryption;
    use crate::parameters::{
        ntruHPS2048509, ntruHPS2048677, ntruHPS4096821, ntruHPS40961229, ntruHRSS701, ntruHRSS1373,
    };
    use crate::testInputs::{cAnswer, digest, everySet, sequenceBytes};

    #[test]
    fn theCiphertextCheckReadsOnlyTheUnusedBitsOfTheLastByte() {
        // 508 * 11 and 700 * 13 bits leave the high four bits of the last byte unused, and
        // 820 * 12, 1228 * 12 and 1372 * 14 bits fill every byte.
        for parameters in [&ntruHPS2048509, &ntruHPS2048677, &ntruHRSS701] {
            let scheme = PublicKeyEncryption::new(parameters);
            let mut ciphertext = vec![0u8; parameters.packedLength()];
            let last = ciphertext.len() - 1;
            for value in 0..=255u8 {
                ciphertext[last] = value;
                assert_eq!(
                    scheme.ciphertextFailure(&ciphertext),
                    u8::from(value >= 0x10),
                    "{value:#04x}"
                );
            }
        }
        for parameters in [&ntruHPS4096821, &ntruHPS40961229, &ntruHRSS1373] {
            let scheme = PublicKeyEncryption::new(parameters);
            let ciphertext = vec![0xFFu8; parameters.packedLength()];
            assert_eq!(scheme.ciphertextFailure(&ciphertext), 0);
        }
    }

    #[test]
    fn theBlindingCheckAcceptsOnlyZeroOneAndMinusOne() {
        for parameters in [&ntruHPS2048509, &ntruHRSS701, &ntruHRSS1373] {
            let scheme = PublicKeyEncryption::new(parameters);
            let q = parameters.modulus();
            let count = parameters.coefficientCount;
            let mut blinding = vec![0u16; count];
            blinding[..3].copy_from_slice(&[1, q - 1, 0]);
            assert_eq!(scheme.blindingFailure(&blinding), 0);
            // A coefficient is read modulo q.
            blinding[3] = q + 1;
            blinding[4] = 2 * q - 1;
            assert_eq!(scheme.blindingFailure(&blinding), 0);
            // The value 2, the values 3 to q - 2, and a last coefficient that is not 0 fail.
            for (place, value) in [
                (5, 2),
                (5, 3),
                (count - 2, q - 2),
                (count - 2, q / 2),
                (count - 1, 1),
                (count - 1, q),
            ] {
                let mut changed = blinding.clone();
                changed[place] = value;
                assert_eq!(
                    scheme.blindingFailure(&changed),
                    1,
                    "{}, coefficient {place} = {value}",
                    parameters.description.name
                );
            }
            // Two equal failures do not cancel. The value 2 fails only the test of the bit 2
            // of `r + 2`, the value q - 2 only the test of the bits from 2 up of `r + 1`, and
            // the value 3 fails both.
            for value in [2, q - 2, 3] {
                let mut changed = blinding.clone();
                changed[5] = value;
                changed[6] = value;
                assert_eq!(
                    scheme.blindingFailure(&changed),
                    1,
                    "{}, two coefficients {value}",
                    parameters.description.name
                );
            }
        }
    }

    #[test]
    fn theMessageCheckWantsTheWeightAndAsManyOnesAsTwos() {
        let scheme = PublicKeyEncryption::new(&ntruHPS2048509);
        let half = 127;
        let mut message = vec![0u16; 509];
        for index in 0..half {
            message[2 * index] = 1;
            message[2 * index + 1] = 2;
        }
        assert_eq!(scheme.messageFailure(&message), 0);
        // One more 1 and one more 2 keep the balance, 128 ones and 128 twos, and break only
        // the weight.
        let mut changed = message.clone();
        changed[400] = 1;
        changed[401] = 2;
        assert_eq!(scheme.messageFailure(&changed), 1);
        // One more 1 keeps the 127 twos of the weight and breaks only the balance.
        let mut changed = message.clone();
        changed[400] = 1;
        assert_eq!(scheme.messageFailure(&changed), 1);
        // A 1 for a 2 breaks both.
        let mut changed = message.clone();
        changed[1] = 1;
        assert_eq!(scheme.messageFailure(&changed), 1);
        // Two failed terms that are equal do not cancel: 124 ones and 126 twos give
        // 124 ^ 126 = 2 for the balance and 252 ^ 254 = 2 for the weight.
        let mut changed = message.clone();
        for place in [0, 2, 4, 1] {
            changed[place] = 0;
        }
        assert_eq!(scheme.messageFailure(&changed), 1);
        // The places do not matter.
        let mut moved = message.clone();
        moved.swap(0, 508);
        moved.swap(1, 300);
        assert_eq!(scheme.messageFailure(&moved), 0);
    }

    #[test]
    fn theKeysAndAHostileDecryptionHaveTheBytesOfTheCFunctions() {
        // owcpa_keypair and owcpa_dec of liboqs 0.16.0: the keys of seeded bytes, and the
        // decryption of seeded bytes as a ciphertext, which fails a check.
        for parameters in everySet() {
            let scheme = PublicKeyEncryption::new(parameters);
            let name = parameters.description.name;
            let (publicKey, secretKey) =
                scheme.keyPair(&sequenceBytes(parameters.sampleLength(), 18));
            assert_eq!(secretKey.len(), parameters.encryptionSecretKeyLength());
            assert_eq!(digest(&publicKey), cAnswer(name, "publicKey"), "{name}");
            assert_eq!(
                digest(&secretKey),
                cAnswer(name, "encryptionSecretKey"),
                "{name}"
            );
            let (packed, failure) =
                scheme.decrypt(&sequenceBytes(parameters.packedLength(), 19), &secretKey);
            assert_eq!(
                digest(&packed),
                cAnswer(name, "hostileDecryption"),
                "{name}"
            );
            assert_eq!(
                failure.to_string(),
                cAnswer(name, "hostileFailure"),
                "{name}"
            );
        }
    }
}
