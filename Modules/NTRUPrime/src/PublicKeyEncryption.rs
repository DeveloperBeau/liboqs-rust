use crate::{Encoding, Parameters, PolynomialRing, Sampler};
use OQSNativeDomain::RandomGenerating;
use alloc::vec::Vec;

/// The public-key encryption of Streamlined NTRU Prime, `KeyGen`, `Encrypt` and `Decrypt` of
/// `sntrup761.c` with their byte forms `ZKeyGen`, `ZEncrypt` and `ZDecrypt`.
///
/// The public key is `h = g / (3 f)` in `Rq`, for a small `g` that has an inverse in `R3` and
/// a short `f` of weight `w`. The secret key is `f` and `1 / g` in `R3`. A ciphertext is
/// `Round(h r)` for a short `r`. Decryption computes `e = 3 f c` in `R3`, and `r = e / g`.
/// When `e / g` does not have the weight `w`, decryption gives the fixed polynomial with `w`
/// leading coefficients 1, so its result is always short.
pub(crate) struct PublicKeyEncryption<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> PublicKeyEncryption<'parameters> {
    /// Makes the scheme of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        PublicKeyEncryption { parameters }
    }

    /// The encoded public key and the encoded `f` and `1 / g` of a key pair, `ZKeyGen`.
    ///
    /// `KeyGen` draws a small `g` until `g` has an inverse in `R3`, each time one request of
    /// `4 p` bytes, and then the short `f` in one more request.
    pub(crate) fn keyPair(&self, random: &mut dyn RandomGenerating) -> (Vec<u8>, Vec<u8>) {
        let ring = PolynomialRing::new(self.parameters);
        let sampler = Sampler::new(self.parameters);
        let (g, inverseOfG) = loop {
            let g = sampler.smallPolynomial(random);
            let (inverse, mask) = ring.ternaryReciprocal(&g);
            if mask == 0 {
                break (g, inverse);
            }
        };
        let f = sampler.shortPolynomial(random);
        let (inverseOfTripleF, _) = ring.reciprocalOfTriple(&f);
        let h = ring.productWithSmall(&inverseOfTripleF, &g);
        let encoding = Encoding::new(self.parameters);
        let mut secretKey = Vec::with_capacity(self.parameters.description.secretKeyLength);
        secretKey.extend_from_slice(&encoding.smallBytes(&f));
        secretKey.extend_from_slice(&encoding.smallBytes(&inverseOfG));
        (encoding.modulusBytes(&h), secretKey)
    }

    /// The encoded rounded ciphertext of a short `r` under an encoded public key, `ZEncrypt`.
    pub(crate) fn encrypt(&self, short: &[i8], publicKey: &[u8]) -> Vec<u8> {
        let encoding = Encoding::new(self.parameters);
        let ring = PolynomialRing::new(self.parameters);
        let h = encoding.modulusPolynomial(publicKey);
        let product = ring.productWithSmall(&h, short);
        encoding.roundedBytes(&PolynomialRing::rounded(&product))
    }

    /// The short `r` of an encoded rounded ciphertext under the encoded `f` and `1 / g`,
    /// `ZDecrypt`.
    pub(crate) fn decrypt(&self, roundedCiphertext: &[u8], secretKey: &[u8]) -> Vec<i8> {
        let parameters = self.parameters;
        let encoding = Encoding::new(parameters);
        let ring = PolynomialRing::new(parameters);
        let smallLength = parameters.smallLength();
        let f = encoding.smallPolynomial(&secretKey[..smallLength]);
        let inverseOfG = encoding.smallPolynomial(&secretKey[smallLength..2 * smallLength]);
        let c = encoding.roundedPolynomial(roundedCiphertext);
        let tripled = ring.tripled(&ring.productWithSmall(&c, &f));
        let e = PolynomialRing::ternaryFromModulus(&tripled);
        let candidate = ring.ternaryProduct(&e, &inverseOfG);
        self.shortOrFixed(&candidate)
    }

    /// The candidate of a decryption when it has the weight `w`, and else the polynomial with
    /// `w` leading coefficients 1, chosen with a mask: the end of `Decrypt` with
    /// `Weightw_mask`.
    pub(crate) fn shortOrFixed(&self, candidate: &[i8]) -> Vec<i8> {
        let weight = self.parameters.weight;
        let mask = self.weightMask(candidate);
        candidate
            .iter()
            .enumerate()
            .map(|(index, coefficient)| {
                if index < weight {
                    ((coefficient ^ 1) & !mask) ^ 1
                } else {
                    coefficient & !mask
                }
            })
            .collect()
    }

    /// 0 when a small polynomial has the weight `w`, and else -1, `Weightw_mask`.
    pub(crate) fn weightMask(&self, small: &[i8]) -> i8 {
        let weight: i32 = small
            .iter()
            .map(|coefficient| i32::from(coefficient & 1))
            .sum();
        let difference = (weight - self.parameters.weight as i32) as i16;
        crate::ModularReduction::nonzeroMask(difference) as i8
    }
}

#[cfg(test)]
mod tests {
    use super::PublicKeyEncryption;
    use crate::parameters::sntrup761;

    #[test]
    fn theWeightMaskAcceptsExactlyTheWeightW() {
        let scheme = PublicKeyEncryption::new(&sntrup761);
        let mut small = vec![0i8; 761];
        for (index, coefficient) in small[..286].iter_mut().enumerate() {
            *coefficient = if index % 2 == 0 { 1 } else { -1 };
        }
        assert_eq!(scheme.weightMask(&small), 0);
        let mut heavier = small.clone();
        heavier[500] = 1;
        assert_eq!(scheme.weightMask(&heavier), -1);
        let mut lighter = small.clone();
        lighter[0] = 0;
        assert_eq!(scheme.weightMask(&lighter), -1);
        // The value 2 of a decoded key has the low bit 0, as 0 has.
        let mut withTwo = small.clone();
        withTwo[0] = 2;
        assert_eq!(scheme.weightMask(&withTwo), -1);
        withTwo[600] = -1;
        assert_eq!(scheme.weightMask(&withTwo), 0);
    }

    #[test]
    fn aCandidateOfAnotherWeightBecomesTheFixedShortPolynomial() {
        let scheme = PublicKeyEncryption::new(&sntrup761);
        let mut candidate = vec![0i8; 761];
        for coefficient in &mut candidate[400..686] {
            *coefficient = -1;
        }
        // The weight w is kept as it is.
        assert_eq!(scheme.shortOrFixed(&candidate), candidate);
        // A weight of w + 1 gives w coefficients 1 and then zeros.
        candidate[0] = 1;
        let mut fixed = vec![0i8; 761];
        for coefficient in &mut fixed[..286] {
            *coefficient = 1;
        }
        assert_eq!(scheme.shortOrFixed(&candidate), fixed);
        // So does a weight of w - 1.
        candidate[0] = 0;
        candidate[400] = 0;
        assert_eq!(scheme.shortOrFixed(&candidate), fixed);
    }
}
