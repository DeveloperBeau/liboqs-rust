use crate::encoding::{Encoding, largePolynomialBits, smallPolynomialBits};
use crate::hashToPoint::HashToPoint;
use crate::keyGenerator::KeyGenerator;
use crate::modularPolynomial::ModularPolynomial;
use crate::parameters::{Parameters, falcon512, falcon1024, falconPadded512, falconPadded1024};
use crate::secretBasis::SecretBasis;
use crate::signer::Signer;
use OQSNativeDomain::{InputLength, RandomGenerating, Signing};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, SignatureDescription};
use OQSNativeSHA3::SHAKE256;
use alloc::vec::Vec;

/// Falcon, the signature scheme over NTRU lattices, with one parameter set, as liboqs ships it
/// from the clean code of PQClean.
///
/// The four parameter sets are `Falcon::falcon512`, `Falcon::falcon1024`,
/// `Falcon::falconPadded512` and `Falcon::falconPadded1024`. Each gives the bytes of the liboqs
/// algorithm of the same name. A key pair draws a 48-byte seed. A signature draws a 40-byte
/// nonce and then a 48-byte seed, in two requests. A signature is a header byte, the nonce and
/// the compressed vector `s2`, which the padded sets pad with zeros to the full length. Falcon
/// has no context string.
pub struct Falcon {
    parameters: &'static Parameters,
}

/// The length of the nonce of a signature.
const nonceLength: usize = 40;

/// The length of the seeds of the key pair and of the signature.
const seedLength: usize = 48;

/// The header byte of a secret key, without the degree.
const secretKeyHeader: u8 = 0x50;

/// The header byte of a signature, without the degree.
const signatureHeader: u8 = 0x30;

impl Falcon {
    /// Falcon-512, security category 1, with compressed signatures.
    pub const falcon512: Falcon = Falcon {
        parameters: &falcon512,
    };

    /// Falcon-1024, security category 5, with compressed signatures.
    pub const falcon1024: Falcon = Falcon {
        parameters: &falcon1024,
    };

    /// Falcon-padded-512, security category 1, with signatures of a fixed length.
    pub const falconPadded512: Falcon = Falcon {
        parameters: &falconPadded512,
    };

    /// Falcon-padded-1024, security category 5, with signatures of a fixed length.
    pub const falconPadded1024: Falcon = Falcon {
        parameters: &falconPadded1024,
    };

    /// The degree logarithm as the low bits of the header bytes.
    fn logn(&self) -> u32 {
        self.parameters.logn
    }

    /// The point `c0` of a nonce and a message: `HashToPoint(nonce || message)`.
    fn hashedMessage(&self, nonce: &[u8], message: &[u8]) -> Vec<u16> {
        let mut hash = SHAKE256::new();
        hash.absorb(nonce);
        hash.absorb(message);
        HashToPoint::point(&mut hash.finalize(), self.logn())
    }

    /// The polynomials `f`, `g` and `F` of a secret key of the right length, or
    /// `OQSError::operationFailed` when the key does not decode, as `do_sign` decodes it.
    fn decodedSecretKey(&self, secretKey: &[u8]) -> Result<[Vec<i8>; 3], OQSError> {
        let logn = self.logn();
        if secretKey[0] != secretKeyHeader + logn as u8 {
            return Err(OQSError::operationFailed);
        }
        let mut position = 1;
        let mut decoded = |bits: u32| -> Result<Vec<i8>, OQSError> {
            let (polynomial, length) = Encoding::trimmedDecoded(&secretKey[position..], logn, bits)
                .ok_or(OQSError::operationFailed)?;
            position += length;
            Ok(polynomial)
        };
        let f = decoded(smallPolynomialBits[logn as usize])?;
        let g = decoded(smallPolynomialBits[logn as usize])?;
        let bigF = decoded(largePolynomialBits[logn as usize])?;
        if position != secretKey.len() {
            return Err(OQSError::operationFailed);
        }
        Ok([f, g, bigF])
    }

    /// The compressed value of a signature from a source of signature vectors, as the two forms
    /// of `do_sign` make it: the compressed sets encode the first vector and fail when it does
    /// not fit, and the padded sets take the first vector that fits and pad it with zeros to the
    /// full length.
    fn encodedValue(&self, mut nextVector: impl FnMut() -> Vec<i16>) -> Result<Vec<u8>, OQSError> {
        let maximumLength = self.parameters.description.signatureLength - 1 - nonceLength;
        loop {
            match Encoding::compressedEncoded(&nextVector(), self.logn(), maximumLength) {
                Some(mut encoded) => {
                    if self.parameters.isPadded {
                        encoded.resize(maximumLength, 0);
                    }
                    return Ok(encoded);
                }
                None if !self.parameters.isPadded => return Err(OQSError::operationFailed),
                None => {}
            }
        }
    }
}

impl Signing for Falcon {
    fn description(&self) -> &'static SignatureDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let logn = self.logn();
        let description = &self.parameters.description;
        let mut seed = [0u8; seedLength];
        random.fillRandomBytes(&mut seed);
        let (f, g, bigF, publicPolynomial) =
            KeyGenerator::generatedKey(&mut SHAKE256::absorbOnce(&seed), logn);
        // The secret key: the header byte, then f, g and F in their trimmed widths.
        let mut secretKey = Vec::with_capacity(description.secretKeyLength);
        secretKey.push(secretKeyHeader + logn as u8);
        let smallBits = smallPolynomialBits[logn as usize];
        let largeBits = largePolynomialBits[logn as usize];
        for (polynomial, bits) in [(&f, smallBits), (&g, smallBits), (&bigF, largeBits)] {
            let room = description.secretKeyLength - secretKey.len();
            let encoded = Encoding::trimmedEncoded(polynomial, logn, bits, room)
                .ok_or(OQSError::operationFailed)?;
            secretKey.extend_from_slice(&encoded);
        }
        if secretKey.len() != description.secretKeyLength {
            return Err(OQSError::operationFailed);
        }
        // The public key: the header byte, then h in 14 bits for each coefficient.
        let mut publicKey = Vec::with_capacity(description.publicKeyLength);
        publicKey.push(logn as u8);
        let encoded =
            Encoding::modularEncoded(&publicPolynomial, logn).ok_or(OQSError::operationFailed)?;
        publicKey.extend_from_slice(&encoded);
        if publicKey.len() != description.publicKeyLength {
            return Err(OQSError::operationFailed);
        }
        Ok(KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        })
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Vec<u8>, OQSError> {
        let description = &self.parameters.description;
        let secretKey = InputLength::checked(secretKey, description.secretKeyLength)?;
        let logn = self.logn();
        let [f, g, bigF] = self.decodedSecretKey(secretKey)?;
        let bigG = ModularPolynomial::completedSecretPolynomial(&f, &g, &bigF, logn)
            .ok_or(OQSError::operationFailed)?;
        let mut nonce = [0u8; nonceLength];
        random.fillRandomBytes(&mut nonce);
        let hashedMessage = self.hashedMessage(&nonce, message);
        let mut seed = [0u8; seedLength];
        random.fillRandomBytes(&mut seed);
        let basis = SecretBasis {
            f: &f,
            g: &g,
            bigF: &bigF,
            bigG: &bigG,
        };
        let mut reader = SHAKE256::absorbOnce(&seed);
        let value = self
            .encodedValue(|| Signer::signatureVector(&mut reader, &basis, &hashedMessage, logn))?;
        let mut signature = Vec::with_capacity(1 + nonceLength + value.len());
        signature.push(signatureHeader + logn as u8);
        signature.extend_from_slice(&nonce);
        signature.extend_from_slice(&value);
        Ok(signature)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        let logn = self.logn();
        if publicKey.len() != self.parameters.description.publicKeyLength
            || signature.len() < 1 + nonceLength
            || signature[0] != signatureHeader + logn as u8
            || publicKey[0] != logn as u8
        {
            return false;
        }
        let Some(mut publicPolynomial) = Encoding::modularDecoded(&publicKey[1..], logn) else {
            return false;
        };
        ModularPolynomial::toMontgomeryTransform(&mut publicPolynomial, logn);
        let (nonce, value) = signature[1..].split_at(nonceLength);
        if value.is_empty() {
            return false;
        }
        let Some((vector, length)) = Encoding::compressedDecoded(value, logn) else {
            return false;
        };
        // The value must fill the signature, except for a value of the padded length, whose
        // remaining bytes must be zero.
        if length != value.len() {
            let paddedLength = self.parameters.paddedSignatureLength - 1 - nonceLength;
            if value.len() != paddedLength || value[length..].iter().any(|byte| *byte != 0) {
                return false;
            }
        }
        let hashedMessage = self.hashedMessage(nonce, message);
        ModularPolynomial::isValidSignatureVector(&hashedMessage, &vector, &publicPolynomial, logn)
    }
}

#[cfg(test)]
mod tests {
    use super::Falcon;
    use crate::encoding::Encoding;
    use OQSNativeEntities::OQSError;

    #[test]
    fn aCompressedSetFailsWhenTheVectorDoesNotFitAndAPaddedSetSignsAgain() {
        // A coefficient of 2047 takes 24 bits, so 512 of them take 1536 bytes, more than either
        // form holds. A coefficient of 0 takes 9 bits, so the zero vector takes 576 bytes.
        let large = vec![2047i16; 512];
        let zero = vec![0i16; 512];
        let mut calls = 0;
        let result = Falcon::falcon512.encodedValue(|| {
            calls += 1;
            large.clone()
        });
        assert_eq!((result, calls), (Err(OQSError::operationFailed), 1));
        let mut calls = 0;
        let value = Falcon::falconPadded512
            .encodedValue(|| {
                calls += 1;
                if calls == 1 {
                    large.clone()
                } else {
                    zero.clone()
                }
            })
            .expect("the second vector fits");
        assert_eq!(calls, 2);
        let mut expected = Encoding::compressedEncoded(&zero, 9, 625).expect("the zero vector");
        assert_eq!(expected.len(), 576);
        expected.resize(625, 0);
        assert_eq!(value, expected);
        let compressed = Falcon::falcon512
            .encodedValue(|| zero.clone())
            .expect("the zero vector fits");
        assert_eq!(compressed.len(), 576);
    }
}
