use crate::Parameters;
use crate::binaryVector::BinaryVector;
use crate::concatenatedCode::ConcatenatedCode;
use crate::hashFunctions::HashFunctions;
use crate::parameters::seedLength;
use alloc::vec::Vec;

/// The public-key encryption scheme HQC-PKE of one parameter set, `hqc.c` and `parsing.c` of
/// the reference code.
///
/// The encryption key is the seed of `h` and the vector `s = x + y h`. The decryption key is
/// the seed of `y` and `x`. A ciphertext is `u = r1 + r2 h` and
/// `v = encode(m) + truncate(s r2 + e)`.
pub(crate) struct PublicKeyEncryption<'parameters> {
    parameters: &'parameters Parameters,
}

impl<'parameters> PublicKeyEncryption<'parameters> {
    /// Makes the scheme of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        PublicKeyEncryption { parameters }
    }

    /// The secret vector `y` of a decryption key, the first vector of its expander,
    /// `hqc_dk_pke_from_string`.
    fn secretVector(&self, decryptionKey: &[u8]) -> BinaryVector {
        let mut expander = HashFunctions::expander(decryptionKey);
        BinaryVector::sampledByRejection(
            &mut expander,
            self.parameters.secretWeight,
            self.parameters,
        )
    }

    /// `HQC-PKE.KeyGen`, `hqc_pke_keygen`: the encryption key and the decryption key of a seed.
    pub(crate) fn keyPair(&self, seed: &[u8; seedLength]) -> (Vec<u8>, [u8; seedLength]) {
        let parameters = self.parameters;
        let seeds = HashFunctions::keyPairSeeds(seed);
        let (decryptionSeed, encryptionSeed) = seeds.split_at(seedLength);
        let mut secretExpander = HashFunctions::expander(decryptionSeed);
        let y = BinaryVector::sampledByRejection(
            &mut secretExpander,
            parameters.secretWeight,
            parameters,
        );
        let x = BinaryVector::sampledByRejection(
            &mut secretExpander,
            parameters.secretWeight,
            parameters,
        );
        let h =
            BinaryVector::sampledUniform(&mut HashFunctions::expander(encryptionSeed), parameters);
        let s = x.plus(&y.product(&h, parameters));
        let mut encryptionKey = Vec::with_capacity(parameters.description.publicKeyLength);
        encryptionKey.extend_from_slice(encryptionSeed);
        encryptionKey.extend_from_slice(&s.bytes(parameters.vectorByteCount()));
        let decryptionKey: [u8; seedLength] = decryptionSeed.try_into().expect("32 bytes");
        (encryptionKey, decryptionKey)
    }

    /// `HQC-PKE.Encrypt`, `hqc_pke_encrypt`: the encoded `u` and `v` of a message of `k` bytes
    /// under an encryption key, with the seed `theta`.
    ///
    /// The expander of `theta` gives `r2`, then `e`, then `r1`, as the C code draws them. The
    /// vector `s` is the bytes of the key as they are, so a hostile key with bits above `n`
    /// keeps them, as in the C code.
    pub(crate) fn encrypt(
        &self,
        encryptionKey: &[u8],
        message: &[u8],
        theta: &[u8; seedLength],
    ) -> Vec<u8> {
        let parameters = self.parameters;
        let wordCount = parameters.vectorWordCount();
        let (encryptionSeed, encodedS) = encryptionKey.split_at(seedLength);
        let h =
            BinaryVector::sampledUniform(&mut HashFunctions::expander(encryptionSeed), parameters);
        let s = BinaryVector::fromBytes(encodedS, wordCount);
        let mut expander = HashFunctions::expander(theta);
        let r2 = BinaryVector::sampledWithoutRejection(
            &mut expander,
            parameters.randomnessWeight,
            parameters,
        );
        let e = BinaryVector::sampledWithoutRejection(
            &mut expander,
            parameters.errorWeight,
            parameters,
        );
        let r1 = BinaryVector::sampledWithoutRejection(
            &mut expander,
            parameters.randomnessWeight,
            parameters,
        );
        let u = r1.plus(&r2.product(&h, parameters));
        let noise = r2
            .product(&s, parameters)
            .plus(&e)
            .truncated(parameters.codewordWordCount());
        let codeword = BinaryVector {
            words: ConcatenatedCode::new(parameters).encoded(message),
        };
        let v = codeword.plus(&noise);
        let mut ciphertext = u.bytes(parameters.vectorByteCount());
        ciphertext.extend_from_slice(&v.bytes(parameters.codewordByteCount()));
        ciphertext
    }

    /// `HQC-PKE.Decrypt`, `hqc_pke_decrypt`: the message of `k` bytes that the encoded `u` and
    /// `v` carry under a decryption key.
    pub(crate) fn decrypt(
        &self,
        decryptionKey: &[u8],
        encodedU: &[u8],
        encodedV: &[u8],
    ) -> Vec<u8> {
        let parameters = self.parameters;
        let codewordWords = parameters.codewordWordCount();
        let y = self.secretVector(decryptionKey);
        let u = BinaryVector::fromBytes(encodedU, parameters.vectorWordCount());
        let v = BinaryVector::fromBytes(encodedV, codewordWords);
        let received = v.plus(&y.product(&u, parameters).truncated(codewordWords));
        ConcatenatedCode::new(parameters).decoded(&received.words)
    }
}

#[cfg(test)]
mod tests {
    use super::PublicKeyEncryption;
    use crate::parameters::{hqc1, hqc3, hqc5, seedLength};

    #[test]
    fn decryptionRecoversTheMessageOfEachSet() {
        for parameters in [&hqc1, &hqc3, &hqc5] {
            let scheme = PublicKeyEncryption::new(parameters);
            let (encryptionKey, decryptionKey) = scheme.keyPair(&[7u8; seedLength]);
            assert_eq!(encryptionKey.len(), parameters.description.publicKeyLength);
            let message: Vec<u8> = (0..parameters.messageLength as u8).collect();
            let ciphertext = scheme.encrypt(&encryptionKey, &message, &[3u8; seedLength]);
            let byteCount = parameters.vectorByteCount();
            assert_eq!(ciphertext.len(), byteCount + parameters.codewordByteCount());
            let decrypted = scheme.decrypt(
                &decryptionKey,
                &ciphertext[..byteCount],
                &ciphertext[byteCount..],
            );
            assert_eq!(decrypted, message, "{}", parameters.description.name);
            // Another seed gives another ciphertext of the same message.
            assert_ne!(
                scheme.encrypt(&encryptionKey, &message, &[4u8; seedLength]),
                ciphertext
            );
        }
    }

    #[test]
    fn theEncryptionKeyIsTheSeedOfHAndTheBytesOfS() {
        let scheme = PublicKeyEncryption::new(&hqc1);
        let (encryptionKey, _) = scheme.keyPair(&[1u8; seedLength]);
        // The bits of the last byte of `s` at and above `n` are zero.
        let lastByte = encryptionKey[encryptionKey.len() - 1];
        assert_eq!(lastByte >> (hqc1.vectorLength % 8), 0);
        let (otherKey, _) = scheme.keyPair(&[2u8; seedLength]);
        assert_ne!(otherKey[..seedLength], encryptionKey[..seedLength]);
    }
}
