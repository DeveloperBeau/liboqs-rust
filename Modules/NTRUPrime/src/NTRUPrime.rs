use crate::parameters::sntrup761;
use crate::{Encoding, HashFunctions, Parameters, PublicKeyEncryption, Sampler};
use OQSNativeDomain::{InputLength, KeyEncapsulating, RandomGenerating};
use OQSNativeEntities::{Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes};
use alloc::vec::Vec;

/// Streamlined NTRU Prime, the lattice key encapsulation mechanism of round 3 of the NIST
/// process, with one parameter set.
///
/// The parameter set is `NTRUPrime::sntrup761`, and it gives the bytes of the liboqs algorithm
/// of the same name, whose C code is `sntrup761.c` of OpenSSH. A key pair draws `4 p` random
/// bytes for each candidate `g` until one has an inverse modulo 3, then `4 p` bytes for `f`,
/// and then the rejection value `rho` of the secret key. An encapsulation draws `4 p` bytes
/// for the short `r`. The ciphertext is the rounded encryption of `r` and a confirmation hash.
/// Decapsulation decrypts, encrypts again and compares the two ciphertexts with no branch on
/// the result: a difference puts `rho` in place of `r`, and the hash prefix 0 in place of 1.
/// sntrup761 checks neither key, and liboqs gives it no seeded forms.
pub struct NTRUPrime {
    parameters: &'static Parameters,
}

impl NTRUPrime {
    /// sntrup761, security category 2.
    pub const sntrup761: NTRUPrime = NTRUPrime {
        parameters: &sntrup761,
    };

    /// The ciphertext of a short `r` and its encoded `r`, `Hide`: the rounded encryption and
    /// the confirmation of `r` and the hash of the public key.
    fn hidden(&self, short: &[i8], publicKey: &[u8], publicKeyHash: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let encodedShort = Encoding::new(self.parameters).smallBytes(short);
        let mut ciphertext = PublicKeyEncryption::new(self.parameters).encrypt(short, publicKey);
        ciphertext.extend_from_slice(&HashFunctions::confirmation(&encodedShort, publicKeyHash));
        (ciphertext, encodedShort)
    }
}

impl KeyEncapsulating for NTRUPrime {
    fn description(&self) -> &'static KEMDescription {
        &self.parameters.description
    }

    fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        let parameters = self.parameters;
        let (publicKey, mut secretKey) = PublicKeyEncryption::new(parameters).keyPair(random);
        secretKey.extend_from_slice(&publicKey);
        let mut rejectionValue = SecretBytes::zeroed(parameters.smallLength());
        random.fillRandomBytes(rejectionValue.mutableBytes());
        secretKey.extend_from_slice(rejectionValue.bytes());
        secretKey.extend_from_slice(&HashFunctions::publicKeyHash(&publicKey));
        Ok(KeyPair {
            publicKey,
            secretKey: SecretBytes::new(secretKey),
        })
    }

    fn encapsulate(
        &self,
        publicKey: &[u8],
        random: &mut dyn RandomGenerating,
    ) -> Result<Encapsulation, OQSError> {
        let parameters = self.parameters;
        let publicKey = InputLength::checked(publicKey, parameters.description.publicKeyLength)?;
        let publicKeyHash = HashFunctions::publicKeyHash(publicKey);
        let short = Sampler::new(parameters).shortPolynomial(random);
        let (ciphertext, encodedShort) = self.hidden(&short, publicKey, &publicKeyHash);
        let encodedShort = SecretBytes::new(encodedShort);
        let sharedSecret = HashFunctions::sessionKey(
            HashFunctions::sessionPrefix,
            encodedShort.bytes(),
            &ciphertext,
        );
        Ok(Encapsulation {
            ciphertext,
            sharedSecret: SecretBytes::new(sharedSecret.to_vec()),
        })
    }

    fn decapsulate(&self, ciphertext: &[u8], secretKey: &[u8]) -> Result<SecretBytes, OQSError> {
        let parameters = self.parameters;
        let description = &parameters.description;
        let ciphertext = InputLength::checked(ciphertext, description.ciphertextLength)?;
        let secretKey = InputLength::checked(secretKey, description.secretKeyLength)?;
        // The secret key is f, 1 / g, the public key, rho and the hash of the public key.
        let smallLength = parameters.smallLength();
        let (_, rest) = secretKey.split_at(2 * smallLength);
        let (publicKey, rest) = rest.split_at(description.publicKeyLength);
        let (rejectionValue, publicKeyHash) = rest.split_at(smallLength);
        let short = PublicKeyEncryption::new(parameters)
            .decrypt(&ciphertext[..parameters.roundedLength()], secretKey);
        let (reencrypted, encodedShort) = self.hidden(&short, publicKey, publicKeyHash);
        let mut encodedShort = SecretBytes::new(encodedShort);
        // `Ciphertexts_diff_mask`: the choice depends on a secret value, so it uses a mask, not
        // a branch. The mask is 0 for equal ciphertexts and -1 for different ones.
        let differences = reencrypted
            .iter()
            .zip(ciphertext)
            .fold(0u16, |accumulated, (left, right)| {
                accumulated | u16::from(left ^ right)
            });
        let mask = core::hint::black_box((((i32::from(differences) - 1) >> 8) & 1) - 1);
        for (byte, replacement) in encodedShort.mutableBytes().iter_mut().zip(rejectionValue) {
            *byte ^= (mask as u8) & (*byte ^ replacement);
        }
        let prefix = HashFunctions::sessionPrefix
            ^ ((mask as u8)
                & (HashFunctions::sessionPrefix ^ HashFunctions::rejectedSessionPrefix));
        let sharedSecret = HashFunctions::sessionKey(prefix, encodedShort.bytes(), ciphertext);
        Ok(SecretBytes::new(sharedSecret.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::NTRUPrime;
    use crate::parameters::sntrup761;
    use crate::testInputs::{SequenceRandom, byteSequence, cAnswer, digest, smallBytes};
    use crate::{PublicKeyEncryption, Sampler};
    use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};

    #[test]
    fn theOperationsOfASequenceGiveTheBytesOfTheCCode() {
        // crypto_kem_sntrup761_keypair, _enc and _dec of liboqs 0.16.0 with the sequence of the
        // seeds 14 and 15 as the random source, and the decapsulation of the bytes of seed 16.
        let mechanism = &NTRUPrime::sntrup761;
        let keyPair = mechanism
            .generateKeyPair(&mut SequenceRandom::new(14))
            .expect("key pair");
        assert_eq!(digest(&keyPair.publicKey), cAnswer("publicKey"));
        assert_eq!(digest(keyPair.secretKey.bytes()), cAnswer("secretKey"));
        let encapsulation = mechanism
            .encapsulate(&keyPair.publicKey, &mut SequenceRandom::new(15))
            .expect("encapsulation");
        assert_eq!(digest(&encapsulation.ciphertext), cAnswer("ciphertext"));
        assert_eq!(
            digest(encapsulation.sharedSecret.bytes()),
            cAnswer("sharedSecret")
        );
        let hostile = byteSequence(1039, 16);
        let secret = mechanism
            .decapsulate(&hostile, keyPair.secretKey.bytes())
            .expect("no error");
        assert_eq!(digest(secret.bytes()), cAnswer("hostileSharedSecret"));
        let short = PublicKeyEncryption::new(&sntrup761)
            .decrypt(&hostile[..1007], keyPair.secretKey.bytes());
        assert_eq!(digest(&smallBytes(&short)), cAnswer("hostileDecryption"));
    }

    /// A random source whose first request gives the words 0x20000000, which make the small
    /// polynomial 0, and whose later requests come from another source.
    struct ZeroCandidateFirst {
        isFirst: bool,
        later: SequenceRandom,
        requests: Vec<usize>,
    }

    impl RandomGenerating for ZeroCandidateFirst {
        fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
            self.requests.push(bytes.len());
            if self.isFirst {
                self.isFirst = false;
                for word in bytes.chunks_exact_mut(4) {
                    word.copy_from_slice(&0x2000_0000u32.to_le_bytes());
                }
            } else {
                self.later.fillRandomBytes(bytes);
            }
        }
    }

    #[test]
    fn aCandidateGWithoutAnInverseIsDrawnAgain() {
        // 0x20000000 is a third of 2^30 and more, so each coefficient is 0, and the zero
        // polynomial has no inverse modulo 3.
        assert!(
            Sampler::smallFromWords(&[0x2000_0000; 761])
                .iter()
                .all(|value| *value == 0)
        );
        let mechanism = &NTRUPrime::sntrup761;
        let mut random = ZeroCandidateFirst {
            isFirst: true,
            later: SequenceRandom::new(14),
            requests: Vec::new(),
        };
        let keyPair = mechanism.generateKeyPair(&mut random).expect("key pair");
        // One more request of 4 p bytes, and then the key pair of the other source alone.
        assert_eq!(random.requests, vec![3044, 3044, 3044, 191]);
        assert_eq!(digest(&keyPair.publicKey), cAnswer("publicKey"));
        assert_eq!(digest(keyPair.secretKey.bytes()), cAnswer("secretKey"));
    }
}
