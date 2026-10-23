use crate::Parameters;
use crate::polynomial::Polynomial;
use OQSNativeSHA3::SHA3512;
use alloc::vec::Vec;

/// The public-key encryption scheme K-PKE of FIPS 203, Section 5, of one parameter set.
pub(crate) struct PublicKeyEncryption<'parameters> {
    parameters: &'parameters Parameters,
}

/// The matrix `A_hat` of FIPS 203, as rows of polynomials in the NTT domain.
type Matrix = Vec<Vec<Polynomial>>;

impl<'parameters> PublicKeyEncryption<'parameters> {
    /// Makes the scheme of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        PublicKeyEncryption { parameters }
    }

    /// The matrix of a seed `rho`: `A_hat[i][j] = SampleNTT(rho || j || i)`. The transposed
    /// matrix swaps the two index bytes.
    fn matrix(&self, seed: &[u8; 32], isTransposed: bool) -> Matrix {
        let rank = self.parameters.rank;
        (0..rank)
            .map(|row| {
                (0..rank)
                    .map(|column| {
                        let (first, second) = if isTransposed {
                            (row as u8, column as u8)
                        } else {
                            (column as u8, row as u8)
                        };
                        Polynomial::sampledUniform(seed, first, second)
                    })
                    .collect()
            })
            .collect()
    }

    /// The product of a matrix and a vector, both in the NTT domain.
    fn matrixProduct(matrix: &Matrix, vector: &[Polynomial]) -> Vec<Polynomial> {
        matrix
            .iter()
            .map(|row| Self::innerProduct(row, vector))
            .collect()
    }

    /// The inner product of two vectors in the NTT domain.
    fn innerProduct(left: &[Polynomial], right: &[Polynomial]) -> Polynomial {
        left.iter().zip(right).fold(
            Polynomial::zero,
            |total, (leftPolynomial, rightPolynomial)| {
                total.plus(&leftPolynomial.transformedProduct(rightPolynomial))
            },
        )
    }

    /// The noise vector of `rank` polynomials from `PRF_eta(seed, nonce)`, with one nonce for
    /// each polynomial from a first nonce.
    fn noiseVector(&self, eta: usize, seed: &[u8; 32], firstNonce: u8) -> Vec<Polynomial> {
        (0..self.parameters.rank)
            .map(|index| Polynomial::sampledCenteredBinomial(eta, seed, firstNonce + index as u8))
            .collect()
    }

    fn encodedVector(vector: &[Polynomial], bits: u32, output: &mut [u8]) {
        for (polynomial, chunk) in vector
            .iter()
            .zip(output.chunks_exact_mut(32 * bits as usize))
        {
            polynomial.encoded(bits, chunk);
        }
    }

    fn decodedVector(bits: u32, input: &[u8]) -> Vec<Polynomial> {
        input
            .chunks_exact(32 * bits as usize)
            .map(|chunk| Polynomial::decoded(bits, chunk))
            .collect()
    }

    /// `K-PKE.KeyGen` of FIPS 203, Algorithm 13, from the 32-byte seed `d`: the encryption key
    /// `ek` and the decryption key `dk`. Kyber of round 3 hashes the seed without the rank
    /// byte.
    pub(crate) fn keyPair(&self, seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let rank = self.parameters.rank;
        let mut hash = SHA3512::new();
        hash.absorb(seed);
        if self.parameters.isRankHashed {
            hash.absorb(&[rank as u8]);
        }
        let expanded = hash.finalize();
        let publicSeed: [u8; 32] = expanded[..32].try_into().expect("32 bytes");
        let noiseSeed: [u8; 32] = expanded[32..].try_into().expect("32 bytes");
        let matrix = self.matrix(&publicSeed, false);
        let eta = self.parameters.firstEta;
        let mut secret = self.noiseVector(eta, &noiseSeed, 0);
        let mut error = self.noiseVector(eta, &noiseSeed, rank as u8);
        for polynomial in secret.iter_mut().chain(error.iter_mut()) {
            polynomial.transform();
        }
        let product = Self::matrixProduct(&matrix, &secret);
        let publicVector: Vec<Polynomial> = product
            .iter()
            .zip(&error)
            .map(|(left, right)| left.plus(right))
            .collect();
        let mut encryptionKey = vec![0u8; 384 * rank + 32];
        Self::encodedVector(&publicVector, 12, &mut encryptionKey[..384 * rank]);
        encryptionKey[384 * rank..].copy_from_slice(&publicSeed);
        let mut decryptionKey = vec![0u8; 384 * rank];
        Self::encodedVector(&secret, 12, &mut decryptionKey);
        (encryptionKey, decryptionKey)
    }

    /// `K-PKE.Encrypt` of FIPS 203, Algorithm 14: the ciphertext of a 32-byte message under an
    /// encryption key, with the 32-byte randomness `r`.
    pub(crate) fn encrypt(
        &self,
        encryptionKey: &[u8],
        message: &[u8; 32],
        randomness: &[u8; 32],
    ) -> Vec<u8> {
        let parameters = self.parameters;
        let rank = parameters.rank;
        let publicVector = Self::decodedVector(12, &encryptionKey[..384 * rank]);
        let publicSeed: [u8; 32] = encryptionKey[384 * rank..].try_into().expect("32 bytes");
        let transposed = self.matrix(&publicSeed, true);
        let mut ephemeral = self.noiseVector(parameters.firstEta, randomness, 0);
        let firstError = self.noiseVector(parameters.secondEta, randomness, rank as u8);
        let secondError =
            Polynomial::sampledCenteredBinomial(parameters.secondEta, randomness, 2 * rank as u8);
        for polynomial in ephemeral.iter_mut() {
            polynomial.transform();
        }
        let vectorPart: Vec<Polynomial> = Self::matrixProduct(&transposed, &ephemeral)
            .into_iter()
            .zip(&firstError)
            .map(|(mut polynomial, error)| {
                polynomial.inverseTransform();
                polynomial.plus(error)
            })
            .collect();
        let mut decodedMessage = Polynomial::decoded(1, message).decompressed(1);
        let mut inner = Self::innerProduct(&publicVector, &ephemeral);
        inner.inverseTransform();
        decodedMessage = inner.plus(&secondError).plus(&decodedMessage);
        let vectorLength = parameters.vectorPartLength();
        let mut ciphertext = vec![0u8; vectorLength + 32 * parameters.polynomialBits as usize];
        let compressedVector: Vec<Polynomial> = vectorPart
            .iter()
            .map(|polynomial| polynomial.compressed(parameters.vectorBits))
            .collect();
        Self::encodedVector(
            &compressedVector,
            parameters.vectorBits,
            &mut ciphertext[..vectorLength],
        );
        decodedMessage
            .compressed(parameters.polynomialBits)
            .encoded(parameters.polynomialBits, &mut ciphertext[vectorLength..]);
        ciphertext
    }

    /// `K-PKE.Decrypt` of FIPS 203, Algorithm 15: the 32-byte message of a ciphertext under a
    /// decryption key.
    pub(crate) fn decrypt(&self, decryptionKey: &[u8], ciphertext: &[u8]) -> [u8; 32] {
        let parameters = self.parameters;
        let vectorLength = parameters.vectorPartLength();
        let mut vectorPart: Vec<Polynomial> =
            Self::decodedVector(parameters.vectorBits, &ciphertext[..vectorLength])
                .iter()
                .map(|polynomial| polynomial.decompressed(parameters.vectorBits))
                .collect();
        let polynomialPart =
            Polynomial::decoded(parameters.polynomialBits, &ciphertext[vectorLength..])
                .decompressed(parameters.polynomialBits);
        let secret = Self::decodedVector(12, decryptionKey);
        for polynomial in vectorPart.iter_mut() {
            polynomial.transform();
        }
        let mut inner = Self::innerProduct(&secret, &vectorPart);
        inner.inverseTransform();
        let mut message = [0u8; 32];
        polynomialPart
            .minus(&inner)
            .compressed(1)
            .encoded(1, &mut message);
        message
    }
}
