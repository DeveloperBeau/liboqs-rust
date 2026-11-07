use OQSNativeEntities::KEMDescription;

/// The parameters of one HQC parameter set, `parameters.h` of the reference code.
pub(crate) struct Parameters {
    /// The length `n` of a vector in bits, which is also the degree of the modulus `X^n - 1`.
    pub(crate) vectorLength: usize,
    /// The length `n1` of the Reed-Solomon code in bytes.
    pub(crate) reedSolomonLength: usize,
    /// The length `n2` of the duplicated Reed-Muller code in bits.
    pub(crate) reedMullerLength: usize,
    /// The weight `omega` of the secret vectors `x` and `y`.
    pub(crate) secretWeight: usize,
    /// The weight `omega_e` of the error vector `e` of an encryption.
    pub(crate) errorWeight: usize,
    /// The weight `omega_r` of the vectors `r1` and `r2` of an encryption.
    pub(crate) randomnessWeight: usize,
    /// The length `k` of a message in bytes. It is the dimension of the Reed-Solomon code, the
    /// length of `sigma` and the security level in bytes.
    pub(crate) messageLength: usize,
    /// The correction capacity `delta` of the Reed-Solomon code.
    pub(crate) correctionCapacity: usize,
    /// The additive FFT works on `2^fftExponent` coefficients of the error locator polynomial.
    pub(crate) fftExponent: u32,
    /// The generator polynomial of the Reed-Solomon code, from the constant term up.
    pub(crate) generatorPolynomial: &'static [u8],
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: KEMDescription,
}

/// The version text of every HQC set in liboqs: the commit of the reference code.
const hqcVersion: &str = "https://gitlab.com/pqc-hqc/hqc@161cd4f";

/// The length of a seed in bytes, `SEED_BYTES`.
pub(crate) const seedLength: usize = 32;

/// The length of the salt of a ciphertext in bytes, `SALT_BYTES`.
pub(crate) const saltLength: usize = 16;

/// The length of a shared secret in bytes.
pub(crate) const sharedSecretLength: usize = 32;

impl Parameters {
    /// The facts of liboqs other than the lengths, which `withLengths` adds.
    const fn facts(name: &'static str, claimedNISTLevel: u8) -> KEMDescription {
        KEMDescription {
            name,
            algorithmVersion: hqcVersion,
            claimedNISTLevel,
            isINDCCASecure: true,
            publicKeyLength: 0,
            secretKeyLength: 0,
            ciphertextLength: 0,
            sharedSecretLength,
            keyPairSeedLength: 0,
            encapsulationSeedLength: 0,
        }
    }

    /// The parameters with the lengths of the keys and of the ciphertext, which follow from the
    /// other parameters.
    const fn withLengths(mut self) -> Self {
        let publicKeyLength = seedLength + self.vectorByteCount();
        self.description.publicKeyLength = publicKeyLength;
        self.description.secretKeyLength =
            publicKeyLength + seedLength + self.messageLength + seedLength;
        self.description.ciphertextLength =
            self.vectorByteCount() + self.codewordByteCount() + saltLength;
        self
    }

    /// The number of 64-bit words of a vector, `VEC_N_SIZE_64`.
    pub(crate) const fn vectorWordCount(&self) -> usize {
        self.vectorLength.div_ceil(64)
    }

    /// The number of bytes of an encoded vector, `VEC_N_SIZE_BYTES`.
    pub(crate) const fn vectorByteCount(&self) -> usize {
        self.vectorLength.div_ceil(8)
    }

    /// The length `n1 n2` of the concatenated code in bits.
    const fn codewordLength(&self) -> usize {
        self.reedSolomonLength * self.reedMullerLength
    }

    /// The number of 64-bit words of a codeword of the concatenated code, `VEC_N1N2_SIZE_64`.
    /// The length of each set is a multiple of 64.
    pub(crate) const fn codewordWordCount(&self) -> usize {
        self.codewordLength() / 64
    }

    /// The number of bytes of an encoded codeword, `VEC_N1N2_SIZE_BYTES`.
    pub(crate) const fn codewordByteCount(&self) -> usize {
        self.codewordLength() / 8
    }

    /// The number of copies of each 128-bit Reed-Muller codeword, `MULTIPLICITY`.
    pub(crate) const fn multiplicity(&self) -> usize {
        self.reedMullerLength / 128
    }

    /// The mask of the bits of the last word of a vector that are below `n`, `BITMASK`.
    pub(crate) const fn lastWordMask(&self) -> u64 {
        (1u64 << (self.vectorLength % 64)) - 1
    }

    /// The multiplier `floor(2^32 / n)` of the Barrett reduction, `PARAM_N_MU`.
    pub(crate) const fn barrettMultiplier(&self) -> u64 {
        (1u64 << 32) / self.vectorLength as u64
    }

    /// The bound `floor(2^24 / n) n` below which a 24-bit candidate position is kept,
    /// `UTILS_REJECTION_THRESHOLD`.
    pub(crate) const fn rejectionThreshold(&self) -> u32 {
        let vectorLength = self.vectorLength as u32;
        ((1u32 << 24) / vectorLength) * vectorLength
    }
}

/// HQC-1, `parameters.h` of `pqc-hqc_hqc-1_ref`.
pub(crate) const hqc1: Parameters = Parameters {
    vectorLength: 17669,
    reedSolomonLength: 46,
    reedMullerLength: 384,
    secretWeight: 66,
    errorWeight: 75,
    randomnessWeight: 75,
    messageLength: 16,
    correctionCapacity: 15,
    fftExponent: 4,
    generatorPolynomial: &[
        89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67,
        118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
    ],
    description: Parameters::facts("HQC-1", 1),
}
.withLengths();

/// HQC-3, `parameters.h` of `pqc-hqc_hqc-3_ref`.
pub(crate) const hqc3: Parameters = Parameters {
    vectorLength: 35851,
    reedSolomonLength: 56,
    reedMullerLength: 640,
    secretWeight: 100,
    errorWeight: 114,
    randomnessWeight: 114,
    messageLength: 24,
    correctionCapacity: 16,
    fftExponent: 5,
    generatorPolynomial: &[
        45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
        238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
    ],
    description: Parameters::facts("HQC-3", 3),
}
.withLengths();

/// HQC-5, `parameters.h` of `pqc-hqc_hqc-5_ref`.
pub(crate) const hqc5: Parameters = Parameters {
    vectorLength: 57637,
    reedSolomonLength: 90,
    reedMullerLength: 640,
    secretWeight: 131,
    errorWeight: 149,
    randomnessWeight: 149,
    messageLength: 32,
    correctionCapacity: 29,
    fftExponent: 5,
    generatorPolynomial: &[
        49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71,
        201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4,
        246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
    ],
    description: Parameters::facts("HQC-5", 5),
}
.withLengths();

#[cfg(test)]
mod tests {
    use super::{Parameters, hqc1, hqc3, hqc5};
    use crate::galoisField::GaloisField;

    const sets: [&Parameters; 3] = [&hqc1, &hqc3, &hqc5];

    #[test]
    fn lengthsAreTheLengthsOfTheLiboqsHeader() {
        // `kem_hqc.h` of liboqs: public key, secret key and ciphertext.
        let lengths = |parameters: &Parameters| {
            (
                parameters.description.publicKeyLength,
                parameters.description.secretKeyLength,
                parameters.description.ciphertextLength,
            )
        };
        assert_eq!(lengths(&hqc1), (2241, 2321, 4433));
        assert_eq!(lengths(&hqc3), (4514, 4602, 8978));
        assert_eq!(lengths(&hqc5), (7237, 7333, 14421));
        for parameters in sets {
            assert_eq!(parameters.description.sharedSecretLength, 32);
            assert_eq!(
                (
                    parameters.description.keyPairSeedLength,
                    parameters.description.encapsulationSeedLength
                ),
                (0, 0)
            );
        }
    }

    #[test]
    fn derivedValuesAreTheValuesOfParametersHeader() {
        // `PARAM_N_MU` and `UTILS_REJECTION_THRESHOLD` of each `parameters.h`.
        let derived = |parameters: &Parameters| {
            (
                parameters.barrettMultiplier(),
                parameters.rejectionThreshold(),
            )
        };
        assert_eq!(derived(&hqc1), (243_079, 16_767_881));
        assert_eq!(derived(&hqc3), (119_800, 16_742_417));
        assert_eq!(derived(&hqc5), (74_517, 16_772_367));
        let sizes = |parameters: &Parameters| {
            (
                parameters.vectorWordCount(),
                parameters.vectorByteCount(),
                parameters.codewordWordCount(),
                parameters.codewordByteCount(),
                parameters.multiplicity(),
            )
        };
        assert_eq!(sizes(&hqc1), (277, 2209, 276, 2208, 3));
        assert_eq!(sizes(&hqc3), (561, 4482, 560, 4480, 5));
        assert_eq!(sizes(&hqc5), (901, 7205, 900, 7200, 5));
        assert_eq!(hqc1.lastWordMask(), 0x1F);
        assert_eq!(hqc3.lastWordMask(), 0x7FF);
        assert_eq!(hqc5.lastWordMask(), (1 << 37) - 1);
    }

    #[test]
    fn eachSetHasAConsistentReedSolomonCode() {
        for parameters in sets {
            let parityLength = 2 * parameters.correctionCapacity;
            assert_eq!(parameters.generatorPolynomial.len(), parityLength + 1);
            assert_eq!(
                parameters.reedSolomonLength - parameters.messageLength,
                parityLength
            );
            // The error locator polynomial has at most `delta + 1` coefficients, and the FFT
            // takes the smallest power of two that holds them.
            let locatorLength = parameters.correctionCapacity + 1;
            assert!(1 << parameters.fftExponent >= locatorLength);
            assert!(1 << (parameters.fftExponent - 1) < locatorLength);
            assert_eq!(parameters.codewordLength() % 64, 0);
            assert_eq!(parameters.reedMullerLength % 128, 0);
            assert_ne!(parameters.vectorLength % 64, 0);
        }
    }

    #[test]
    fn generatorPolynomialHasTheRootsAlphaToTwiceDelta() {
        // The generator of a Reed-Solomon code with correction capacity `delta` is the product of
        // `X - alpha^i` for `i` from 1 to `2 delta`.
        for parameters in sets {
            let mut expected = vec![1u8];
            for exponent in 1..=2 * parameters.correctionCapacity {
                let root = GaloisField::power(exponent);
                let mut next = vec![0u8; expected.len() + 1];
                for (degree, coefficient) in expected.iter().enumerate() {
                    next[degree + 1] ^= coefficient;
                    next[degree] ^= GaloisField::product(*coefficient, root);
                }
                expected = next;
            }
            assert_eq!(
                parameters.generatorPolynomial,
                expected.as_slice(),
                "{}",
                parameters.description.name
            );
        }
    }
}
