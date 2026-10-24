use crate::{MultiplicationMethod, Variant};
use OQSNativeEntities::KEMDescription;

/// The parameters of one parameter set, `params.h` of its PQClean folder, and the liboqs facts
/// of the set.
pub(crate) struct Parameters {
    /// The number `n` of coefficients of a polynomial, `NTRU_N`, a prime. The ring is
    /// `Z[x] / (x^n - 1)`.
    pub(crate) coefficientCount: usize,
    /// The bits of the modulus `q = 2^logq`, `NTRU_LOGQ`.
    pub(crate) modulusBits: u32,
    /// NTRU-HPS or NTRU-HRSS.
    pub(crate) variant: Variant,
    /// The method of the product in the ring modulo `2^16`.
    pub(crate) multiplicationMethod: MultiplicationMethod,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: KEMDescription,
}

/// The version text of every NTRU set in liboqs.
const algorithmVersion: &str =
    "https://github.com/jschanck/ntru/tree/6d96ed37 reference implementation";

impl Parameters {
    /// The length of the key of the implicit rejection, `NTRU_PRFKEYBYTES`.
    pub(crate) const rejectionKeyLength: usize = 32;

    /// The length of a shared secret, `NTRU_SHAREDKEYBYTES`.
    pub(crate) const sharedSecretLength: usize = 32;

    /// The modulus `q`, `NTRU_Q`.
    pub(crate) const fn modulus(&self) -> u16 {
        1 << self.modulusBits
    }

    /// The number of coefficients 1 plus the number of coefficients -1 of a polynomial of a
    /// fixed type, `NTRU_WEIGHT = q / 8 - 2`. Only NTRU-HPS uses it.
    pub(crate) const fn weight(&self) -> u16 {
        self.modulus() / 8 - 2
    }

    /// The number of coefficients that a packing holds, `NTRU_PACK_DEG = n - 1`. The last
    /// coefficient follows from the others.
    pub(crate) const fn packedCoefficientCount(&self) -> usize {
        self.coefficientCount - 1
    }

    /// The length of a packed polynomial modulo 3, five coefficients in each byte,
    /// `NTRU_PACK_TRINARY_BYTES`.
    pub(crate) const fn ternaryLength(&self) -> usize {
        Self::ternaryLengthOf(self.coefficientCount)
    }

    /// The length of a packed polynomial modulo `q`: the public key and the ciphertext,
    /// `NTRU_OWCPA_PUBLICKEYBYTES` and `NTRU_OWCPA_BYTES`.
    pub(crate) const fn packedLength(&self) -> usize {
        Self::packedLengthOf(self.coefficientCount, self.modulusBits)
    }

    /// The length of the packed blinding polynomial `r` and message `m` of an encryption,
    /// `NTRU_OWCPA_MSGBYTES`.
    pub(crate) const fn messageLength(&self) -> usize {
        2 * self.ternaryLength()
    }

    /// The length of the secret key of the encryption scheme: `f` and `f^-1` modulo 3, and
    /// `h^-1` modulo `q`, `NTRU_OWCPA_SECRETKEYBYTES`.
    pub(crate) const fn encryptionSecretKeyLength(&self) -> usize {
        Self::encryptionSecretKeyLengthOf(self.coefficientCount, self.modulusBits)
    }

    /// The bytes of a sample with independent coefficients, one byte for each coefficient
    /// below `n - 1`, `NTRU_SAMPLE_IID_BYTES`.
    pub(crate) const fn independentSampleLength(&self) -> usize {
        self.coefficientCount - 1
    }

    /// The bytes of a sample of a fixed type, 30 bits for each coefficient below `n - 1`,
    /// `NTRU_SAMPLE_FT_BYTES`.
    pub(crate) const fn fixedTypeSampleLength(&self) -> usize {
        (30 * (self.coefficientCount - 1)).div_ceil(8)
    }

    /// The bytes of one random request of a key pair or of an encapsulation,
    /// `NTRU_SAMPLE_FG_BYTES` and `NTRU_SAMPLE_RM_BYTES`: a sample with independent
    /// coefficients, and then a sample of a fixed type for NTRU-HPS or a second sample with
    /// independent coefficients for NTRU-HRSS.
    pub(crate) const fn sampleLength(&self) -> usize {
        self.independentSampleLength()
            + match self.variant {
                Variant::hps => self.fixedTypeSampleLength(),
                Variant::hrss => self.independentSampleLength(),
            }
    }

    const fn ternaryLengthOf(coefficientCount: usize) -> usize {
        (coefficientCount - 1).div_ceil(5)
    }

    const fn packedLengthOf(coefficientCount: usize, modulusBits: u32) -> usize {
        (modulusBits as usize * (coefficientCount - 1)).div_ceil(8)
    }

    const fn encryptionSecretKeyLengthOf(coefficientCount: usize, modulusBits: u32) -> usize {
        2 * Self::ternaryLengthOf(coefficientCount)
            + Self::packedLengthOf(coefficientCount, modulusBits)
    }

    /// Makes the parameters of a set with the liboqs facts of `kem_ntru_<set>.c`. liboqs gives
    /// NTRU no seeded forms.
    const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        coefficientCount: usize,
        modulusBits: u32,
        variant: Variant,
        multiplicationMethod: MultiplicationMethod,
    ) -> Self {
        let packedLength = Self::packedLengthOf(coefficientCount, modulusBits);
        Parameters {
            coefficientCount,
            modulusBits,
            variant,
            multiplicationMethod,
            description: KEMDescription {
                name,
                algorithmVersion,
                claimedNISTLevel,
                isINDCCASecure: true,
                publicKeyLength: packedLength,
                secretKeyLength: Self::encryptionSecretKeyLengthOf(coefficientCount, modulusBits)
                    + Self::rejectionKeyLength,
                ciphertextLength: packedLength,
                sharedSecretLength: Self::sharedSecretLength,
                keyPairSeedLength: 0,
                encapsulationSeedLength: 0,
            },
        }
    }
}

/// NTRU-HPS-2048-509, `pqclean_ntruhps2048509_clean`.
pub(crate) const ntruHPS2048509: Parameters = Parameters::new(
    "NTRU-HPS-2048-509",
    1,
    509,
    11,
    Variant::hps,
    MultiplicationMethod::toomCook,
);

/// NTRU-HPS-2048-677, `pqclean_ntruhps2048677_clean`.
pub(crate) const ntruHPS2048677: Parameters = Parameters::new(
    "NTRU-HPS-2048-677",
    3,
    677,
    11,
    Variant::hps,
    MultiplicationMethod::toomCook,
);

/// NTRU-HPS-4096-821, `pqclean_ntruhps4096821_clean`.
pub(crate) const ntruHPS4096821: Parameters = Parameters::new(
    "NTRU-HPS-4096-821",
    5,
    821,
    12,
    Variant::hps,
    MultiplicationMethod::toomCook,
);

/// NTRU-HPS-4096-1229, `pqclean_ntruhps40961229_clean`.
pub(crate) const ntruHPS40961229: Parameters = Parameters::new(
    "NTRU-HPS-4096-1229",
    5,
    1229,
    12,
    Variant::hps,
    MultiplicationMethod::toomCook,
);

/// NTRU-HRSS-701, `pqclean_ntruhrss701_clean`.
pub(crate) const ntruHRSS701: Parameters = Parameters::new(
    "NTRU-HRSS-701",
    3,
    701,
    13,
    Variant::hrss,
    MultiplicationMethod::toomCook,
);

/// NTRU-HRSS-1373, `pqclean_ntruhrss1373_clean`.
pub(crate) const ntruHRSS1373: Parameters = Parameters::new(
    "NTRU-HRSS-1373",
    5,
    1373,
    14,
    Variant::hrss,
    MultiplicationMethod::karatsuba,
);

#[cfg(test)]
mod tests {
    use super::{
        Parameters, ntruHPS2048509, ntruHPS2048677, ntruHPS4096821, ntruHPS40961229, ntruHRSS701,
        ntruHRSS1373,
    };

    const everySet: [&Parameters; 6] = [
        &ntruHPS2048509,
        &ntruHPS2048677,
        &ntruHPS4096821,
        &ntruHPS40961229,
        &ntruHRSS701,
        &ntruHRSS1373,
    ];

    #[test]
    fn lengthsAreTheLengthsOfTheLiboqsHeader() {
        // `kem_ntru.h`: the public key, the secret key and the ciphertext of each set.
        let expected = [
            (699, 935, 699),
            (930, 1234, 930),
            (1230, 1590, 1230),
            (1842, 2366, 1842),
            (1138, 1450, 1138),
            (2401, 2983, 2401),
        ];
        for (parameters, lengths) in everySet.into_iter().zip(expected) {
            let description = &parameters.description;
            assert_eq!(
                (
                    description.publicKeyLength,
                    description.secretKeyLength,
                    description.ciphertextLength
                ),
                lengths,
                "{}",
                description.name
            );
            assert_eq!(description.sharedSecretLength, 32);
        }
    }

    #[test]
    fn sampleLengthsAreTheLengthsOfParamsH() {
        // `NTRU_SAMPLE_FG_BYTES`: n - 1 bytes and ceil(30 (n - 1) / 8) bytes for NTRU-HPS, and
        // 2 (n - 1) bytes for NTRU-HRSS.
        let expected = [2413, 3211, 3895, 5833, 1400, 2744];
        for (parameters, length) in everySet.into_iter().zip(expected) {
            assert_eq!(
                parameters.sampleLength(),
                length,
                "{}",
                parameters.description.name
            );
        }
        assert_eq!(ntruHPS2048509.fixedTypeSampleLength(), 1905);
        assert_eq!(ntruHPS40961229.independentSampleLength(), 1228);
    }

    #[test]
    fn packedLengthsAndTheWeightFollowFromTheParameters() {
        // NTRU_PACK_TRINARY_BYTES = ceil((n - 1) / 5), NTRU_WEIGHT = q / 8 - 2.
        let ternaryLengths = [102, 136, 164, 246, 140, 275];
        for (parameters, length) in everySet.into_iter().zip(ternaryLengths) {
            assert_eq!(parameters.ternaryLength(), length);
            assert_eq!(parameters.messageLength(), 2 * length);
            assert_eq!(
                parameters.encryptionSecretKeyLength() + Parameters::rejectionKeyLength,
                parameters.description.secretKeyLength
            );
        }
        assert_eq!(ntruHPS2048509.weight(), 254);
        assert_eq!(ntruHPS4096821.weight(), 510);
        assert_eq!(ntruHRSS701.modulus(), 8192);
        assert_eq!(ntruHRSS1373.modulus(), 16384);
    }
}
