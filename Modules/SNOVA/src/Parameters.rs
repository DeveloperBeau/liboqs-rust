use crate::publicKeyExpansion::PublicKeyExpansion;
use crate::secretKeyForm::SecretKeyForm;
use OQSNativeEntities::SignatureDescription;

/// The parameters of one SNOVA set and its liboqs facts.
///
/// liboqs compiles one C code for every set, with the switches `v_SNOVA`, `o_SNOVA`, `l_SNOVA`,
/// `PK_EXPAND_SHAKE` and `sk_is_seed` of `src/sig/snova/CMakeLists.txt`, and `deriv_params.h`
/// derives every size from them. The facts of a set come from `sig_snova_<set>.c` and the
/// lengths from `sig_snova.h`.
pub(crate) struct Parameters {
    /// The number v of vinegar variables.
    pub(crate) vinegarCount: usize,
    /// The number o of oil variables, which is also the number m of equations.
    pub(crate) oilCount: usize,
    /// The rank l of the matrices over GF(16).
    pub(crate) rank: usize,
    /// The expansion of the public seed.
    pub(crate) publicKeyExpansion: PublicKeyExpansion,
    /// The form of the secret key.
    pub(crate) secretKeyForm: SecretKeyForm,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: SignatureDescription,
}

/// The length of the public seed, `seed_length_public`.
pub(crate) const publicSeedLength: usize = 16;

/// The length of the secret seed, `seed_length_private`.
pub(crate) const secretSeedLength: usize = 32;

/// The length of the salt of a signature, `bytes_salt`.
pub(crate) const saltLength: usize = 16;

/// The length of the digest of the message that the scheme signs, `SNOVA_BYTES_DIGEST` of
/// `oqs_snova.c`.
pub(crate) const digestLength: usize = 64;

/// The version text of every SNOVA set in liboqs.
const version: &str = "round2";

impl Parameters {
    /// The number n of variables, `v + o`.
    pub(crate) const fn variableCount(&self) -> usize {
        self.vinegarCount + self.oilCount
    }

    /// The number of elements of a matrix, `l^2`.
    pub(crate) const fn squaredRank(&self) -> usize {
        self.rank * self.rank
    }

    /// The number alpha of terms of each equation, `l^2 + l`.
    pub(crate) const fn termCount(&self) -> usize {
        self.rank * self.rank + self.rank
    }

    /// True for the ranks below 4, whose matrices A, B, Q1 and Q2 come from a fixed seed and
    /// not from the public seed, `FIXED_ABQ`.
    pub(crate) const fn hasFixedMatrices(&self) -> bool {
        self.rank < 4
    }

    /// The number of elements of the expansion of the public seed, `GF16s_prng_public`: the
    /// matrices A and B, P11, P12 and P21, and `l` coefficients for each of Q1 and Q2.
    pub(crate) const fn publicMapElementCount(&self) -> usize {
        let equationCount = self.oilCount;
        let termCount = self.termCount();
        let variableCount = self.variableCount();
        self.squaredRank()
            * (2 * equationCount * termCount
                + equationCount * (variableCount * variableCount - equationCount * equationCount))
            + self.rank * 2 * equationCount * termCount
    }

    /// The number of coefficients of the matrices Q1 and Q2 at the end of the expansion of the
    /// public seed, `sizeof(Q_temp)`.
    pub(crate) const fn coefficientCountOfQ(&self) -> usize {
        2 * self.oilCount * self.termCount() * self.rank
    }

    /// The length of the signed hash, `bytes_hash`: `o l^2` elements.
    pub(crate) const fn signedHashLength(&self) -> usize {
        (self.oilCount * self.squaredRank()).div_ceil(2)
    }

    /// The number of elements of a signature without its salt, `GF16s_signature`.
    pub(crate) const fn signatureElementCount(&self) -> usize {
        self.variableCount() * self.squaredRank()
    }

    /// The length of a signature without its salt, `bytes_signature`.
    pub(crate) const fn packedSignatureLength(&self) -> usize {
        self.signatureElementCount().div_ceil(2)
    }

    /// The length of a public key, `bytes_pk`: the public seed and the matrices P22.
    const fn publicKeyLength(oilCount: usize, rank: usize) -> usize {
        publicSeedLength + (oilCount * oilCount * oilCount * rank * rank).div_ceil(2)
    }

    /// The number of elements of an expanded secret key, before its seeds: the matrices A, B,
    /// Q1 and Q2, T12, F11, F12 and F21.
    const fn expandedSecretElementCount(
        vinegarCount: usize,
        oilCount: usize,
        rank: usize,
    ) -> usize {
        let termCount = rank * rank + rank;
        rank * rank
            * (4 * oilCount * termCount
                + oilCount
                    * (vinegarCount * vinegarCount
                        + vinegarCount * oilCount
                        + oilCount * vinegarCount)
                + vinegarCount * oilCount)
    }

    /// The number of elements of the expanded secret key, before its seeds.
    pub(crate) const fn expandedSecretKeyElementCount(&self) -> usize {
        Self::expandedSecretElementCount(self.vinegarCount, self.oilCount, self.rank)
    }

    /// Makes the parameters of a set with the liboqs facts. SNOVA claims EUF-CMA only and signs
    /// without a context string.
    const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        (vinegarCount, oilCount, rank): (usize, usize, usize),
        publicKeyExpansion: PublicKeyExpansion,
        secretKeyForm: SecretKeyForm,
    ) -> Self {
        let secretKeyLength = match secretKeyForm {
            SecretKeyForm::seeds => publicSeedLength + secretSeedLength,
            SecretKeyForm::expanded => {
                Self::expandedSecretElementCount(vinegarCount, oilCount, rank).div_ceil(2)
                    + publicSeedLength
                    + secretSeedLength
            }
        };
        Parameters {
            vinegarCount,
            oilCount,
            rank,
            publicKeyExpansion,
            secretKeyForm,
            description: SignatureDescription {
                name,
                algorithmVersion: version,
                claimedNISTLevel,
                isEUFCMASecure: true,
                isSUFCMASecure: false,
                supportsContext: false,
                publicKeyLength: Self::publicKeyLength(oilCount, rank),
                secretKeyLength,
                signatureLength: ((vinegarCount + oilCount) * rank * rank).div_ceil(2) + saltLength,
            },
        }
    }
}

/// SNOVA_24_5_4: v = 24, o = 5, l = 4, at the NIST level 1.
pub(crate) const snova24x5x4: Parameters = Parameters::new(
    "SNOVA_24_5_4",
    1,
    (24, 5, 4),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::seeds,
);

/// SNOVA_24_5_4_SHAKE: SNOVA_24_5_4 with the public seed expanded by SHAKE128.
pub(crate) const snova24x5x4SHAKE: Parameters = Parameters::new(
    "SNOVA_24_5_4_SHAKE",
    1,
    (24, 5, 4),
    PublicKeyExpansion::shake128Counter,
    SecretKeyForm::seeds,
);

/// SNOVA_24_5_4_esk: SNOVA_24_5_4 with the expanded secret key.
pub(crate) const snova24x5x4WithExpandedSecretKey: Parameters = Parameters::new(
    "SNOVA_24_5_4_esk",
    1,
    (24, 5, 4),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::expanded,
);

/// SNOVA_24_5_4_SHAKE_esk: SNOVA_24_5_4 with SHAKE128 and the expanded secret key.
pub(crate) const snova24x5x4SHAKEWithExpandedSecretKey: Parameters = Parameters::new(
    "SNOVA_24_5_4_SHAKE_esk",
    1,
    (24, 5, 4),
    PublicKeyExpansion::shake128Counter,
    SecretKeyForm::expanded,
);

/// SNOVA_37_17_2: v = 37, o = 17, l = 2, at the NIST level 1.
pub(crate) const snova37x17x2: Parameters = Parameters::new(
    "SNOVA_37_17_2",
    1,
    (37, 17, 2),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::seeds,
);

/// SNOVA_25_8_3: v = 25, o = 8, l = 3, at the NIST level 1.
pub(crate) const snova25x8x3: Parameters = Parameters::new(
    "SNOVA_25_8_3",
    1,
    (25, 8, 3),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::seeds,
);

/// SNOVA_56_25_2: v = 56, o = 25, l = 2, at the NIST level 3.
pub(crate) const snova56x25x2: Parameters = Parameters::new(
    "SNOVA_56_25_2",
    3,
    (56, 25, 2),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::seeds,
);

/// SNOVA_49_11_3: v = 49, o = 11, l = 3, at the NIST level 3.
pub(crate) const snova49x11x3: Parameters = Parameters::new(
    "SNOVA_49_11_3",
    3,
    (49, 11, 3),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::seeds,
);

/// SNOVA_37_8_4: v = 37, o = 8, l = 4, at the NIST level 3.
pub(crate) const snova37x8x4: Parameters = Parameters::new(
    "SNOVA_37_8_4",
    3,
    (37, 8, 4),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::seeds,
);

/// SNOVA_24_5_5: v = 24, o = 5, l = 5, at the NIST level 3.
pub(crate) const snova24x5x5: Parameters = Parameters::new(
    "SNOVA_24_5_5",
    3,
    (24, 5, 5),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::seeds,
);

/// SNOVA_60_10_4: v = 60, o = 10, l = 4, at the NIST level 5.
pub(crate) const snova60x10x4: Parameters = Parameters::new(
    "SNOVA_60_10_4",
    5,
    (60, 10, 4),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::seeds,
);

/// SNOVA_29_6_5: v = 29, o = 6, l = 5, at the NIST level 5.
pub(crate) const snova29x6x5: Parameters = Parameters::new(
    "SNOVA_29_6_5",
    5,
    (29, 6, 5),
    PublicKeyExpansion::aes128Counter,
    SecretKeyForm::seeds,
);

/// Every set, in the order of the liboqs list.
#[cfg(test)]
pub(crate) const everySet: [&Parameters; 12] = [
    &snova24x5x4,
    &snova24x5x4SHAKE,
    &snova24x5x4WithExpandedSecretKey,
    &snova24x5x4SHAKEWithExpandedSecretKey,
    &snova37x17x2,
    &snova25x8x3,
    &snova56x25x2,
    &snova49x11x3,
    &snova37x8x4,
    &snova24x5x5,
    &snova60x10x4,
    &snova29x6x5,
];

#[cfg(test)]
mod tests {
    use super::{everySet, snova24x5x4, snova49x11x3};

    #[test]
    fn lengthsAreTheLengthsOfSigSNOVAH() {
        // `src/sig/snova/sig_snova.h` of liboqs.
        let lengths = [
            (1016, 48, 248),
            (1016, 48, 248),
            (1016, 36848, 248),
            (1016, 36848, 248),
            (9842, 48, 124),
            (2320, 48, 165),
            (31266, 48, 178),
            (6006, 48, 286),
            (4112, 48, 376),
            (1579, 48, 379),
            (8016, 48, 576),
            (2716, 48, 454),
        ];
        for (parameters, expected) in everySet.into_iter().zip(lengths) {
            let description = &parameters.description;
            assert_eq!(
                (
                    description.publicKeyLength,
                    description.secretKeyLength,
                    description.signatureLength
                ),
                expected,
                "{}",
                description.name
            );
        }
    }

    #[test]
    fn derivedSizesAreTheSizesOfDerivParamsH() {
        // v = 24, o = 5, l = 4: n = 29, alpha = 20, and the public expansion has
        // 16 (2 * 5 * 20 + 5 (29^2 - 5^2)) + 4 * 2 * 5 * 20 = 69280 elements.
        let parameters = &snova24x5x4;
        assert_eq!(
            (
                parameters.variableCount(),
                parameters.termCount(),
                parameters.publicMapElementCount(),
                parameters.coefficientCountOfQ(),
                parameters.signedHashLength(),
                parameters.packedSignatureLength(),
                parameters.expandedSecretKeyElementCount(),
            ),
            (29, 20, 69280, 800, 40, 232, 73600)
        );
        // v = 49, o = 11, l = 3: o l^2 = 99 elements of the hash fill 50 bytes, and
        // n l^2 = 540 elements of the signature 270 bytes.
        let parameters = &snova49x11x3;
        assert_eq!(
            (
                parameters.termCount(),
                parameters.signedHashLength(),
                parameters.packedSignatureLength(),
            ),
            (12, 50, 270)
        );
        assert!(parameters.hasFixedMatrices() && !snova24x5x4.hasFixedMatrices());
    }

    #[test]
    fn eachSetHasTheFactsOfItsLiboqsFile() {
        let facts = [
            ("SNOVA_24_5_4", 1),
            ("SNOVA_24_5_4_SHAKE", 1),
            ("SNOVA_24_5_4_esk", 1),
            ("SNOVA_24_5_4_SHAKE_esk", 1),
            ("SNOVA_37_17_2", 1),
            ("SNOVA_25_8_3", 1),
            ("SNOVA_56_25_2", 3),
            ("SNOVA_49_11_3", 3),
            ("SNOVA_37_8_4", 3),
            ("SNOVA_24_5_5", 3),
            ("SNOVA_60_10_4", 5),
            ("SNOVA_29_6_5", 5),
        ];
        for (parameters, (name, level)) in everySet.into_iter().zip(facts) {
            let description = &parameters.description;
            assert_eq!(description.name, name);
            assert_eq!(description.algorithmVersion, "round2");
            assert_eq!(description.claimedNISTLevel, level, "{name}");
            assert!(description.isEUFCMASecure && !description.isSUFCMASecure);
            assert!(!description.supportsContext);
        }
    }
}
