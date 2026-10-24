use OQSNativeEntities::SignatureDescription;

/// The parameters of one MAYO parameter set, as `mayo.h` of the MAYO team states them, and the
/// facts of the set as liboqs states them in `sig_mayo_<n>.c`.
pub(crate) struct Parameters {
    /// The number m of polynomials of the public map, and so of elements in each packed vector.
    pub(crate) equationCount: usize,
    /// The number n of variables of the public map.
    pub(crate) variableCount: usize,
    /// The number o of oil variables: the dimension of the oil space.
    pub(crate) oilCount: usize,
    /// The whipping parameter k: the number of vectors s_i in a signature.
    pub(crate) vectorCount: usize,
    /// The coefficients of z^0 to z^3 of the polynomial f(z) = z^m + ... that reduces the
    /// combined equations of a signature, as the `F_TAIL` arrays of `mayo.h` give them.
    pub(crate) reductionTail: [u8; 4],
    /// The length of the salt of a signature in bytes.
    pub(crate) saltLength: usize,
    /// The length of the digest of a message in bytes.
    pub(crate) digestLength: usize,
    /// The length of the secret seed in bytes, which is the whole secret key.
    pub(crate) secretSeedLength: usize,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: SignatureDescription,
}

/// The length of the public seed in bytes, the key of the AES-128 expansion of P1 and P2.
pub(crate) const publicSeedLength: usize = 16;

impl Parameters {
    /// The number v = n - o of vinegar variables.
    pub(crate) const fn vinegarCount(&self) -> usize {
        self.variableCount - self.oilCount
    }

    /// The number of 64-bit words of a packed vector of m elements, 16 elements to a word.
    pub(crate) const fn limbCount(&self) -> usize {
        self.equationCount.div_ceil(16)
    }

    /// The number of columns of the linear system of a signature attempt: the k o unknowns and
    /// the right-hand side.
    pub(crate) const fn systemColumnCount(&self) -> usize {
        self.vectorCount * self.oilCount + 1
    }

    /// The bytes of a packed vector of m elements in a key: two elements to a byte.
    pub(crate) const fn vectorBytes(&self) -> usize {
        self.equationCount / 2
    }

    /// The number of entries of the upper triangular v by v matrix P1.
    pub(crate) const fn p1Count(&self) -> usize {
        let vinegarCount = self.vinegarCount();
        vinegarCount * (vinegarCount + 1) / 2
    }

    /// The number of entries of the v by o matrix P2.
    pub(crate) const fn p2Count(&self) -> usize {
        self.vinegarCount() * self.oilCount
    }

    /// The bytes of the oil space O in the expansion of the secret seed.
    pub(crate) const fn oilBytes(&self) -> usize {
        (self.vinegarCount() * self.oilCount).div_ceil(2)
    }

    /// The bytes of one vinegar vector in the hash output of a signature attempt.
    pub(crate) const fn vinegarBytes(&self) -> usize {
        self.vinegarCount().div_ceil(2)
    }

    /// The bytes of the randomizer r of the solution in the hash output of a signature attempt.
    pub(crate) const fn randomizerBytes(&self) -> usize {
        (self.vectorCount * self.oilCount).div_ceil(2)
    }

    /// The length of a public key: the public seed and the packed upper triangle of P3.
    const fn publicKeyLength(equationCount: usize, oilCount: usize) -> usize {
        publicSeedLength + oilCount * (oilCount + 1) / 2 * (equationCount / 2)
    }

    /// The length of a signature: the k n elements of s and the salt.
    const fn signatureLength(variableCount: usize, vectorCount: usize, saltLength: usize) -> usize {
        (vectorCount * variableCount).div_ceil(2) + saltLength
    }

    /// Makes the parameters of a set with the liboqs facts.
    #[allow(clippy::too_many_arguments)]
    const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        equationCount: usize,
        variableCount: usize,
        oilCount: usize,
        vectorCount: usize,
        reductionTail: [u8; 4],
        saltLength: usize,
        digestLength: usize,
        secretSeedLength: usize,
    ) -> Self {
        Parameters {
            equationCount,
            variableCount,
            oilCount,
            vectorCount,
            reductionTail,
            saltLength,
            digestLength,
            secretSeedLength,
            description: SignatureDescription {
                name,
                algorithmVersion: "round2",
                claimedNISTLevel,
                isEUFCMASecure: true,
                isSUFCMASecure: false,
                supportsContext: false,
                publicKeyLength: Self::publicKeyLength(equationCount, oilCount),
                secretKeyLength: secretSeedLength,
                signatureLength: Self::signatureLength(variableCount, vectorCount, saltLength),
            },
        }
    }
}

/// MAYO-1 of `mayo.h`, at the NIST level 1 that liboqs claims. f(z) is
/// `z^78 + z^2 + z + x^3`.
pub(crate) const mayo1: Parameters =
    Parameters::new("MAYO-1", 1, 78, 86, 8, 10, [8, 1, 1, 0], 24, 32, 24);

/// MAYO-2 of `mayo.h`, at the NIST level 1 that liboqs claims. f(z) is
/// `z^64 + x^3 z^3 + x z^2 + x^3`.
pub(crate) const mayo2: Parameters =
    Parameters::new("MAYO-2", 1, 64, 81, 17, 4, [8, 0, 2, 8], 24, 32, 24);

/// MAYO-3 of `mayo.h`, at the NIST level 3 that liboqs claims. f(z) is
/// `z^108 + (x^2 + x + 1) z^3 + z^2 + x^3`.
pub(crate) const mayo3: Parameters =
    Parameters::new("MAYO-3", 3, 108, 118, 10, 11, [8, 0, 1, 7], 32, 48, 32);

/// MAYO-5 of `mayo.h`, at the NIST level 5 that liboqs claims. f(z) is
/// `z^142 + z^3 + x^3 z^2 + x^2`.
pub(crate) const mayo5: Parameters =
    Parameters::new("MAYO-5", 5, 142, 154, 12, 12, [4, 0, 8, 1], 40, 64, 40);

#[cfg(test)]
mod tests {
    use super::{Parameters, mayo1, mayo2, mayo3, mayo5, publicSeedLength};

    const parameterSets: [&Parameters; 4] = [&mayo1, &mayo2, &mayo3, &mayo5];

    #[test]
    fn lengthsAreTheLengthsOfLiboqs() {
        let lengths = |parameters: &Parameters| {
            let description = &parameters.description;
            (
                description.publicKeyLength,
                description.secretKeyLength,
                description.signatureLength,
            )
        };
        // `sig_mayo.h` of liboqs and `api.h` of each upstream folder.
        assert_eq!(lengths(&mayo1), (1420, 24, 454));
        assert_eq!(lengths(&mayo2), (4912, 24, 186));
        assert_eq!(lengths(&mayo3), (2986, 32, 681));
        assert_eq!(lengths(&mayo5), (5554, 40, 964));
    }

    #[test]
    fn derivedValuesAreTheValuesOfTheMAYOHeader() {
        // `m_vec_limbs`, `m_bytes`, `O_bytes`, `v_bytes`, `r_bytes`, `P1_bytes`, `P2_bytes` and
        // `P3_bytes` of each set in `mayo.h`.
        let expected = [
            (5, 39, 312, 39, 40, 120_159, 24_336, 1404),
            (4, 32, 544, 32, 34, 66_560, 34_816, 4896),
            (7, 54, 540, 54, 55, 317_844, 58_320, 2970),
            (9, 71, 852, 71, 72, 720_863, 120_984, 5538),
        ];
        for (parameters, values) in parameterSets.iter().zip(expected) {
            let bytes = parameters.vectorBytes();
            assert_eq!(
                (
                    parameters.limbCount(),
                    bytes,
                    parameters.oilBytes(),
                    parameters.vinegarBytes(),
                    parameters.randomizerBytes(),
                    parameters.p1Count() * bytes,
                    parameters.p2Count() * bytes,
                    parameters.description.publicKeyLength - publicSeedLength,
                ),
                values,
                "{}",
                parameters.description.name
            );
        }
        assert_eq!(
            parameterSets.map(|parameters| parameters.systemColumnCount()),
            [81, 69, 111, 145]
        );
        assert_eq!(
            parameterSets.map(|parameters| parameters.vinegarCount()),
            [78, 64, 108, 142]
        );
    }

    #[test]
    fn eachSetHasTheFactsOfItsLiboqsFile() {
        for (parameters, name, level) in [
            (&mayo1, "MAYO-1", 1),
            (&mayo2, "MAYO-2", 1),
            (&mayo3, "MAYO-3", 3),
            (&mayo5, "MAYO-5", 5),
        ] {
            let description = &parameters.description;
            assert_eq!(description.name, name);
            assert_eq!(description.algorithmVersion, "round2");
            assert_eq!(description.claimedNISTLevel, level);
            assert!(description.isEUFCMASecure);
            assert!(!description.isSUFCMASecure);
            assert!(!description.supportsContext);
        }
    }
}
