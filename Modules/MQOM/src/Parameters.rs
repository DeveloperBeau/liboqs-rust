use crate::ExtensionField;
use OQSNativeEntities::SignatureDescription;

/// The parameters of one MQOM parameter set, as the header `mqom2_parameters_<set>.h` and the
/// build flags of `src/sig/mqom/CMakeLists.txt` of liboqs give them, and the facts of the set
/// as liboqs states them in `sig_mqom_mqom2_<set>.c`.
pub(crate) struct Parameters {
    /// The security level λ in bits: 128, 192 or 256.
    pub(crate) securityBits: usize,
    /// The extension field of the proof: GF(2^8) for the fast sets and GF(2^16) for the short
    /// sets.
    pub(crate) extensionField: ExtensionField,
    /// The number n of variables over GF(16), which is also the number m of equations.
    pub(crate) variableCount: usize,
    /// The number τ of parallel repetitions of the proof.
    pub(crate) repetitionCount: usize,
    /// The depth of each seed tree: the base 2 logarithm of the number N of evaluation points.
    pub(crate) treeDepth: usize,
    /// The number w of bits of the proof of work: a challenge stands when the w bits after
    /// the τ hidden leaves are zero.
    pub(crate) workBits: u32,
    /// True for the five-round variant, which combines the equations with a challenge matrix,
    /// the statistical batching of the C code.
    pub(crate) hasBatching: bool,
    /// The number η of extension elements of the masks u and of each polynomial value alpha:
    /// all m / µ equations for three rounds, and λ divided by the bits of the extension field
    /// for five rounds.
    pub(crate) eta: usize,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: SignatureDescription,
}

/// The length of the nonce of the proof of work at the end of a signature, in bytes.
pub(crate) const nonceLength: usize = 4;

impl Parameters {
    /// The length of a seed in bytes, λ / 8, which is also the length of the salt and the key
    /// length of the block cipher.
    pub(crate) const fn seedLength(&self) -> usize {
        self.securityBits / 8
    }

    /// The length of a digest in bytes, 2 λ / 8.
    pub(crate) const fn digestLength(&self) -> usize {
        2 * self.seedLength()
    }

    /// The number µ of elements of GF(16) in one element of the extension field.
    pub(crate) const fn extensionDegree(&self) -> usize {
        self.extensionField.bitCount() / 4
    }

    /// The number m / µ of equations over the extension field.
    pub(crate) const fn equationCount(&self) -> usize {
        self.variableCount / self.extensionDegree()
    }

    /// The number N of leaves of a seed tree, and of evaluation points.
    pub(crate) const fn leafCount(&self) -> usize {
        1 << self.treeDepth
    }

    /// The bytes of `count` elements of GF(16), two to a byte.
    pub(crate) const fn baseBytes(count: usize) -> usize {
        count / 2
    }

    /// The bytes of `count` elements of the extension field.
    pub(crate) const fn extensionBytes(&self, count: usize) -> usize {
        count * self.extensionField.byteCount()
    }

    /// The bytes of the secret vector x: n elements of GF(16).
    pub(crate) const fn variableBytes(&self) -> usize {
        Self::baseBytes(self.variableCount)
    }

    /// The bytes of one serialized polynomial value alpha, or of one mask: η extension
    /// elements.
    pub(crate) const fn maskBytes(&self) -> usize {
        self.extensionBytes(self.eta)
    }

    /// The bytes of the expansion of a leaf seed: the seed and the PRG output, which hold the
    /// share of x and the share of u.
    pub(crate) const fn leafExpansionBytes(&self) -> usize {
        self.variableBytes() + self.maskBytes()
    }

    /// The bytes that the PRG of a leaf seed gives after the seed, `PRG_BLC_SIZE`.
    pub(crate) const fn leafGeneratorBytes(&self) -> usize {
        self.leafExpansionBytes() - self.seedLength()
    }

    /// The bytes of the part of x + the sum of the shares that the opening of a repetition
    /// holds: all but the first λ / 8 bytes, which are zero.
    pub(crate) const fn partialDeltaBytes(&self) -> usize {
        self.variableBytes() - self.seedLength()
    }

    /// The length of the public key: the equation seed of 2 λ / 8 bytes and y.
    const fn publicKeyLength(&self) -> usize {
        2 * self.seedLength() + self.extensionBytes(self.equationCount())
    }

    /// The length of the opening of the line commitment: for each repetition, the sibling
    /// path of the hidden leaf, the commitment of the hidden leaf and the partial delta.
    pub(crate) const fn openingLength(&self) -> usize {
        self.repetitionCount
            * (self.treeDepth * self.seedLength() + self.digestLength() + self.partialDeltaBytes())
    }

    /// The length of a signature: the salt, the two commitments, τ serialized alpha1, the
    /// opening and the nonce, `MQOM2_SIG_SIZE`.
    const fn signatureLength(&self) -> usize {
        self.seedLength()
            + 2 * self.digestLength()
            + self.repetitionCount * self.maskBytes()
            + self.openingLength()
            + nonceLength
    }

    /// Makes the parameters of a set with the liboqs facts.
    #[allow(clippy::too_many_arguments)]
    const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        securityBits: usize,
        extensionField: ExtensionField,
        variableCount: usize,
        repetitionCount: usize,
        treeDepth: usize,
        workBits: u32,
        hasBatching: bool,
    ) -> Self {
        let eta = if hasBatching {
            securityBits / extensionField.bitCount()
        } else {
            variableCount / (extensionField.bitCount() / 4)
        };
        let mut parameters = Parameters {
            securityBits,
            extensionField,
            variableCount,
            repetitionCount,
            treeDepth,
            workBits,
            hasBatching,
            eta,
            description: SignatureDescription {
                name,
                algorithmVersion: "2.1",
                claimedNISTLevel,
                isEUFCMASecure: true,
                isSUFCMASecure: false,
                supportsContext: false,
                publicKeyLength: 0,
                secretKeyLength: 0,
                signatureLength: 0,
            },
        };
        parameters.description.publicKeyLength = parameters.publicKeyLength();
        parameters.description.secretKeyLength =
            parameters.publicKeyLength() + parameters.variableBytes();
        parameters.description.signatureLength = parameters.signatureLength();
        parameters
    }
}

// The twelve sets, in liboqs order. Each row gives the name, the NIST level, λ, the extension
// field, n, τ, the tree depth, w and the five-round flag.

/// `mqom2_cat1_gf16_fast_r3`, at the NIST level 1.
pub(crate) const mqom2Cat1GF16FastR3: Parameters = Parameters::new(
    "mqom2_cat1_gf16_fast_r3",
    1,
    128,
    ExtensionField::gf256,
    56,
    17,
    8,
    9,
    false,
);

/// `mqom2_cat1_gf16_fast_r5`, at the NIST level 1.
pub(crate) const mqom2Cat1GF16FastR5: Parameters = Parameters::new(
    "mqom2_cat1_gf16_fast_r5",
    1,
    128,
    ExtensionField::gf256,
    56,
    17,
    8,
    9,
    true,
);

/// `mqom2_cat1_gf16_short_r3`, at the NIST level 1.
pub(crate) const mqom2Cat1GF16ShortR3: Parameters = Parameters::new(
    "mqom2_cat1_gf16_short_r3",
    1,
    128,
    ExtensionField::gf65536,
    56,
    12,
    11,
    8,
    false,
);

/// `mqom2_cat1_gf16_short_r5`, at the NIST level 1.
pub(crate) const mqom2Cat1GF16ShortR5: Parameters = Parameters::new(
    "mqom2_cat1_gf16_short_r5",
    1,
    128,
    ExtensionField::gf65536,
    56,
    12,
    11,
    8,
    true,
);

/// `mqom2_cat3_gf16_fast_r3`, at the NIST level 3.
pub(crate) const mqom2Cat3GF16FastR3: Parameters = Parameters::new(
    "mqom2_cat3_gf16_fast_r3",
    3,
    192,
    ExtensionField::gf256,
    84,
    27,
    8,
    3,
    false,
);

/// `mqom2_cat3_gf16_fast_r5`, at the NIST level 3.
pub(crate) const mqom2Cat3GF16FastR5: Parameters = Parameters::new(
    "mqom2_cat3_gf16_fast_r5",
    3,
    192,
    ExtensionField::gf256,
    84,
    27,
    8,
    3,
    true,
);

/// `mqom2_cat3_gf16_short_r3`, at the NIST level 3.
pub(crate) const mqom2Cat3GF16ShortR3: Parameters = Parameters::new(
    "mqom2_cat3_gf16_short_r3",
    3,
    192,
    ExtensionField::gf65536,
    84,
    18,
    11,
    12,
    false,
);

/// `mqom2_cat3_gf16_short_r5`, at the NIST level 3.
pub(crate) const mqom2Cat3GF16ShortR5: Parameters = Parameters::new(
    "mqom2_cat3_gf16_short_r5",
    3,
    192,
    ExtensionField::gf65536,
    84,
    18,
    11,
    12,
    true,
);

/// `mqom2_cat5_gf16_fast_r3`, at the NIST level 5.
pub(crate) const mqom2Cat5GF16FastR3: Parameters = Parameters::new(
    "mqom2_cat5_gf16_fast_r3",
    5,
    256,
    ExtensionField::gf256,
    116,
    36,
    8,
    4,
    false,
);

/// `mqom2_cat5_gf16_fast_r5`, at the NIST level 5.
pub(crate) const mqom2Cat5GF16FastR5: Parameters = Parameters::new(
    "mqom2_cat5_gf16_fast_r5",
    5,
    256,
    ExtensionField::gf256,
    116,
    36,
    8,
    4,
    true,
);

/// `mqom2_cat5_gf16_short_r3`, at the NIST level 5.
pub(crate) const mqom2Cat5GF16ShortR3: Parameters = Parameters::new(
    "mqom2_cat5_gf16_short_r3",
    5,
    256,
    ExtensionField::gf65536,
    116,
    25,
    11,
    6,
    false,
);

/// `mqom2_cat5_gf16_short_r5`, at the NIST level 5.
pub(crate) const mqom2Cat5GF16ShortR5: Parameters = Parameters::new(
    "mqom2_cat5_gf16_short_r5",
    5,
    256,
    ExtensionField::gf65536,
    116,
    25,
    11,
    6,
    true,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testInputs::everySet;

    #[test]
    fn lengthsAreTheLengthsOfSigMQOMHeader() {
        // `src/sig/mqom/sig_mqom.h` of liboqs: the public key, the secret key and the
        // signature of each set.
        let expected = [
            (60, 88, 3484),
            (60, 88, 3280),
            (60, 88, 3060),
            (60, 88, 2916),
            (90, 132, 8224),
            (90, 132, 7738),
            (90, 132, 6820),
            (90, 132, 6496),
            (122, 180, 14708),
            (122, 180, 13772),
            (122, 180, 12664),
            (122, 180, 12014),
        ];
        for (parameters, lengths) in everySet().iter().zip(expected) {
            let description = &parameters.description;
            assert_eq!(
                (
                    description.publicKeyLength,
                    description.secretKeyLength,
                    description.signatureLength
                ),
                lengths,
                "{}",
                description.name
            );
        }
    }

    #[test]
    fn derivedValuesAreTheValuesOfTheParameterHeaders() {
        // MQOM2_PARAM_ETA is m / µ for three rounds and λ / log2 of the field size for five
        // rounds, and PRG_BLC_SIZE is the bytes of x and u less one seed.
        let expected = [
            (28, 28, 40),
            (16, 28, 28),
            (14, 14, 40),
            (8, 14, 28),
            (42, 42, 60),
            (24, 42, 42),
            (21, 21, 60),
            (12, 21, 42),
            (58, 58, 84),
            (32, 58, 58),
            (29, 29, 84),
            (16, 29, 58),
        ];
        for (parameters, (eta, equations, generatorBytes)) in everySet().iter().zip(expected) {
            let name = parameters.description.name;
            assert_eq!(parameters.eta, eta, "{name}");
            assert_eq!(parameters.equationCount(), equations, "{name}");
            assert_eq!(parameters.leafGeneratorBytes(), generatorBytes, "{name}");
            assert_eq!(parameters.digestLength(), 2 * parameters.seedLength());
        }
        assert_eq!(mqom2Cat1GF16FastR3.leafCount(), 256);
        assert_eq!(mqom2Cat5GF16ShortR5.leafCount(), 2048);
        assert_eq!(mqom2Cat3GF16ShortR3.extensionDegree(), 4);
        assert_eq!(mqom2Cat3GF16FastR3.extensionDegree(), 2);
    }

    #[test]
    fn eachSetHasTheFactsOfItsLiboqsFile() {
        for (index, parameters) in everySet().iter().enumerate() {
            let description = &parameters.description;
            let level = [1, 3, 5][index / 4];
            assert_eq!(description.claimedNISTLevel, level);
            assert_eq!(description.algorithmVersion, "2.1");
            assert!(description.isEUFCMASecure);
            assert!(!description.isSUFCMASecure);
            assert!(!description.supportsContext);
            assert_eq!(parameters.securityBits, [128, 192, 256][index / 4]);
            assert_eq!(parameters.hasBatching, index % 2 == 1);
        }
    }
}
