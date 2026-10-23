use crate::{Field, KeyForm};
use OQSNativeEntities::SignatureDescription;

/// The parameters of one UOV parameter set: `params.h` of the reference code with the macros
/// that the liboqs build sets, and the facts of the set as liboqs states them in
/// `src/sig/uov/sig_uov_ov_<set>.c`.
pub(crate) struct Parameters {
    /// The field of the elements.
    pub(crate) field: Field,
    /// The variables n of the public map, `_PUB_N`.
    pub(crate) variableCount: usize,
    /// The oil variables o, `_O`, which are as many as the equations m of the public map,
    /// `_PUB_M`.
    pub(crate) oilCount: usize,
    /// The form of the keys.
    pub(crate) form: KeyForm,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: SignatureDescription,
}

/// The length of the seed of a secret key, `LEN_SKSEED`.
pub(crate) const secretSeedLength: usize = 32;

/// The length of the seed of the public blocks, `LEN_PKSEED`.
pub(crate) const publicSeedLength: usize = 16;

/// The length of the salt of a signature, `_SALT_BYTE`.
pub(crate) const saltLength: usize = 16;

/// The version text of every UOV set in liboqs.
const version: &str = "Round 2";

/// The entries of an upper triangular matrix of a dimension, `N_TRIANGLE_TERMS`.
pub(crate) const fn triangleSize(dimension: usize) -> usize {
    dimension * (dimension + 1) / 2
}

impl Parameters {
    /// The vinegar variables v, `_V`.
    pub(crate) const fn vinegarCount(&self) -> usize {
        self.variableCount - self.oilCount
    }

    /// The bytes of a vector of a number of elements.
    const fn byteLength(&self, elementCount: usize) -> usize {
        elementCount / self.field.elementsPerByte()
    }

    /// The bytes of a vector of the vinegar values, `_V_BYTE`.
    pub(crate) const fn vinegarLength(&self) -> usize {
        self.byteLength(self.vinegarCount())
    }

    /// The bytes of a vector of the oil values, `_O_BYTE`. It is also the length of an entry
    /// of a block, which holds one element for each equation.
    pub(crate) const fn oilLength(&self) -> usize {
        self.byteLength(self.oilCount)
    }

    /// The bytes of the point w of a signature, `_PUB_N_BYTE`.
    pub(crate) const fn pointLength(&self) -> usize {
        self.byteLength(self.variableCount)
    }

    /// The bytes of the oil matrix O, `_V_BYTE * _O`: one column of v elements for each oil
    /// variable.
    pub(crate) const fn oilMatrixLength(&self) -> usize {
        self.vinegarLength() * self.oilCount
    }

    /// The bytes of the block P1 of the pairs of vinegar variables, `_PK_P1_BYTE`: an upper
    /// triangular matrix of v rows.
    pub(crate) const fn vinegarBlockLength(&self) -> usize {
        self.oilLength() * triangleSize(self.vinegarCount())
    }

    /// The bytes of the block P2 of a vinegar and an oil variable, `_PK_P2_BYTE`: a matrix of v
    /// rows and o columns. The block S of the secret key has the same shape.
    pub(crate) const fn mixedBlockLength(&self) -> usize {
        self.oilLength() * self.vinegarCount() * self.oilCount
    }

    /// The bytes of the block P3 of the pairs of oil variables, `_PK_P3_BYTE`: an upper
    /// triangular matrix of o rows.
    pub(crate) const fn oilBlockLength(&self) -> usize {
        self.oilLength() * triangleSize(self.oilCount)
    }

    /// The bytes of a classic secret key, `OV_SK_UNCOMPRESSED_BYTES`: the seed, the oil matrix
    /// O, the block P1 and the block S.
    pub(crate) const fn expandedSecretKeyLength(&self) -> usize {
        secretSeedLength
            + self.oilMatrixLength()
            + self.vinegarBlockLength()
            + self.mixedBlockLength()
    }

    /// The bytes of a classic public key, `OV_PK_UNCOMPRESSED_BYTES`: the blocks P1, P2 and P3.
    pub(crate) const fn expandedPublicKeyLength(&self) -> usize {
        self.vinegarBlockLength() + self.mixedBlockLength() + self.oilBlockLength()
    }

    /// The bytes of a compressed public key, `OV_PK_COMPRESSED_BYTES`: the public seed and the
    /// block P3.
    pub(crate) const fn compressedPublicKeyLength(&self) -> usize {
        publicSeedLength + self.oilBlockLength()
    }

    /// Makes the parameters of a set with the liboqs facts. UOV claims EUF-CMA only and signs
    /// without a context string.
    const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        field: Field,
        variableCount: usize,
        oilCount: usize,
        form: KeyForm,
    ) -> Self {
        let mut parameters = Parameters {
            field,
            variableCount,
            oilCount,
            form,
            description: SignatureDescription {
                name,
                algorithmVersion: version,
                claimedNISTLevel,
                isEUFCMASecure: true,
                isSUFCMASecure: false,
                supportsContext: false,
                publicKeyLength: 0,
                secretKeyLength: 0,
                signatureLength: 0,
            },
        };
        parameters.description.publicKeyLength = match form {
            KeyForm::classic => parameters.expandedPublicKeyLength(),
            KeyForm::compressedPublicKey | KeyForm::compressedKeys => {
                parameters.compressedPublicKeyLength()
            }
        };
        parameters.description.secretKeyLength = match form {
            KeyForm::classic | KeyForm::compressedPublicKey => parameters.expandedSecretKeyLength(),
            KeyForm::compressedKeys => secretSeedLength,
        };
        parameters.description.signatureLength = parameters.pointLength() + saltLength;
        parameters
    }
}

/// OV-Is: GF(16), 160 variables and 64 equations, at the NIST level 1.
pub(crate) const ovIs: Parameters =
    Parameters::new("OV-Is", 1, Field::gf16, 160, 64, KeyForm::classic);

/// OV-Ip: GF(256), 112 variables and 44 equations, at the NIST level 1.
pub(crate) const ovIp: Parameters =
    Parameters::new("OV-Ip", 1, Field::gf256, 112, 44, KeyForm::classic);

/// OV-III: GF(256), 184 variables and 72 equations, at the NIST level 3.
pub(crate) const ovIII: Parameters =
    Parameters::new("OV-III", 3, Field::gf256, 184, 72, KeyForm::classic);

/// OV-V: GF(256), 244 variables and 96 equations, at the NIST level 5.
pub(crate) const ovV: Parameters =
    Parameters::new("OV-V", 5, Field::gf256, 244, 96, KeyForm::classic);

/// OV-Is-pkc: OV-Is with a compressed public key.
pub(crate) const ovIsCompressedPublicKey: Parameters = Parameters::new(
    "OV-Is-pkc",
    1,
    Field::gf16,
    160,
    64,
    KeyForm::compressedPublicKey,
);

/// OV-Ip-pkc: OV-Ip with a compressed public key.
pub(crate) const ovIpCompressedPublicKey: Parameters = Parameters::new(
    "OV-Ip-pkc",
    1,
    Field::gf256,
    112,
    44,
    KeyForm::compressedPublicKey,
);

/// OV-III-pkc: OV-III with a compressed public key.
pub(crate) const ovIIICompressedPublicKey: Parameters = Parameters::new(
    "OV-III-pkc",
    3,
    Field::gf256,
    184,
    72,
    KeyForm::compressedPublicKey,
);

/// OV-V-pkc: OV-V with a compressed public key.
pub(crate) const ovVCompressedPublicKey: Parameters = Parameters::new(
    "OV-V-pkc",
    5,
    Field::gf256,
    244,
    96,
    KeyForm::compressedPublicKey,
);

/// OV-Is-pkc-skc: OV-Is with a compressed public key and a compressed secret key.
pub(crate) const ovIsCompressedKeys: Parameters = Parameters::new(
    "OV-Is-pkc-skc",
    1,
    Field::gf16,
    160,
    64,
    KeyForm::compressedKeys,
);

/// OV-Ip-pkc-skc: OV-Ip with a compressed public key and a compressed secret key.
pub(crate) const ovIpCompressedKeys: Parameters = Parameters::new(
    "OV-Ip-pkc-skc",
    1,
    Field::gf256,
    112,
    44,
    KeyForm::compressedKeys,
);

/// OV-III-pkc-skc: OV-III with a compressed public key and a compressed secret key.
pub(crate) const ovIIICompressedKeys: Parameters = Parameters::new(
    "OV-III-pkc-skc",
    3,
    Field::gf256,
    184,
    72,
    KeyForm::compressedKeys,
);

/// OV-V-pkc-skc: OV-V with a compressed public key and a compressed secret key.
pub(crate) const ovVCompressedKeys: Parameters = Parameters::new(
    "OV-V-pkc-skc",
    5,
    Field::gf256,
    244,
    96,
    KeyForm::compressedKeys,
);

/// The twelve sets in the order of the liboqs list.
#[cfg(test)]
pub(crate) const everySet: [&Parameters; 12] = [
    &ovIs,
    &ovIp,
    &ovIII,
    &ovV,
    &ovIsCompressedPublicKey,
    &ovIpCompressedPublicKey,
    &ovIIICompressedPublicKey,
    &ovVCompressedPublicKey,
    &ovIsCompressedKeys,
    &ovIpCompressedKeys,
    &ovIIICompressedKeys,
    &ovVCompressedKeys,
];

#[cfg(test)]
mod tests {
    use super::{everySet, ovIII, ovIp, ovIs, ovV, triangleSize};
    use crate::{Field, KeyForm};

    #[test]
    fn lengthsAreTheLengthsOfTheLiboqsHeader() {
        // `src/sig/uov/sig_uov.h` of liboqs 0.16.0: the public key, the secret key and the
        // signature of each set, in the liboqs order.
        let lengths = [
            (412160, 348704, 96),
            (278432, 237896, 128),
            (1225440, 1044320, 200),
            (2869440, 2436704, 260),
            (66576, 348704, 96),
            (43576, 237896, 128),
            (189232, 1044320, 200),
            (446992, 2436704, 260),
            (66576, 32, 96),
            (43576, 32, 128),
            (189232, 32, 200),
            (446992, 32, 260),
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
    fn derivedValuesAreTheValuesOfParamsH() {
        // v = n - m, and GF(16) packs two elements in a byte.
        assert_eq!(
            (ovIs.vinegarCount(), ovIs.vinegarLength(), ovIs.oilLength()),
            (96, 48, 32)
        );
        assert_eq!(
            (ovIp.vinegarCount(), ovIp.vinegarLength(), ovIp.oilLength()),
            (68, 68, 44)
        );
        assert_eq!((ovIII.vinegarCount(), ovV.vinegarCount()), (112, 148));
        assert_eq!((ovIs.pointLength(), ovV.pointLength()), (80, 244));
        assert_eq!(triangleSize(3), 6);
        // P1 of OV-Ip: 44 bytes for each of the 68 * 69 / 2 entries.
        assert_eq!(ovIp.vinegarBlockLength(), 44 * 2346);
        assert_eq!(ovIp.mixedBlockLength(), 44 * 68 * 44);
        assert_eq!(ovIp.oilBlockLength(), 44 * 990);
        assert_eq!(ovIp.oilMatrixLength(), 68 * 44);
    }

    #[test]
    fn eachSetHasTheFactsOfItsLiboqsFile() {
        let levels = [1, 1, 3, 5];
        let shapes = [
            (Field::gf16, 160, 64),
            (Field::gf256, 112, 44),
            (Field::gf256, 184, 72),
            (Field::gf256, 244, 96),
        ];
        let forms = [
            (KeyForm::classic, ""),
            (KeyForm::compressedPublicKey, "-pkc"),
            (KeyForm::compressedKeys, "-pkc-skc"),
        ];
        let names = ["OV-Is", "OV-Ip", "OV-III", "OV-V"];
        for (index, parameters) in everySet.into_iter().enumerate() {
            let (form, suffix) = forms[index / 4];
            let description = &parameters.description;
            assert_eq!(description.name, format!("{}{suffix}", names[index % 4]));
            assert_eq!(description.algorithmVersion, "Round 2");
            assert_eq!(description.claimedNISTLevel, levels[index % 4]);
            assert!(description.isEUFCMASecure && !description.isSUFCMASecure);
            assert!(!description.supportsContext);
            assert_eq!(
                (
                    parameters.field,
                    parameters.variableCount,
                    parameters.oilCount
                ),
                shapes[index % 4]
            );
            assert_eq!(parameters.form, form);
        }
    }
}
