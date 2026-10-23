use crate::{LevelType, OneTimeSignatureType, ParameterSet, TreeType};
use OQSNativeEntities::StatefulSignatureDescription;

/// The length of the hashes of the parameter sets of liboqs, n = 32 for SHA-256.
pub(crate) const hashLength: usize = 32;

/// The length of the identifier I of a tree.
pub(crate) const identifierLength: usize = 16;

/// The length of the seed of a tree.
pub(crate) const seedLength: usize = 32;

/// The largest number of levels of an HSS key that hash-sigs reads.
pub(crate) const maximumLevelCount: usize = 8;

/// The length of the parameter set in a private key: one byte for each level.
pub(crate) const parameterSetLength: usize = maximumLevelCount;

/// The length of the private key of hash-sigs, `PRIVATE_KEY_LEN` with the seed method of
/// liboqs: the count, the parameter set, the seed and the identifier I of the top tree.
pub(crate) const privateKeyLength: usize = 8 + parameterSetLength + seedLength + identifierLength;

/// The length of the aux data of a key pair, `DEFAULT_AUX_DATA` of `sig_stfl_lms_functions.c`.
pub(crate) const auxiliaryDataLength: usize = 10916;

/// The length of an HSS public key: the level count and the LMS public key of the top tree.
pub(crate) const publicKeyLength: usize = 4 + LevelType::publicKeyLength;

/// The version text of every LMS set of liboqs, `sig->alg_version` of `sig_stfl_lms.c`.
const algorithmVersion: &str = "https://datatracker.ietf.org/doc/html/rfc8554";

/// One LMS parameter set of liboqs: the types of its levels, the top level first, and the facts
/// of the set as `sig_stfl_lms.c` and `sig_stfl_lms.h` state them.
pub(crate) struct Parameters {
    /// The types of the levels, the top level first.
    pub(crate) levels: &'static [LevelType],
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: StatefulSignatureDescription,
}

impl Parameters {
    /// Makes the parameters of a set with the liboqs facts. Every set of liboqs claims
    /// EUF-CMA and not SUF-CMA, and has the public key of 60 bytes and the private key length
    /// of 64 bytes.
    const fn new(name: &'static str, levels: &'static [LevelType]) -> Self {
        let parameterSet = ParameterSet::new(levels);
        Parameters {
            levels,
            description: StatefulSignatureDescription {
                objectIdentifier: parameterSet.objectIdentifier(),
                name,
                algorithmVersion,
                isEUFCMASecure: true,
                isSUFCMASecure: false,
                publicKeyLength,
                secretKeyLength: privateKeyLength,
                signatureLength: parameterSet.signatureLength(),
            },
        }
    }
}

/// The type of a level.
const fn level(tree: TreeType, oneTimeSignature: OneTimeSignatureType) -> LevelType {
    LevelType::new(tree, oneTimeSignature)
}

use OneTimeSignatureType::{winternitz1, winternitz2, winternitz4, winternitz8};
use TreeType::{height5, height10, height15, height20, height25};

/// `LMS_SHA256_H5_W1`.
pub(crate) const lmsSHA256H5W1: Parameters =
    Parameters::new("LMS_SHA256_H5_W1", &[level(height5, winternitz1)]);
/// `LMS_SHA256_H5_W2`.
pub(crate) const lmsSHA256H5W2: Parameters =
    Parameters::new("LMS_SHA256_H5_W2", &[level(height5, winternitz2)]);
/// `LMS_SHA256_H5_W4`.
pub(crate) const lmsSHA256H5W4: Parameters =
    Parameters::new("LMS_SHA256_H5_W4", &[level(height5, winternitz4)]);
/// `LMS_SHA256_H5_W8`.
pub(crate) const lmsSHA256H5W8: Parameters =
    Parameters::new("LMS_SHA256_H5_W8", &[level(height5, winternitz8)]);
/// `LMS_SHA256_H10_W1`.
pub(crate) const lmsSHA256H10W1: Parameters =
    Parameters::new("LMS_SHA256_H10_W1", &[level(height10, winternitz1)]);
/// `LMS_SHA256_H10_W2`.
pub(crate) const lmsSHA256H10W2: Parameters =
    Parameters::new("LMS_SHA256_H10_W2", &[level(height10, winternitz2)]);
/// `LMS_SHA256_H10_W4`.
pub(crate) const lmsSHA256H10W4: Parameters =
    Parameters::new("LMS_SHA256_H10_W4", &[level(height10, winternitz4)]);
/// `LMS_SHA256_H10_W8`.
pub(crate) const lmsSHA256H10W8: Parameters =
    Parameters::new("LMS_SHA256_H10_W8", &[level(height10, winternitz8)]);
/// `LMS_SHA256_H15_W1`.
pub(crate) const lmsSHA256H15W1: Parameters =
    Parameters::new("LMS_SHA256_H15_W1", &[level(height15, winternitz1)]);
/// `LMS_SHA256_H15_W2`.
pub(crate) const lmsSHA256H15W2: Parameters =
    Parameters::new("LMS_SHA256_H15_W2", &[level(height15, winternitz2)]);
/// `LMS_SHA256_H15_W4`.
pub(crate) const lmsSHA256H15W4: Parameters =
    Parameters::new("LMS_SHA256_H15_W4", &[level(height15, winternitz4)]);
/// `LMS_SHA256_H15_W8`.
pub(crate) const lmsSHA256H15W8: Parameters =
    Parameters::new("LMS_SHA256_H15_W8", &[level(height15, winternitz8)]);
/// `LMS_SHA256_H20_W1`.
pub(crate) const lmsSHA256H20W1: Parameters =
    Parameters::new("LMS_SHA256_H20_W1", &[level(height20, winternitz1)]);
/// `LMS_SHA256_H20_W2`.
pub(crate) const lmsSHA256H20W2: Parameters =
    Parameters::new("LMS_SHA256_H20_W2", &[level(height20, winternitz2)]);
/// `LMS_SHA256_H20_W4`.
pub(crate) const lmsSHA256H20W4: Parameters =
    Parameters::new("LMS_SHA256_H20_W4", &[level(height20, winternitz4)]);
/// `LMS_SHA256_H20_W8`.
pub(crate) const lmsSHA256H20W8: Parameters =
    Parameters::new("LMS_SHA256_H20_W8", &[level(height20, winternitz8)]);
/// `LMS_SHA256_H25_W1`.
pub(crate) const lmsSHA256H25W1: Parameters =
    Parameters::new("LMS_SHA256_H25_W1", &[level(height25, winternitz1)]);
/// `LMS_SHA256_H25_W2`.
pub(crate) const lmsSHA256H25W2: Parameters =
    Parameters::new("LMS_SHA256_H25_W2", &[level(height25, winternitz2)]);
/// `LMS_SHA256_H25_W4`.
pub(crate) const lmsSHA256H25W4: Parameters =
    Parameters::new("LMS_SHA256_H25_W4", &[level(height25, winternitz4)]);
/// `LMS_SHA256_H25_W8`.
pub(crate) const lmsSHA256H25W8: Parameters =
    Parameters::new("LMS_SHA256_H25_W8", &[level(height25, winternitz8)]);
/// `LMS_SHA256_H5_W8_H5_W8`, the parameter set of Test Case 1 of RFC 8554, Appendix F.
pub(crate) const lmsSHA256H5W8H5W8: Parameters = Parameters::new(
    "LMS_SHA256_H5_W8_H5_W8",
    &[level(height5, winternitz8), level(height5, winternitz8)],
);
/// `LMS_SHA256_H10_W4_H5_W8`, the parameter set of Test Case 2 of RFC 8554, Appendix F.
pub(crate) const lmsSHA256H10W4H5W8: Parameters = Parameters::new(
    "LMS_SHA256_H10_W4_H5_W8",
    &[level(height10, winternitz4), level(height5, winternitz8)],
);
/// `LMS_SHA256_H10_W8_H5_W8`.
pub(crate) const lmsSHA256H10W8H5W8: Parameters = Parameters::new(
    "LMS_SHA256_H10_W8_H5_W8",
    &[level(height10, winternitz8), level(height5, winternitz8)],
);
/// `LMS_SHA256_H10_W2_H10_W2`.
pub(crate) const lmsSHA256H10W2H10W2: Parameters = Parameters::new(
    "LMS_SHA256_H10_W2_H10_W2",
    &[level(height10, winternitz2), level(height10, winternitz2)],
);
/// `LMS_SHA256_H10_W4_H10_W4`.
pub(crate) const lmsSHA256H10W4H10W4: Parameters = Parameters::new(
    "LMS_SHA256_H10_W4_H10_W4",
    &[level(height10, winternitz4), level(height10, winternitz4)],
);
/// `LMS_SHA256_H10_W8_H10_W8`.
pub(crate) const lmsSHA256H10W8H10W8: Parameters = Parameters::new(
    "LMS_SHA256_H10_W8_H10_W8",
    &[level(height10, winternitz8), level(height10, winternitz8)],
);
/// `LMS_SHA256_H15_W8_H5_W8`.
pub(crate) const lmsSHA256H15W8H5W8: Parameters = Parameters::new(
    "LMS_SHA256_H15_W8_H5_W8",
    &[level(height15, winternitz8), level(height5, winternitz8)],
);
/// `LMS_SHA256_H15_W8_H10_W8`.
pub(crate) const lmsSHA256H15W8H10W8: Parameters = Parameters::new(
    "LMS_SHA256_H15_W8_H10_W8",
    &[level(height15, winternitz8), level(height10, winternitz8)],
);
/// `LMS_SHA256_H15_W8_H15_W8`.
pub(crate) const lmsSHA256H15W8H15W8: Parameters = Parameters::new(
    "LMS_SHA256_H15_W8_H15_W8",
    &[level(height15, winternitz8), level(height15, winternitz8)],
);
/// `LMS_SHA256_H20_W8_H5_W8`.
pub(crate) const lmsSHA256H20W8H5W8: Parameters = Parameters::new(
    "LMS_SHA256_H20_W8_H5_W8",
    &[level(height20, winternitz8), level(height5, winternitz8)],
);
/// `LMS_SHA256_H20_W8_H10_W8`.
pub(crate) const lmsSHA256H20W8H10W8: Parameters = Parameters::new(
    "LMS_SHA256_H20_W8_H10_W8",
    &[level(height20, winternitz8), level(height10, winternitz8)],
);
/// `LMS_SHA256_H20_W8_H15_W8`.
pub(crate) const lmsSHA256H20W8H15W8: Parameters = Parameters::new(
    "LMS_SHA256_H20_W8_H15_W8",
    &[level(height20, winternitz8), level(height15, winternitz8)],
);
/// `LMS_SHA256_H20_W8_H20_W8`.
pub(crate) const lmsSHA256H20W8H20W8: Parameters = Parameters::new(
    "LMS_SHA256_H20_W8_H20_W8",
    &[level(height20, winternitz8), level(height20, winternitz8)],
);

/// Every parameter set, in the order of `OQS_SIG_STFL_alg_identifier` of liboqs.
#[cfg(test)]
pub(crate) const allParameters: [&Parameters; 33] = [
    &lmsSHA256H5W1,
    &lmsSHA256H5W2,
    &lmsSHA256H5W4,
    &lmsSHA256H5W8,
    &lmsSHA256H10W1,
    &lmsSHA256H10W2,
    &lmsSHA256H10W4,
    &lmsSHA256H10W8,
    &lmsSHA256H15W1,
    &lmsSHA256H15W2,
    &lmsSHA256H15W4,
    &lmsSHA256H15W8,
    &lmsSHA256H20W1,
    &lmsSHA256H20W2,
    &lmsSHA256H20W4,
    &lmsSHA256H20W8,
    &lmsSHA256H25W1,
    &lmsSHA256H25W2,
    &lmsSHA256H25W4,
    &lmsSHA256H25W8,
    &lmsSHA256H5W8H5W8,
    &lmsSHA256H10W4H5W8,
    &lmsSHA256H10W8H5W8,
    &lmsSHA256H10W2H10W2,
    &lmsSHA256H10W4H10W4,
    &lmsSHA256H10W8H10W8,
    &lmsSHA256H15W8H5W8,
    &lmsSHA256H15W8H10W8,
    &lmsSHA256H15W8H15W8,
    &lmsSHA256H20W8H5W8,
    &lmsSHA256H20W8H10W8,
    &lmsSHA256H20W8H15W8,
    &lmsSHA256H20W8H20W8,
];

#[cfg(test)]
mod tests {
    use super::allParameters;

    #[test]
    fn eachSetHasTheIdentifierAndTheLengthsOfItsLiboqsDefinitions() {
        // The `OQS_LMS_ID_*` and `*_length_signature` definitions of `sig_stfl_lms.h`, in the
        // order of `OQS_SIG_STFL_alg_identifier`.
        let expected: [(&str, u32, usize); 33] = [
            ("LMS_SHA256_H5_W1", 0x0151, 8688),
            ("LMS_SHA256_H5_W2", 0x0152, 4464),
            ("LMS_SHA256_H5_W4", 0x0153, 2352),
            ("LMS_SHA256_H5_W8", 0x0154, 1296),
            ("LMS_SHA256_H10_W1", 0x0161, 8848),
            ("LMS_SHA256_H10_W2", 0x0162, 4624),
            ("LMS_SHA256_H10_W4", 0x0163, 2512),
            ("LMS_SHA256_H10_W8", 0x0164, 1456),
            ("LMS_SHA256_H15_W1", 0x0171, 9008),
            ("LMS_SHA256_H15_W2", 0x0172, 4784),
            ("LMS_SHA256_H15_W4", 0x0173, 2672),
            ("LMS_SHA256_H15_W8", 0x0174, 1616),
            ("LMS_SHA256_H20_W1", 0x0181, 9168),
            ("LMS_SHA256_H20_W2", 0x0182, 4944),
            ("LMS_SHA256_H20_W4", 0x0183, 2832),
            ("LMS_SHA256_H20_W8", 0x0184, 1776),
            ("LMS_SHA256_H25_W1", 0x0191, 9328),
            ("LMS_SHA256_H25_W2", 0x0192, 5104),
            ("LMS_SHA256_H25_W4", 0x0193, 2992),
            ("LMS_SHA256_H25_W8", 0x0194, 1936),
            ("LMS_SHA256_H5_W8_H5_W8", 0x02_5454, 2644),
            ("LMS_SHA256_H10_W4_H5_W8", 0x02_6354, 3860),
            ("LMS_SHA256_H10_W8_H5_W8", 0x02_6454, 2804),
            ("LMS_SHA256_H10_W2_H10_W2", 0x02_6262, 9300),
            ("LMS_SHA256_H10_W4_H10_W4", 0x02_6363, 5076),
            ("LMS_SHA256_H10_W8_H10_W8", 0x02_6464, 2964),
            ("LMS_SHA256_H15_W8_H5_W8", 0x02_7454, 2964),
            ("LMS_SHA256_H15_W8_H10_W8", 0x02_7464, 3124),
            ("LMS_SHA256_H15_W8_H15_W8", 0x02_7474, 3284),
            ("LMS_SHA256_H20_W8_H5_W8", 0x02_8454, 3124),
            ("LMS_SHA256_H20_W8_H10_W8", 0x02_8464, 3284),
            ("LMS_SHA256_H20_W8_H15_W8", 0x02_8474, 3444),
            ("LMS_SHA256_H20_W8_H20_W8", 0x02_8484, 3604),
        ];
        for (parameters, (name, identifier, signatureLength)) in allParameters.iter().zip(expected)
        {
            let description = &parameters.description;
            assert_eq!(description.name, name);
            assert_eq!(description.objectIdentifier, identifier, "{name}");
            assert_eq!(description.signatureLength, signatureLength, "{name}");
            assert_eq!(
                (description.publicKeyLength, description.secretKeyLength),
                (60, 64),
                "{name}"
            );
            assert_eq!(
                description.algorithmVersion,
                "https://datatracker.ietf.org/doc/html/rfc8554"
            );
            assert!(description.isEUFCMASecure && !description.isSUFCMASecure);
        }
    }
}
