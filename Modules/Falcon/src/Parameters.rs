use OQSNativeEntities::SignatureDescription;

/// The parameters of one Falcon parameter set, with the facts of its liboqs file
/// `src/sig/falcon/sig_falcon_<name>.c`.
pub(crate) struct Parameters {
    /// The binary logarithm of the degree `N`: 9 for Falcon-512 and 10 for Falcon-1024.
    pub(crate) logn: u32,
    /// True for the padded sets, whose signatures always have the full length.
    pub(crate) isPadded: bool,
    /// The length of a padded signature of the degree. A verification of either form accepts
    /// a compressed value of this length when zeros pad it, as the PQClean code in liboqs does.
    pub(crate) paddedSignatureLength: usize,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: SignatureDescription,
}

/// The version text of every Falcon set in liboqs.
const version: &str = "20211101 with PQClean patches";

impl Parameters {
    /// Makes the parameters of a set with the liboqs facts. Falcon claims EUF-CMA only and signs
    /// without a context string.
    const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        logn: u32,
        isPadded: bool,
        lengths: (usize, usize, usize),
        paddedSignatureLength: usize,
    ) -> Self {
        let (publicKeyLength, secretKeyLength, signatureLength) = lengths;
        Parameters {
            logn,
            isPadded,
            paddedSignatureLength,
            description: SignatureDescription {
                name,
                algorithmVersion: version,
                claimedNISTLevel,
                isEUFCMASecure: true,
                isSUFCMASecure: false,
                supportsContext: false,
                publicKeyLength,
                secretKeyLength,
                signatureLength,
            },
        }
    }
}

/// Falcon-512 with compressed signatures of at most 752 bytes.
pub(crate) const falcon512: Parameters =
    Parameters::new("Falcon-512", 1, 9, false, (897, 1281, 752), 666);

/// Falcon-1024 with compressed signatures of at most 1462 bytes.
pub(crate) const falcon1024: Parameters =
    Parameters::new("Falcon-1024", 5, 10, false, (1793, 2305, 1462), 1280);

/// Falcon-512 with signatures padded to 666 bytes.
pub(crate) const falconPadded512: Parameters =
    Parameters::new("Falcon-padded-512", 1, 9, true, (897, 1281, 666), 666);

/// Falcon-1024 with signatures padded to 1280 bytes.
pub(crate) const falconPadded1024: Parameters =
    Parameters::new("Falcon-padded-1024", 5, 10, true, (1793, 2305, 1280), 1280);

#[cfg(test)]
mod tests {
    use super::{falcon512, falcon1024, falconPadded512, falconPadded1024};
    use crate::encoding::{largePolynomialBits, smallPolynomialBits};

    #[test]
    fn keyLengthsAreTheLengthsOfTheirEncodings() {
        // The public key is a header byte and 14 bits for each coefficient. The secret key is a
        // header byte, f and g in their trimmed width and F in 8 bits.
        for parameters in [&falcon512, &falcon1024, &falconPadded512, &falconPadded1024] {
            let n = 1usize << parameters.logn;
            let description = &parameters.description;
            assert_eq!(
                description.publicKeyLength,
                1 + 14 * n / 8,
                "{}",
                description.name
            );
            let smallBits = smallPolynomialBits[parameters.logn as usize] as usize;
            let largeBits = largePolynomialBits[parameters.logn as usize] as usize;
            assert_eq!(
                description.secretKeyLength,
                1 + (2 * smallBits + largeBits) * n / 8,
                "{}",
                description.name
            );
        }
    }

    #[test]
    fn paddedSetsShareTheKeysOfTheCompressedSets() {
        for (compressed, padded) in [
            (&falcon512, &falconPadded512),
            (&falcon1024, &falconPadded1024),
        ] {
            assert_eq!(compressed.logn, padded.logn);
            assert_eq!(
                compressed.description.publicKeyLength,
                padded.description.publicKeyLength
            );
            assert_eq!(
                compressed.description.secretKeyLength,
                padded.description.secretKeyLength
            );
            assert_eq!(
                compressed.paddedSignatureLength,
                padded.description.signatureLength
            );
            assert!(!compressed.isPadded && padded.isPadded);
            assert!(compressed.description.signatureLength > padded.description.signatureLength);
        }
    }
}
