use crate::galoisField::GaloisField;
use OQSNativeEntities::KEMDescription;
use core::ops::Range;

/// The parameters of one Classic McEliece parameter set, as `params.h` of the C code gives
/// them, with the liboqs facts of the set.
pub(crate) struct Parameters {
    /// The bits `m` of an element of the field GF(2^m), `GFBITS`.
    pub(crate) fieldBits: u32,
    /// The code length `n`, `SYS_N`.
    pub(crate) codeLength: usize,
    /// The error weight `t`, `SYS_T`, which is also the degree of the Goppa polynomial.
    pub(crate) errorWeight: usize,
    /// The terms below `y^t` of the field polynomial of GF((2^m)^t), each as an exponent and a
    /// coefficient in GF(2^m). `GF_mul` of `gf.c` replaces `y^t` by their sum.
    pub(crate) reductionTerms: &'static [(usize, u16)],
    /// True for the `f` sets, whose key generation finds the public key in semi-systematic
    /// form with the pivot search of `pk_gen.c`.
    pub(crate) isSemiSystematic: bool,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: KEMDescription,
}

/// The version text of every set in liboqs.
const algorithmVersion: &str = "SUPERCOP-20221025";

impl Parameters {
    /// The length of the random request of a key pair, and of the seed at the start of a
    /// secret key.
    pub(crate) const seedLength: usize = 32;

    /// The length of the field `c` of the pivots in a secret key, which follows the seed.
    pub(crate) const pivotsLength: usize = 8;

    /// The length of a shared secret.
    pub(crate) const sharedSecretLength: usize = 32;

    /// The bytes of the control bits of the Benes network, `COND_BYTES`: `(2 m - 1) 2^(m - 4)`.
    const fn controlBitsLengthOf(fieldBits: u32) -> usize {
        (1 << (fieldBits - 4)) * (2 * fieldBits as usize - 1)
    }

    /// Makes the parameters of a set with the liboqs facts.
    const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        fieldBits: u32,
        codeLength: usize,
        errorWeight: usize,
        reductionTerms: &'static [(usize, u16)],
        isSemiSystematic: bool,
    ) -> Self {
        let rowCount = fieldBits as usize * errorWeight;
        Parameters {
            fieldBits,
            codeLength,
            errorWeight,
            reductionTerms,
            isSemiSystematic,
            description: KEMDescription {
                name,
                algorithmVersion,
                claimedNISTLevel,
                isINDCCASecure: true,
                publicKeyLength: rowCount * (codeLength - rowCount).div_ceil(8),
                secretKeyLength: Self::seedLength
                    + Self::pivotsLength
                    + 2 * errorWeight
                    + Self::controlBitsLengthOf(fieldBits)
                    + codeLength / 8,
                ciphertextLength: rowCount.div_ceil(8),
                sharedSecretLength: Self::sharedSecretLength,
                keyPairSeedLength: 0,
                encapsulationSeedLength: 0,
            },
        }
    }

    /// The field GF(2^m) of the set.
    pub(crate) const fn field(&self) -> GaloisField {
        GaloisField::new(self.fieldBits)
    }

    /// The number of elements of the field, `2^m`.
    pub(crate) const fn fieldSize(&self) -> usize {
        1 << self.fieldBits
    }

    /// The rows of the parity-check matrix, `PK_NROWS`: `m t`.
    pub(crate) const fn rowCount(&self) -> usize {
        self.fieldBits as usize * self.errorWeight
    }

    /// The bytes of each row of the public key, `PK_ROW_BYTES`: the `n - m t` columns after the
    /// identity part, in whole bytes.
    pub(crate) const fn publicKeyRowLength(&self) -> usize {
        (self.codeLength - self.rowCount()).div_ceil(8)
    }

    /// The bytes of an error vector of `n` bits.
    pub(crate) const fn errorVectorLength(&self) -> usize {
        self.codeLength / 8
    }

    /// The bits of the last byte of a ciphertext and of a row of the public key that are not
    /// padding, or zero when the rows end on a whole byte. Only `m t` of the 6960119 sets is not
    /// a multiple of 8.
    pub(crate) const fn rowTail(&self) -> u32 {
        (self.rowCount() % 8) as u32
    }

    /// The bytes of the control bits in a secret key, `COND_BYTES`.
    pub(crate) const fn controlBitsLength(&self) -> usize {
        Self::controlBitsLengthOf(self.fieldBits)
    }

    /// The bytes of the Goppa polynomial in a secret key, `IRR_BYTES`: `t` coefficients of two
    /// bytes each.
    pub(crate) const fn goppaPolynomialLength(&self) -> usize {
        2 * self.errorWeight
    }

    /// The bytes of the Goppa polynomial in a secret key.
    pub(crate) const fn goppaPolynomialRange(&self) -> Range<usize> {
        let start = Self::seedLength + Self::pivotsLength;
        start..start + self.goppaPolynomialLength()
    }

    /// The bytes of the control bits of the Benes network in a secret key.
    pub(crate) const fn controlBitsRange(&self) -> Range<usize> {
        let start = self.goppaPolynomialRange().end;
        start..start + self.controlBitsLength()
    }

    /// The bytes of the rejection value `s` in a secret key, which a failed decryption hashes
    /// in place of the error vector.
    pub(crate) const fn rejectionValueRange(&self) -> Range<usize> {
        let start = self.controlBitsRange().end;
        start..start + self.errorVectorLength()
    }

    /// The bytes of the SHAKE256 output of one attempt of key generation: `s`, the 32-bit values
    /// of the permutation, the element of GF((2^m)^t) and the seed of the next attempt.
    pub(crate) const fn expandedSeedLength(&self) -> usize {
        self.errorVectorLength() + 4 * self.fieldSize() + 2 * self.errorWeight + Self::seedLength
    }

    /// True when every value of `m` bits is a position of the code, so that an error vector
    /// takes its `t` positions as they are. Only the 8192128 sets have `n = 2^m`.
    pub(crate) const fn isFullLength(&self) -> bool {
        self.codeLength == self.fieldSize()
    }

    /// The bytes of the random request of one attempt of the error vector: `t` values of two
    /// bytes when the code has full length, and else `2 t` candidates, as `gen_e` of
    /// `encrypt.c` draws them.
    pub(crate) const fn errorRequestLength(&self) -> usize {
        if self.isFullLength() {
            2 * self.errorWeight
        } else {
            4 * self.errorWeight
        }
    }
}

/// The field polynomial `y^64 + y^3 + y + z` of the 348864 sets.
const terms348864: &[(usize, u16)] = &[(3, 1), (1, 1), (0, 2)];

/// The field polynomial `y^96 + y^10 + y^9 + y^6 + 1` of the 460896 sets.
const terms460896: &[(usize, u16)] = &[(10, 1), (9, 1), (6, 1), (0, 1)];

/// The field polynomial `y^128 + y^7 + y^2 + y + 1` of the 6688128 and 8192128 sets.
const terms128: &[(usize, u16)] = &[(7, 1), (2, 1), (1, 1), (0, 1)];

/// The field polynomial `y^119 + y^8 + 1` of the 6960119 sets.
const terms6960119: &[(usize, u16)] = &[(8, 1), (0, 1)];

/// Classic-McEliece-348864.
pub(crate) const classicMcEliece348864: Parameters = Parameters::new(
    "Classic-McEliece-348864",
    1,
    12,
    3488,
    64,
    terms348864,
    false,
);

/// Classic-McEliece-348864f.
pub(crate) const classicMcEliece348864f: Parameters = Parameters::new(
    "Classic-McEliece-348864f",
    1,
    12,
    3488,
    64,
    terms348864,
    true,
);

/// Classic-McEliece-460896.
pub(crate) const classicMcEliece460896: Parameters = Parameters::new(
    "Classic-McEliece-460896",
    3,
    13,
    4608,
    96,
    terms460896,
    false,
);

/// Classic-McEliece-460896f.
pub(crate) const classicMcEliece460896f: Parameters = Parameters::new(
    "Classic-McEliece-460896f",
    3,
    13,
    4608,
    96,
    terms460896,
    true,
);

/// Classic-McEliece-6688128.
pub(crate) const classicMcEliece6688128: Parameters = Parameters::new(
    "Classic-McEliece-6688128",
    5,
    13,
    6688,
    128,
    terms128,
    false,
);

/// Classic-McEliece-6688128f.
pub(crate) const classicMcEliece6688128f: Parameters = Parameters::new(
    "Classic-McEliece-6688128f",
    5,
    13,
    6688,
    128,
    terms128,
    true,
);

/// Classic-McEliece-6960119.
pub(crate) const classicMcEliece6960119: Parameters = Parameters::new(
    "Classic-McEliece-6960119",
    5,
    13,
    6960,
    119,
    terms6960119,
    false,
);

/// Classic-McEliece-6960119f.
pub(crate) const classicMcEliece6960119f: Parameters = Parameters::new(
    "Classic-McEliece-6960119f",
    5,
    13,
    6960,
    119,
    terms6960119,
    true,
);

/// Classic-McEliece-8192128.
pub(crate) const classicMcEliece8192128: Parameters = Parameters::new(
    "Classic-McEliece-8192128",
    5,
    13,
    8192,
    128,
    terms128,
    false,
);

/// Classic-McEliece-8192128f.
pub(crate) const classicMcEliece8192128f: Parameters = Parameters::new(
    "Classic-McEliece-8192128f",
    5,
    13,
    8192,
    128,
    terms128,
    true,
);

/// Every parameter set, in the order of the liboqs list.
#[cfg(test)]
pub(crate) const allParameters: [&Parameters; 10] = [
    &classicMcEliece348864,
    &classicMcEliece348864f,
    &classicMcEliece460896,
    &classicMcEliece460896f,
    &classicMcEliece6688128,
    &classicMcEliece6688128f,
    &classicMcEliece6960119,
    &classicMcEliece6960119f,
    &classicMcEliece8192128,
    &classicMcEliece8192128f,
];

#[cfg(test)]
mod tests {
    use super::allParameters;

    #[test]
    fn lengthsAreTheLengthsOfTheCHeaders() {
        // `kem_classic_mceliece.h` of liboqs and `api.h` of each set: public key, secret key
        // and ciphertext.
        let expected = [
            (261_120, 6492, 96),
            (261_120, 6492, 96),
            (524_160, 13_608, 156),
            (524_160, 13_608, 156),
            (1_044_992, 13_932, 208),
            (1_044_992, 13_932, 208),
            (1_047_319, 13_948, 194),
            (1_047_319, 13_948, 194),
            (1_357_824, 14_120, 208),
            (1_357_824, 14_120, 208),
        ];
        for (parameters, lengths) in allParameters.iter().zip(expected) {
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
            assert_eq!(
                (
                    description.keyPairSeedLength,
                    description.encapsulationSeedLength
                ),
                (0, 0)
            );
            assert_eq!(description.algorithmVersion, "SUPERCOP-20221025");
            assert!(description.isINDCCASecure);
        }
    }

    #[test]
    fn derivedSizesAreTheMacrosOfParamsH() {
        // `PK_NROWS`, `PK_ROW_BYTES`, `COND_BYTES` and `IRR_BYTES` of each base set.
        let expected = [
            (768, 340, 5888, 128),
            (1248, 420, 12_800, 192),
            (1664, 628, 12_800, 256),
            (1547, 677, 12_800, 238),
            (1664, 816, 12_800, 256),
        ];
        for (parameters, sizes) in allParameters.iter().step_by(2).zip(expected) {
            assert_eq!(
                (
                    parameters.rowCount(),
                    parameters.publicKeyRowLength(),
                    parameters.controlBitsLength(),
                    parameters.goppaPolynomialLength()
                ),
                sizes,
                "{}",
                parameters.description.name
            );
        }
    }

    #[test]
    fn theSecretKeyRangesFollowEachOtherToTheEnd() {
        for parameters in allParameters {
            // The seed of 32 bytes and the pivots of 8 bytes come first.
            assert_eq!(parameters.goppaPolynomialRange().start, 40);
            assert_eq!(
                parameters.controlBitsRange().start,
                parameters.goppaPolynomialRange().end
            );
            assert_eq!(
                parameters.rejectionValueRange().start,
                parameters.controlBitsRange().end
            );
            assert_eq!(
                parameters.rejectionValueRange().end,
                parameters.description.secretKeyLength
            );
        }
    }

    #[test]
    fn onlyThe6960119SetsHavePaddingAndOnlyThe8192128SetsHaveFullLength() {
        for parameters in allParameters {
            let name = parameters.description.name;
            let isPadded = name.contains("6960119");
            let isFull = name.contains("8192128");
            assert_eq!(parameters.rowTail(), if isPadded { 3 } else { 0 }, "{name}");
            assert_eq!(parameters.isFullLength(), isFull, "{name}");
            // `gen_e` draws `sizeof(ind)` bytes for 8192128 and `sizeof(buf)` for the others.
            let request = if isFull {
                2 * parameters.errorWeight
            } else {
                4 * parameters.errorWeight
            };
            assert_eq!(parameters.errorRequestLength(), request, "{name}");
            assert_eq!(parameters.isSemiSystematic, name.ends_with('f'), "{name}");
        }
    }

    #[test]
    fn theSeedExpansionHasTheLengthOfTheBufferOfOperationsC() {
        // `r` of `crypto_kem_keypair`: `SYS_N / 8 + (1 << GFBITS) * 4 + SYS_T * 2 + 32`.
        let expected = [16_980, 33_568, 33_892, 33_908, 34_080];
        for (parameters, length) in allParameters.iter().step_by(2).zip(expected) {
            assert_eq!(parameters.expandedSeedLength(), length);
        }
    }
}
