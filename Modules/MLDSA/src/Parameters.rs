use OQSNativeEntities::SignatureDescription;

/// The parameters of one ML-DSA parameter set, FIPS 204, Section 4, Table 1, and the facts of
/// the set as liboqs states them in `sig_ml_dsa_<set>.c`.
pub(crate) struct Parameters {
    /// The rows k of the matrix A: the length of the vectors s2, t and w.
    pub(crate) rowCount: usize,
    /// The columns l of the matrix A: the length of the vectors s1, y and z.
    pub(crate) columnCount: usize,
    /// The bound eta of the coefficients of the secret vectors s1 and s2.
    pub(crate) eta: i32,
    /// The number tau of coefficients of the challenge that are not zero.
    pub(crate) tau: usize,
    /// The bound beta, tau times eta, that the norm checks of a signature subtract.
    pub(crate) beta: i32,
    /// The bits of the range gamma1 of the mask y: gamma1 is two to this power.
    pub(crate) gamma1Bits: u32,
    /// The rounding range gamma2 of the low bits of w.
    pub(crate) gamma2: i32,
    /// The largest number omega of hint bits in a signature.
    pub(crate) omega: usize,
    /// The length of the commitment hash c tilde in bytes, lambda / 4.
    pub(crate) commitmentHashLength: usize,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: SignatureDescription,
}

/// The length of the public seed rho and of the signing key K in bytes.
pub(crate) const seedLength: usize = 32;

/// The length of the hash tr of the public key in bytes, and of the message representative mu.
pub(crate) const representativeLength: usize = 64;

/// The length of the packed t1 of one polynomial: 10 bits for each coefficient.
pub(crate) const packedHighLength: usize = 320;

/// The length of the packed t0 of one polynomial: 13 bits for each coefficient.
pub(crate) const packedLowLength: usize = 416;

impl Parameters {
    /// The bits of a packed coefficient of s1 or s2: 3 for eta 2 and 4 for eta 4.
    pub(crate) const fn etaBits(eta: i32) -> u32 {
        if eta == 2 { 3 } else { 4 }
    }

    /// The bits of a packed coefficient of z: the bits of gamma1 and one more.
    pub(crate) const fn maskBits(&self) -> u32 {
        self.gamma1Bits + 1
    }

    /// The bits of a packed coefficient of w1: 6 for the 44 values of gamma2 = (q - 1) / 88,
    /// and 4 for the 16 values of gamma2 = (q - 1) / 32.
    pub(crate) const fn commitmentBits(&self) -> u32 {
        if self.gamma2 == (crate::polynomial::modulus - 1) / 88 {
            6
        } else {
            4
        }
    }

    /// The length of one packed polynomial of s1 or s2.
    pub(crate) const fn packedShortLength(&self) -> usize {
        32 * Self::etaBits(self.eta) as usize
    }

    /// The length of one packed polynomial of z.
    pub(crate) const fn packedMaskLength(&self) -> usize {
        32 * self.maskBits() as usize
    }

    /// The length of one packed polynomial of w1.
    pub(crate) const fn packedCommitmentLength(&self) -> usize {
        32 * self.commitmentBits() as usize
    }

    /// The number of attempts of the rejection loop of a signature, `MLD_NONCE_UB` of
    /// mldsa-native: `(2^16 - 1 - l) / l`. Attempt n samples its mask with the nonces from
    /// `l n` to `l n + l - 1`, so the nonces of the last attempt stay below 2^16.
    pub(crate) const fn signingAttemptCount(&self) -> usize {
        (u16::MAX as usize - self.columnCount) / self.columnCount
    }

    /// The length of a public key: `32 + 320 k`.
    pub(crate) const fn publicKeyLength(rowCount: usize) -> usize {
        seedLength + packedHighLength * rowCount
    }

    /// The length of a secret key: `128 + 32 (l + k) bitlen(2 eta) + 416 k`.
    pub(crate) const fn secretKeyLength(rowCount: usize, columnCount: usize, eta: i32) -> usize {
        2 * seedLength
            + representativeLength
            + (columnCount + rowCount) * 32 * Self::etaBits(eta) as usize
            + packedLowLength * rowCount
    }

    /// The length of a signature: `lambda / 4 + 32 l (1 + bitlen(gamma1 - 1)) + omega + k`.
    pub(crate) const fn signatureLength(
        rowCount: usize,
        columnCount: usize,
        gamma1Bits: u32,
        omega: usize,
        commitmentHashLength: usize,
    ) -> usize {
        commitmentHashLength + columnCount * 32 * (gamma1Bits as usize + 1) + omega + rowCount
    }

    /// Makes the parameters of a set with the liboqs facts.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        rowCount: usize,
        columnCount: usize,
        eta: i32,
        tau: usize,
        gamma1Bits: u32,
        gamma2: i32,
        omega: usize,
        commitmentHashLength: usize,
    ) -> Self {
        Parameters {
            rowCount,
            columnCount,
            eta,
            tau,
            beta: tau as i32 * eta,
            gamma1Bits,
            gamma2,
            omega,
            commitmentHashLength,
            description: SignatureDescription {
                name,
                algorithmVersion: "FIPS204",
                claimedNISTLevel,
                isEUFCMASecure: true,
                isSUFCMASecure: true,
                supportsContext: true,
                publicKeyLength: Self::publicKeyLength(rowCount),
                secretKeyLength: Self::secretKeyLength(rowCount, columnCount, eta),
                signatureLength: Self::signatureLength(
                    rowCount,
                    columnCount,
                    gamma1Bits,
                    omega,
                    commitmentHashLength,
                ),
            },
        }
    }
}

/// ML-DSA-44, FIPS 204, Table 1, at the NIST level 2 that liboqs claims.
pub(crate) const mldsa44: Parameters = Parameters::new(
    "ML-DSA-44",
    2,
    4,
    4,
    2,
    39,
    17,
    (crate::polynomial::modulus - 1) / 88,
    80,
    32,
);

/// ML-DSA-65, FIPS 204, Table 1, at the NIST level 3 that liboqs claims.
pub(crate) const mldsa65: Parameters = Parameters::new(
    "ML-DSA-65",
    3,
    6,
    5,
    4,
    49,
    19,
    (crate::polynomial::modulus - 1) / 32,
    55,
    48,
);

/// ML-DSA-87, FIPS 204, Table 1, at the NIST level 5 that liboqs claims.
pub(crate) const mldsa87: Parameters = Parameters::new(
    "ML-DSA-87",
    5,
    8,
    7,
    2,
    60,
    19,
    (crate::polynomial::modulus - 1) / 32,
    75,
    64,
);

#[cfg(test)]
mod tests {
    use super::{mldsa44, mldsa65, mldsa87};

    #[test]
    fn lengthsAreTheLengthsOfFIPS204Table2AndOfLiboqs() {
        let lengths = |description: &OQSNativeEntities::SignatureDescription| {
            (
                description.publicKeyLength,
                description.secretKeyLength,
                description.signatureLength,
            )
        };
        // FIPS 204, Table 2, and `sig_ml_dsa.h` of liboqs.
        assert_eq!(lengths(&mldsa44.description), (1312, 2560, 2420));
        assert_eq!(lengths(&mldsa65.description), (1952, 4032, 3309));
        assert_eq!(lengths(&mldsa87.description), (2592, 4896, 4627));
    }

    #[test]
    fn derivedValuesAreTheValuesOfFIPS204Table1() {
        assert_eq!((mldsa44.beta, mldsa65.beta, mldsa87.beta), (78, 196, 120));
        assert_eq!((mldsa44.gamma2, mldsa65.gamma2), (95_232, 261_888));
        assert_eq!(
            (
                mldsa44.packedShortLength(),
                mldsa65.packedShortLength(),
                mldsa87.packedShortLength()
            ),
            (96, 128, 96)
        );
        assert_eq!(
            (mldsa44.packedMaskLength(), mldsa65.packedMaskLength()),
            (576, 640)
        );
        assert_eq!(
            (
                mldsa44.packedCommitmentLength(),
                mldsa87.packedCommitmentLength()
            ),
            (192, 128)
        );
    }

    #[test]
    fn eachConstantIsTheConstantOfFIPS204AndOfTheHeaderOfMLDSANative() {
        // A C program printed the constants of `params.h` of mldsa-native for each set: k, l,
        // eta, tau, beta, gamma1, gamma2, omega and lambda / 4 of FIPS 204, Table 1, the packed
        // lengths of z, w1 and s1, and `MLD_NONCE_UB` of `sign.c`, the number of attempts of a
        // signature.
        for (parameters, expected) in [
            (
                &mldsa44,
                [
                    4, 4, 2, 39, 78, 131_072, 95_232, 80, 32, 576, 192, 96, 16_382,
                ],
            ),
            (
                &mldsa65,
                [
                    6, 5, 4, 49, 196, 524_288, 261_888, 55, 48, 640, 128, 128, 13_106,
                ],
            ),
            (
                &mldsa87,
                [
                    8, 7, 2, 60, 120, 524_288, 261_888, 75, 64, 640, 128, 96, 9_361,
                ],
            ),
        ] {
            let constants = [
                parameters.rowCount,
                parameters.columnCount,
                parameters.eta as usize,
                parameters.tau,
                parameters.beta as usize,
                1 << parameters.gamma1Bits,
                parameters.gamma2 as usize,
                parameters.omega,
                parameters.commitmentHashLength,
                parameters.packedMaskLength(),
                parameters.packedCommitmentLength(),
                parameters.packedShortLength(),
                parameters.signingAttemptCount(),
            ];
            assert_eq!(constants, expected, "{}", parameters.description.name);
        }
    }

    #[test]
    fn eachSetHasTheFactsOfItsLiboqsFile() {
        for (parameters, name, level) in [
            (&mldsa44, "ML-DSA-44", 2),
            (&mldsa65, "ML-DSA-65", 3),
            (&mldsa87, "ML-DSA-87", 5),
        ] {
            let description = &parameters.description;
            assert_eq!(description.name, name);
            assert_eq!(description.algorithmVersion, "FIPS204");
            assert_eq!(description.claimedNISTLevel, level);
            assert!(description.isEUFCMASecure && description.isSUFCMASecure);
            assert!(description.supportsContext);
        }
    }
}
