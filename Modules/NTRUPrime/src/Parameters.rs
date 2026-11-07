use OQSNativeEntities::KEMDescription;

/// The parameters of a Streamlined NTRU Prime set, the constants of `sntrup761.c`, and the
/// liboqs facts of the set.
pub(crate) struct Parameters {
    /// The prime degree `p` of the ring `Z[x] / (x^p - x - 1)`.
    pub(crate) degree: usize,
    /// The prime modulus `q`.
    pub(crate) modulus: i16,
    /// The weight `w` of a short polynomial: its number of coefficients 1 and -1.
    pub(crate) weight: usize,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: KEMDescription,
}

impl Parameters {
    /// The length of a hash, `Hash_bytes`, and of the confirmation at the end of a
    /// ciphertext, `Confirm_bytes`.
    pub(crate) const hashLength: usize = 32;

    /// `(q - 1) / 2`, the largest centered value modulo `q`, `q12`.
    pub(crate) const fn halfModulus(&self) -> i16 {
        (self.modulus - 1) / 2
    }

    /// The number of values of a rounded coefficient, `(q + 2) / 3` in the C code.
    pub(crate) const fn roundedRange(&self) -> u16 {
        (self.modulus as u16).div_ceil(3)
    }

    /// The length of a packed small polynomial, four coefficients in each byte,
    /// `Small_bytes`.
    pub(crate) const fn smallLength(&self) -> usize {
        Self::smallLengthOf(self.degree)
    }

    /// The length of the encoded rounded polynomial at the start of a ciphertext.
    pub(crate) const fn roundedLength(&self) -> usize {
        self.description.ciphertextLength - Self::hashLength
    }

    /// The length of a random request of `p` 32-bit words, `sizeof(L)` of `Short_random` and
    /// `Small_random`.
    pub(crate) const fn wordRequestLength(&self) -> usize {
        4 * self.degree
    }

    const fn smallLengthOf(degree: usize) -> usize {
        degree.div_ceil(4)
    }
}

/// sntrup761, from `sntrup761_openssh/sntrup761.c` and `kem_ntruprime_sntrup761.c`.
///
/// The lengths of a public key and of a rounded polynomial follow from the radix encoding of
/// the C code, and `RadixEncoding` derives them again in its tests.
pub(crate) const sntrup761: Parameters = Parameters {
    degree: 761,
    modulus: 4591,
    weight: 286,
    description: KEMDescription {
        name: "sntrup761",
        algorithmVersion: "v1.9.2026.01.20 via https://github.com/openssh/openssh-portable/blob/master/sntrup761.c",
        claimedNISTLevel: 2,
        isINDCCASecure: true,
        publicKeyLength: 1158,
        secretKeyLength: 2 * Parameters::smallLengthOf(761)
            + 1158
            + Parameters::smallLengthOf(761)
            + Parameters::hashLength,
        ciphertextLength: 1007 + Parameters::hashLength,
        sharedSecretLength: 32,
        keyPairSeedLength: 0,
        encapsulationSeedLength: 0,
    },
};

#[cfg(test)]
mod tests {
    use super::sntrup761;

    #[test]
    fn lengthsAreTheLengthsOfTheLiboqsHeader() {
        // `kem_ntruprime.h`.
        let description = &sntrup761.description;
        assert_eq!(
            (
                description.publicKeyLength,
                description.secretKeyLength,
                description.ciphertextLength,
                description.sharedSecretLength
            ),
            (1158, 1763, 1039, 32)
        );
        assert_eq!(sntrup761.smallLength(), 191);
        assert_eq!(sntrup761.roundedLength(), 1007);
        assert_eq!(sntrup761.wordRequestLength(), 3044);
        assert_eq!(sntrup761.halfModulus(), 2295);
        assert_eq!(sntrup761.roundedRange(), 1531);
    }
}
