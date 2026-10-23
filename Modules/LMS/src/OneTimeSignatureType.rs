use crate::parameters::hashLength;

/// The LM-OTS parameter set of RFC 8554, Section 4.1, with SHA-256 and n = 32: the Winternitz
/// parameter w, the number p of hash chains, the left shift ls of the checksum and the
/// typecode.
///
/// The cases are the four one-time signature types of `lm_ots_look_up_parameter_set` of
/// hash-sigs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OneTimeSignatureType {
    /// `LMOTS_SHA256_N32_W1`, typecode 1.
    winternitz1,
    /// `LMOTS_SHA256_N32_W2`, typecode 2.
    winternitz2,
    /// `LMOTS_SHA256_N32_W4`, typecode 3.
    winternitz4,
    /// `LMOTS_SHA256_N32_W8`, typecode 4.
    winternitz8,
}

impl OneTimeSignatureType {
    /// The one-time signature type of a typecode, or `None` for a typecode that hash-sigs does
    /// not know.
    pub(crate) const fn ofCode(code: u64) -> Option<OneTimeSignatureType> {
        match code {
            1 => Some(OneTimeSignatureType::winternitz1),
            2 => Some(OneTimeSignatureType::winternitz2),
            3 => Some(OneTimeSignatureType::winternitz4),
            4 => Some(OneTimeSignatureType::winternitz8),
            _ => None,
        }
    }

    /// The typecode of RFC 8554, Section 4.1.
    pub(crate) const fn code(self) -> u32 {
        match self {
            OneTimeSignatureType::winternitz1 => 1,
            OneTimeSignatureType::winternitz2 => 2,
            OneTimeSignatureType::winternitz4 => 3,
            OneTimeSignatureType::winternitz8 => 4,
        }
    }

    /// The Winternitz parameter w: the bits of the message hash that each chain signs.
    pub(crate) const fn winternitz(self) -> u32 {
        match self {
            OneTimeSignatureType::winternitz1 => 1,
            OneTimeSignatureType::winternitz2 => 2,
            OneTimeSignatureType::winternitz4 => 4,
            OneTimeSignatureType::winternitz8 => 8,
        }
    }

    /// The number p of hash chains: the digits of the message hash and of its checksum.
    pub(crate) const fn chainCount(self) -> usize {
        match self {
            OneTimeSignatureType::winternitz1 => 265,
            OneTimeSignatureType::winternitz2 => 133,
            OneTimeSignatureType::winternitz4 => 67,
            OneTimeSignatureType::winternitz8 => 34,
        }
    }

    /// The left shift ls of the checksum, which puts its digits at the top of its 16 bits.
    pub(crate) const fn checksumShift(self) -> u32 {
        match self {
            OneTimeSignatureType::winternitz1 => 7,
            OneTimeSignatureType::winternitz2 => 6,
            OneTimeSignatureType::winternitz4 => 4,
            OneTimeSignatureType::winternitz8 => 0,
        }
    }

    /// The largest digit, `2^w - 1`, which is also the length of each hash chain.
    pub(crate) const fn largestDigit(self) -> u32 {
        (1 << self.winternitz()) - 1
    }

    /// The length of a signature, `lm_ots_get_signature_len`: the typecode, the randomizer C
    /// and one hash for each chain.
    pub(crate) const fn signatureLength(self) -> usize {
        4 + hashLength + self.chainCount() * hashLength
    }
}

#[cfg(test)]
mod tests {
    use super::OneTimeSignatureType;

    #[test]
    fn eachTypeHasTheValuesOfRFC8554Table1AndHashSigs() {
        // RFC 8554, Section 4.1, Table 1, and `lm_ots_look_up_parameter_set` of hash-sigs.
        let expected = [
            (OneTimeSignatureType::winternitz1, 1, 1, 265, 7, 1, 8516),
            (OneTimeSignatureType::winternitz2, 2, 2, 133, 6, 3, 4292),
            (OneTimeSignatureType::winternitz4, 3, 4, 67, 4, 15, 2180),
            (OneTimeSignatureType::winternitz8, 4, 8, 34, 0, 255, 1124),
        ];
        for (kind, code, winternitz, chainCount, shift, largestDigit, length) in expected {
            assert_eq!(kind.code(), code, "{kind:?}");
            assert_eq!(kind.winternitz(), winternitz, "{kind:?}");
            assert_eq!(kind.chainCount(), chainCount, "{kind:?}");
            assert_eq!(kind.checksumShift(), shift, "{kind:?}");
            assert_eq!(kind.largestDigit(), largestDigit, "{kind:?}");
            assert_eq!(kind.signatureLength(), length, "{kind:?}");
            assert_eq!(
                OneTimeSignatureType::ofCode(u64::from(code)),
                Some(kind),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn everyOtherTypecodeIsUnknown() {
        for code in [0, 5, 6, 0x0E, 0xFF, 0x1_0000_0001] {
            assert_eq!(OneTimeSignatureType::ofCode(code), None, "{code}");
        }
    }
}
