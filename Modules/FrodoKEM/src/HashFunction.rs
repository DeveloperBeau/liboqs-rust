use OQSNativeSHA3::{SHAKE128, SHAKE256};

/// The hash function of a parameter set, the `shake` of its liboqs parameter header: SHAKE128
/// for FrodoKEM-640 and SHAKE256 for FrodoKEM-976 and FrodoKEM-1344.
///
/// Every hash of the scheme uses it: the seed of the public matrix, the noise matrices, the hash
/// of the public key, the seeds of encapsulation and the shared secret. The public matrix of a
/// SHAKE set uses SHAKE128 in every set, see `MatrixGeneration`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HashFunction {
    /// SHAKE128 of FIPS 202.
    shake128,
    /// SHAKE256 of FIPS 202.
    shake256,
}

impl HashFunction {
    /// Fills an output with the hash of the concatenation of the input parts.
    pub(crate) fn hash(&self, parts: &[&[u8]], output: &mut [u8]) {
        match self {
            HashFunction::shake128 => {
                let mut function = SHAKE128::new();
                for part in parts {
                    function.absorb(part);
                }
                function.finalize().squeeze(output);
            }
            HashFunction::shake256 => {
                let mut function = SHAKE256::new();
                for part in parts {
                    function.absorb(part);
                }
                function.finalize().squeeze(output);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HashFunction;

    #[test]
    fn eachFunctionGivesTheKnownAnswerOfFIPS202ForTheEmptyInput() {
        // The SHAKE128 and SHAKE256 outputs of the empty message, from the examples of NIST.
        let mut output = [0u8; 8];
        HashFunction::shake128.hash(&[], &mut output);
        assert_eq!(output, [0x7F, 0x9C, 0x2B, 0xA4, 0xE8, 0x8F, 0x82, 0x7D]);
        HashFunction::shake256.hash(&[], &mut output);
        assert_eq!(output, [0x46, 0xB9, 0xDD, 0x2B, 0x0B, 0xA8, 0x8D, 0x13]);
    }

    #[test]
    fn thePartsAreHashedAsOneConcatenation() {
        for function in [HashFunction::shake128, HashFunction::shake256] {
            let mut whole = [0u8; 40];
            function.hash(&[b"pkh mu salt"], &mut whole);
            let mut parts = [0u8; 40];
            function.hash(&[b"pkh ", b"mu", b" salt"], &mut parts);
            assert_eq!(whole, parts, "{function:?}");
            let mut other = [0u8; 40];
            function.hash(&[b"pkh mu salT"], &mut other);
            assert_ne!(whole, other, "{function:?}");
        }
    }
}
