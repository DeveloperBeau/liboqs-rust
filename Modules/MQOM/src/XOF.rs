use crate::Parameters;
use OQSNativeSHA3::{SHAKE128, SHAKE256, SHAKEReader};

/// The extendable-output function of a parameter set: SHAKE128 for λ = 128 and SHAKE256 for
/// λ = 192 and 256, as `xof.h` chooses it.
///
/// Each use starts with a domain byte, such as 0x02 for the message hash. The four-way XOF of
/// the C code is four of these functions, so the port computes each one alone.
pub(crate) enum XOF {
    /// SHAKE128.
    shake128(SHAKE128),
    /// SHAKE256.
    shake256(SHAKE256),
}

impl XOF {
    /// A new function for the security level of a parameter set.
    pub(crate) fn new(parameters: &Parameters) -> Self {
        if parameters.securityBits == 128 {
            XOF::shake128(SHAKE128::new())
        } else {
            XOF::shake256(SHAKE256::new())
        }
    }

    /// Absorbs bytes, as `xof_update` does.
    pub(crate) fn absorb(&mut self, bytes: &[u8]) {
        match self {
            XOF::shake128(sponge) => sponge.absorb(bytes),
            XOF::shake256(sponge) => sponge.absorb(bytes),
        }
    }

    /// Ends the input and gives the output stream, which `xof_squeeze` reads in any number of
    /// calls.
    pub(crate) fn finalize(self) -> SHAKEReader {
        match self {
            XOF::shake128(sponge) => sponge.finalize(),
            XOF::shake256(sponge) => sponge.finalize(),
        }
    }

    /// Fills an output with the function of the parts of an input, one after another.
    pub(crate) fn hash(parameters: &Parameters, parts: &[&[u8]], output: &mut [u8]) {
        let mut function = Self::new(parameters);
        for part in parts {
            function.absorb(part);
        }
        function.finalize().squeeze(output);
    }
}

#[cfg(test)]
mod tests {
    use super::XOF;
    use crate::parameters::{mqom2Cat1GF16FastR3, mqom2Cat3GF16FastR3, mqom2Cat5GF16ShortR5};
    use OQSNativeSHA3::{SHAKE128, SHAKE256};

    #[test]
    fn theFirstLevelHashesWithSHAKE128AndTheOthersWithSHAKE256() {
        let input = b"the parts of an input";
        let mut expected128 = [0u8; 40];
        SHAKE128::hash(input, &mut expected128);
        let mut expected256 = [0u8; 40];
        SHAKE256::hash(input, &mut expected256);
        let mut output = [0u8; 40];
        XOF::hash(
            &mqom2Cat1GF16FastR3,
            &[b"the parts ", b"of an input"],
            &mut output,
        );
        assert_eq!(output, expected128);
        for parameters in [&mqom2Cat3GF16FastR3, &mqom2Cat5GF16ShortR5] {
            XOF::hash(
                parameters,
                &[b"the parts of ", b"", b"an input"],
                &mut output,
            );
            assert_eq!(output, expected256);
        }
    }
}
