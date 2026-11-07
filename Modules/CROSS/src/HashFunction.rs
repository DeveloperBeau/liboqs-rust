use OQSNativeSHA3::{SHAKE128, SHAKE256, SHAKEReader};

/// The extendable-output function of a CROSS set, as `sha3.h` of its folder chooses it:
/// SHAKE128 for the security level 128, and SHAKE256 for the levels 192 and 256.
///
/// The seed expansions and the hashes of `csprng_hash.h` absorb their input and then a domain
/// separator of 16 bits, low byte first. A hash is the first 2 lambda bits of the output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HashFunction {
    /// SHAKE128 of FIPS 202.
    shake128,
    /// SHAKE256 of FIPS 202.
    shake256,
}

impl HashFunction {
    /// The domain separator of every hash of the scheme apart from the commitments of the
    /// rounds, `HASH_DOMAIN_SEP_CONST`.
    pub(crate) const hashDomain: u16 = 0x8000;

    /// The output stream of the concatenation of the input parts and the domain separator,
    /// `csprng_initialize`.
    pub(crate) fn reader(self, parts: &[&[u8]], domain: u16) -> SHAKEReader {
        let separator = domain.to_le_bytes();
        match self {
            HashFunction::shake128 => {
                let mut function = SHAKE128::new();
                for part in parts {
                    function.absorb(part);
                }
                function.absorb(&separator);
                function.finalize()
            }
            HashFunction::shake256 => {
                let mut function = SHAKE256::new();
                for part in parts {
                    function.absorb(part);
                }
                function.absorb(&separator);
                function.finalize()
            }
        }
    }

    /// Fills a digest with the start of the output of the input parts and the domain
    /// separator, `hash`.
    pub(crate) fn digest(self, parts: &[&[u8]], domain: u16, digest: &mut [u8]) {
        self.reader(parts, domain).squeeze(digest);
    }
}

#[cfg(test)]
mod tests {
    use super::HashFunction;
    use OQSNativeSHA3::{SHAKE128, SHAKE256};

    #[test]
    fn theDomainSeparatorFollowsTheInputLowByteFirst() {
        // csprng_initialize absorbs `dsc & 0xff` and then `dsc >> 8`.
        let mut expected = [0u8; 32];
        SHAKE128::hash(b"seed\x34\x12", &mut expected);
        let mut digest = [0u8; 32];
        HashFunction::shake128.digest(&[b"se", b"ed"], 0x1234, &mut digest);
        assert_eq!(digest, expected);
        SHAKE256::hash(b"seed\x00\x80", &mut expected);
        HashFunction::shake256.digest(&[b"seed"], HashFunction::hashDomain, &mut digest);
        assert_eq!(digest, expected);
    }

    #[test]
    fn anEmptyInputHashesTheSeparatorAlone() {
        let mut digest = [0u8; 16];
        HashFunction::shake128.reader(&[], 0).squeeze(&mut digest);
        let mut expected = [0u8; 16];
        SHAKE128::hash(&[0, 0], &mut expected);
        assert_eq!(digest, expected);
        HashFunction::shake256
            .reader(&[], 0x0102)
            .squeeze(&mut digest);
        SHAKE256::hash(&[2, 1], &mut expected);
        assert_eq!(digest, expected);
    }

    #[test]
    fn theReaderIsOneStreamHoweverTheSqueezesSplitIt() {
        let mut whole = [0u8; 300];
        HashFunction::shake256
            .reader(&[b"x"], 7)
            .squeeze(&mut whole);
        let mut reader = HashFunction::shake256.reader(&[b"x"], 7);
        let mut first = [0u8; 137];
        let mut second = [0u8; 163];
        reader.squeeze(&mut first);
        reader.squeeze(&mut second);
        assert_eq!(&whole[..137], &first);
        assert_eq!(&whole[137..], &second);
    }
}
