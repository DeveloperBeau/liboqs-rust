use crate::HashFamily;

/// One parameter set of SLH-DSA, FIPS 205, Table 2, as liboqs names it.
pub(crate) struct Parameters {
    /// The part of the liboqs names that names the set, such as `SHA2_128S`.
    pub(crate) liboqsName: &'static str,
    /// The position of the set in each form of the liboqs list, from 0 to 11.
    pub(crate) index: usize,
    /// The hash functions of the set.
    pub(crate) hashFamily: HashFamily,
    /// The security parameter `n`: the length of a hash value and of each key part, in bytes.
    pub(crate) hashLength: usize,
    /// The total height `h` of the hypertree.
    pub(crate) hypertreeHeight: u32,
    /// The number `d` of layers of the hypertree.
    pub(crate) layerCount: u32,
    /// The height `h'` of each XMSS tree.
    pub(crate) treeHeight: u32,
    /// The height `a` of each FORS tree.
    pub(crate) forsTreeHeight: u32,
    /// The number `k` of FORS trees.
    pub(crate) forsTreeCount: u32,
    /// The length `m` of the message digest, in bytes.
    pub(crate) digestLength: usize,
    /// The security category that liboqs claims for the set.
    pub(crate) claimedNISTLevel: u8,
}

impl Parameters {
    /// The bits `lg_w` of each digit of a WOTS+ chain, 4 for every set of FIPS 205.
    pub(crate) const winternitzBits: u32 = 4;
    /// The largest digit `w - 1` of a WOTS+ chain.
    pub(crate) const largestDigit: u32 = (1 << Self::winternitzBits) - 1;
    /// The largest `n` of the sets.
    pub(crate) const maximumHashLength: usize = 32;
    /// The largest number of WOTS+ chains, `len` for `n = 32`.
    pub(crate) const maximumChainCount: usize = 67;
    /// The largest height `h'` of an XMSS tree.
    pub(crate) const maximumTreeHeight: usize = 9;
    /// The largest height `a` of a FORS tree.
    pub(crate) const maximumFORSTreeHeight: usize = 14;
    /// The largest number `k` of FORS trees.
    pub(crate) const maximumFORSTreeCount: usize = 35;
    /// The largest length `m` of a message digest.
    pub(crate) const maximumDigestLength: usize = 49;

    /// The number `len_1` of WOTS+ chains of the message: `ceil(8 n / lg_w)`.
    pub(crate) const fn messageChainCount(&self) -> usize {
        (8 * self.hashLength).div_ceil(Self::winternitzBits as usize)
    }

    /// The number `len_2` of WOTS+ chains of the checksum. FIPS 205, Section 5, gives 3 for
    /// `lg_w = 4` and `9 <= n <= 136`, and `gen_len2` of the C code returns 3 at once for them.
    pub(crate) const fn checksumChainCount(&self) -> usize {
        3
    }

    /// The number `len` of WOTS+ chains: `len_1 + len_2`.
    pub(crate) const fn chainCount(&self) -> usize {
        self.messageChainCount() + self.checksumChainCount()
    }

    /// The length of a public key, `PK.seed || PK.root`.
    pub(crate) const fn publicKeyLength(&self) -> usize {
        2 * self.hashLength
    }

    /// The length of a secret key, `SK.seed || SK.prf || PK.seed || PK.root`.
    pub(crate) const fn secretKeyLength(&self) -> usize {
        4 * self.hashLength
    }

    /// The length of a FORS signature: `k (1 + a) n`.
    pub(crate) const fn forsSignatureLength(&self) -> usize {
        self.forsTreeCount as usize * (1 + self.forsTreeHeight as usize) * self.hashLength
    }

    /// The length of the signature of one XMSS tree: `(len + h') n`.
    pub(crate) const fn xmssSignatureLength(&self) -> usize {
        (self.chainCount() + self.treeHeight as usize) * self.hashLength
    }

    /// The length of a signature: `(1 + k (1 + a) + h + d len) n`, FIPS 205, Table 2.
    pub(crate) const fn signatureLength(&self) -> usize {
        self.hashLength
            + self.forsSignatureLength()
            + self.layerCount as usize * self.xmssSignatureLength()
    }

    /// The bytes of the digest that select the FORS leaves: `ceil(k a / 8)`.
    pub(crate) const fn forsDigestLength(&self) -> usize {
        (self.forsTreeCount as usize * self.forsTreeHeight as usize).div_ceil(8)
    }

    /// True for a SHA-2 set of category 3 or 5, whose `H`, `T_l` and message functions use
    /// SHA-512.
    pub(crate) const fn usesSHA512(&self) -> bool {
        matches!(self.hashFamily, HashFamily::sha2) && self.hashLength > 16
    }

    /// The twelve parameter sets, in the order of each form of the liboqs list.
    pub(crate) const all: [Parameters; 12] = [
        Self::set("SHA2_128S", 0, HashFamily::sha2, 16, 63, 7, 12, 14, 30, 1),
        Self::set("SHA2_128F", 1, HashFamily::sha2, 16, 66, 22, 6, 33, 34, 1),
        Self::set("SHA2_192S", 2, HashFamily::sha2, 24, 63, 7, 14, 17, 39, 3),
        Self::set("SHA2_192F", 3, HashFamily::sha2, 24, 66, 22, 8, 33, 42, 3),
        Self::set("SHA2_256S", 4, HashFamily::sha2, 32, 64, 8, 14, 22, 47, 5),
        Self::set("SHA2_256F", 5, HashFamily::sha2, 32, 68, 17, 9, 35, 49, 5),
        Self::set("SHAKE_128S", 6, HashFamily::shake, 16, 63, 7, 12, 14, 30, 1),
        Self::set("SHAKE_128F", 7, HashFamily::shake, 16, 66, 22, 6, 33, 34, 1),
        Self::set("SHAKE_192S", 8, HashFamily::shake, 24, 63, 7, 14, 17, 39, 3),
        Self::set("SHAKE_192F", 9, HashFamily::shake, 24, 66, 22, 8, 33, 42, 3),
        Self::set(
            "SHAKE_256S",
            10,
            HashFamily::shake,
            32,
            64,
            8,
            14,
            22,
            47,
            5,
        ),
        Self::set(
            "SHAKE_256F",
            11,
            HashFamily::shake,
            32,
            68,
            17,
            9,
            35,
            49,
            5,
        ),
    ];

    /// Makes a parameter set of FIPS 205, Table 2. The height of each XMSS tree is `h / d`.
    #[allow(clippy::too_many_arguments)]
    const fn set(
        liboqsName: &'static str,
        index: usize,
        hashFamily: HashFamily,
        hashLength: usize,
        hypertreeHeight: u32,
        layerCount: u32,
        forsTreeHeight: u32,
        forsTreeCount: u32,
        digestLength: usize,
        claimedNISTLevel: u8,
    ) -> Parameters {
        Parameters {
            liboqsName,
            index,
            hashFamily,
            hashLength,
            hypertreeHeight,
            layerCount,
            treeHeight: hypertreeHeight / layerCount,
            forsTreeHeight,
            forsTreeCount,
            digestLength,
            claimedNISTLevel,
        }
    }
}

/// The parameter sets as a static table, so that a scheme can keep a reference to its set.
pub(crate) static parameterSets: [Parameters; 12] = Parameters::all;

#[cfg(test)]
mod tests {
    use super::{Parameters, parameterSets};

    #[test]
    fn eachSetHasTheParametersOfFIPS205Table2() {
        // n, h, d, h', a, k, lg_w and m of FIPS 205, Table 2, for the SHA2 and the SHAKE form.
        let table = [
            (16, 63, 7, 9, 12, 14, 4, 30),
            (16, 66, 22, 3, 6, 33, 4, 34),
            (24, 63, 7, 9, 14, 17, 4, 39),
            (24, 66, 22, 3, 8, 33, 4, 42),
            (32, 64, 8, 8, 14, 22, 4, 47),
            (32, 68, 17, 4, 9, 35, 4, 49),
        ];
        for (index, set) in parameterSets.iter().enumerate() {
            let expected = table[index % 6];
            assert_eq!(
                (
                    set.hashLength,
                    set.hypertreeHeight,
                    set.layerCount,
                    set.treeHeight,
                    set.forsTreeHeight,
                    set.forsTreeCount,
                    Parameters::winternitzBits,
                    set.digestLength
                ),
                expected,
                "{}",
                set.liboqsName
            );
            assert_eq!(set.index, index);
        }
    }

    #[test]
    fn lengthsAreTheLengthsOfFIPS205Table2AndOfLiboqs() {
        // Public key, secret key and signature lengths of `sig_slh_dsa.h`.
        let lengths = [
            (32, 64, 7856),
            (32, 64, 17088),
            (48, 96, 16224),
            (48, 96, 35664),
            (64, 128, 29792),
            (64, 128, 49856),
        ];
        for set in &parameterSets {
            assert_eq!(
                (
                    set.publicKeyLength(),
                    set.secretKeyLength(),
                    set.signatureLength()
                ),
                lengths[set.index % 6],
                "{}",
                set.liboqsName
            );
        }
    }

    #[test]
    fn chainCountsAreTheWOTSLengthsOfFIPS205() {
        // FIPS 205, Section 5: len_1 = 2 n and len_2 = 3 for lg_w = 4.
        for set in &parameterSets {
            assert_eq!(set.messageChainCount(), 2 * set.hashLength);
            assert_eq!(set.checksumChainCount(), 3);
            assert_eq!(set.chainCount(), 2 * set.hashLength + 3);
        }
        assert_eq!(
            Parameters::all[5].chainCount(),
            Parameters::maximumChainCount
        );
    }

    #[test]
    fn threeChecksumDigitsHoldTheLargestChecksumOfEachSet() {
        // The largest checksum len_1 (w - 1) needs three digits of 4 bits and not two, so
        // len_2 = 3 is the value of gen_len2, FIPS 205, Algorithm 1.
        for set in &parameterSets {
            let largestChecksum = set.messageChainCount() * Parameters::largestDigit as usize;
            assert!(largestChecksum >= 16 * 16, "{}", set.liboqsName);
            assert!(largestChecksum < 16 * 16 * 16, "{}", set.liboqsName);
        }
        assert_eq!(Parameters::largestDigit, 15);
    }

    #[test]
    fn largestValuesBoundEverySet() {
        for set in &parameterSets {
            assert!(set.hashLength <= Parameters::maximumHashLength);
            assert!(set.chainCount() <= Parameters::maximumChainCount);
            assert!(set.treeHeight as usize <= Parameters::maximumTreeHeight);
            assert!(set.forsTreeHeight as usize <= Parameters::maximumFORSTreeHeight);
            assert!(set.forsTreeCount as usize <= Parameters::maximumFORSTreeCount);
            assert!(set.digestLength <= Parameters::maximumDigestLength);
            // The digest holds the FORS indices, the tree index and the leaf index.
            let treeBits = (set.hypertreeHeight - set.treeHeight) as usize;
            assert_eq!(
                set.forsDigestLength()
                    + treeBits.div_ceil(8)
                    + (set.treeHeight as usize).div_ceil(8),
                set.digestLength,
                "{}",
                set.liboqsName
            );
        }
    }

    #[test]
    fn onlyTheSHA2SetsAboveCategoryOneUseSHA512() {
        let users: Vec<&str> = parameterSets
            .iter()
            .filter(|set| set.usesSHA512())
            .map(|set| set.liboqsName)
            .collect();
        assert_eq!(users, ["SHA2_192S", "SHA2_192F", "SHA2_256S", "SHA2_256F"]);
    }
}
