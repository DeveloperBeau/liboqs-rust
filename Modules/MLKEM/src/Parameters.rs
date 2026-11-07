use OQSNativeEntities::KEMDescription;

/// The parameters of one ML-KEM parameter set, FIPS 203, Section 8.
pub(crate) struct Parameters {
    /// The rank `k` of the module.
    pub(crate) rank: usize,
    /// The `eta_1` of the secret and of the noise of key generation.
    pub(crate) firstEta: usize,
    /// The `eta_2` of the noise of encryption.
    pub(crate) secondEta: usize,
    /// The bits `d_u` of each coefficient of the vector part of a ciphertext.
    pub(crate) vectorBits: u32,
    /// The bits `d_v` of each coefficient of the polynomial part of a ciphertext.
    pub(crate) polynomialBits: u32,
    /// True for FIPS 203, whose key generation hashes the seed with the rank byte. Kyber of
    /// round 3 hashes the seed alone.
    pub(crate) isRankHashed: bool,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: KEMDescription,
}

impl Parameters {
    /// The length of an encapsulation key: `384 k + 32`.
    pub(crate) const fn publicKeyLength(rank: usize) -> usize {
        384 * rank + 32
    }

    /// The length of a decapsulation key: `768 k + 96`.
    pub(crate) const fn secretKeyLength(rank: usize) -> usize {
        768 * rank + 96
    }

    /// The length of a ciphertext: `32 (d_u k + d_v)`.
    pub(crate) const fn ciphertextLength(
        rank: usize,
        vectorBits: u32,
        polynomialBits: u32,
    ) -> usize {
        32 * (vectorBits as usize * rank + polynomialBits as usize)
    }

    /// The length of the encoded vector part of a ciphertext: `32 d_u k`.
    pub(crate) fn vectorPartLength(&self) -> usize {
        32 * self.vectorBits as usize * self.rank
    }

    /// Makes the parameters of an ML-KEM set with the liboqs facts.
    pub(crate) const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        rank: usize,
        firstEta: usize,
        vectorBits: u32,
        polynomialBits: u32,
    ) -> Self {
        Parameters {
            rank,
            firstEta,
            secondEta: 2,
            vectorBits,
            polynomialBits,
            isRankHashed: true,
            description: KEMDescription {
                name,
                algorithmVersion: "FIPS203",
                claimedNISTLevel,
                isINDCCASecure: true,
                publicKeyLength: Self::publicKeyLength(rank),
                secretKeyLength: Self::secretKeyLength(rank),
                ciphertextLength: Self::ciphertextLength(rank, vectorBits, polynomialBits),
                sharedSecretLength: 32,
                keyPairSeedLength: 64,
                encapsulationSeedLength: 32,
            },
        }
    }

    /// Makes the parameters of a Kyber set of round 3 with the liboqs facts. liboqs gives
    /// Kyber no seeded forms, and names the commit of the reference code as the version.
    pub(crate) const fn kyber(
        name: &'static str,
        algorithmVersion: &'static str,
        claimedNISTLevel: u8,
        rank: usize,
        firstEta: usize,
        vectorBits: u32,
        polynomialBits: u32,
    ) -> Self {
        let mut parameters = Self::new(
            name,
            claimedNISTLevel,
            rank,
            firstEta,
            vectorBits,
            polynomialBits,
        );
        parameters.isRankHashed = false;
        parameters.description.algorithmVersion = algorithmVersion;
        parameters.description.keyPairSeedLength = 0;
        parameters.description.encapsulationSeedLength = 0;
        parameters
    }
}

/// The version text of Kyber512 in liboqs: a later commit of the reference code.
const kyber512Version: &str =
    "https://github.com/pq-crystals/kyber/commit/74cad307858b61e434490c75f812cb9b9ef7279b";

/// The version text of Kyber768 and Kyber1024 in liboqs.
const kyberVersion: &str =
    "https://github.com/pq-crystals/kyber/commit/28413dfbf523fdde181246451c2bd77199c0f7ff";

/// Kyber512 of round 3.
pub(crate) const kyber512: Parameters =
    Parameters::kyber("Kyber512", kyber512Version, 1, 2, 3, 10, 4);

/// Kyber768 of round 3.
pub(crate) const kyber768: Parameters = Parameters::kyber("Kyber768", kyberVersion, 3, 3, 2, 10, 4);

/// Kyber1024 of round 3.
pub(crate) const kyber1024: Parameters =
    Parameters::kyber("Kyber1024", kyberVersion, 5, 4, 2, 11, 5);

/// ML-KEM-512, FIPS 203, Table 2.
pub(crate) const mlkem512: Parameters = Parameters::new("ML-KEM-512", 1, 2, 3, 10, 4);

/// ML-KEM-768, FIPS 203, Table 2.
pub(crate) const mlkem768: Parameters = Parameters::new("ML-KEM-768", 3, 3, 2, 10, 4);

/// ML-KEM-1024, FIPS 203, Table 2.
pub(crate) const mlkem1024: Parameters = Parameters::new("ML-KEM-1024", 5, 4, 2, 11, 5);

#[cfg(test)]
mod tests {
    use super::{kyber512, kyber768, kyber1024, mlkem512, mlkem768, mlkem1024};

    #[test]
    fn lengthsAreTheLengthsOfFIPS203Table3() {
        let lengths = |description: &OQSNativeEntities::KEMDescription| {
            (
                description.publicKeyLength,
                description.secretKeyLength,
                description.ciphertextLength,
            )
        };
        assert_eq!(lengths(&mlkem512.description), (800, 1632, 768));
        assert_eq!(lengths(&mlkem768.description), (1184, 2400, 1088));
        assert_eq!(lengths(&mlkem1024.description), (1568, 3168, 1568));
        assert_eq!(mlkem768.vectorPartLength(), 960);
        assert_eq!(mlkem1024.vectorPartLength(), 1408);
    }

    #[test]
    fn kyberSetsHaveTheLengthsOfMLKEMAndNoSeededForms() {
        for (kyber, mlkem) in [
            (&kyber512, &mlkem512),
            (&kyber768, &mlkem768),
            (&kyber1024, &mlkem1024),
        ] {
            assert_eq!(
                kyber.description.publicKeyLength,
                mlkem.description.publicKeyLength
            );
            assert_eq!(
                kyber.description.secretKeyLength,
                mlkem.description.secretKeyLength
            );
            assert_eq!(
                kyber.description.ciphertextLength,
                mlkem.description.ciphertextLength
            );
            assert_eq!(
                kyber.description.claimedNISTLevel,
                mlkem.description.claimedNISTLevel
            );
            assert_eq!(
                (
                    kyber.description.keyPairSeedLength,
                    kyber.description.encapsulationSeedLength
                ),
                (0, 0)
            );
            assert!(!kyber.isRankHashed && mlkem.isRankHashed);
        }
    }
}
