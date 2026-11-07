use crate::{ErrorDistribution, HashFunction, MatrixGeneration};
use OQSNativeEntities::KEMDescription;

/// The parameters of one parameter set, from the liboqs parameter headers in
/// `src/kem/frodokem/external/frodo` and `src/kem/frodokem/external/efrodo`.
pub(crate) struct Parameters {
    /// The dimension `n` of the public matrix `A`.
    pub(crate) dimension: usize,
    /// The `D` of the modulus `q = 2^D`, `PARAMS_LOGQ`.
    pub(crate) modulusBits: u32,
    /// The `B` bits of the message in each value of the message matrix,
    /// `PARAMS_EXTRACTED_BITS`.
    pub(crate) messageBits: u32,
    /// The distribution of the secret and the error matrices.
    pub(crate) errorDistribution: ErrorDistribution,
    /// AES-128 or SHAKE128 for the public matrix.
    pub(crate) matrixGeneration: MatrixGeneration,
    /// SHAKE128 or SHAKE256 for every other hash.
    pub(crate) hashFunction: HashFunction,
    /// The length of the seed of the noise matrices, `BYTES_SEED_SE`: twice the shared secret
    /// for FrodoKEM, and the shared secret for eFrodoKEM.
    pub(crate) noiseSeedLength: usize,
    /// The length of the salt at the end of a ciphertext, `BYTES_SALT`: twice the shared secret
    /// for FrodoKEM, and zero for eFrodoKEM.
    pub(crate) saltLength: usize,
    /// The facts of the parameter set as liboqs states them.
    pub(crate) description: KEMDescription,
}

/// The version text of every set in liboqs: the commit of PQCrypto-LWEKE.
const algorithmVersion: &str =
    "https://github.com/microsoft/PQCrypto-LWEKE/commit/a2f9dec8917ccc3464b3378d46b140fa7353320d";

/// The table of the error distribution of FrodoKEM-640, `CDF_TABLE` of its header.
const errorTable640: [u16; 13] = [
    4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
];

/// The table of the error distribution of FrodoKEM-976.
const errorTable976: [u16; 11] = [
    5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767,
];

/// The table of the error distribution of FrodoKEM-1344.
const errorTable1344: [u16; 7] = [9142, 23462, 30338, 32361, 32725, 32765, 32767];

impl Parameters {
    /// The `n̄ = m̄ = 8` of every set: the columns of the secret matrix `S` and the rows of the
    /// ephemeral secret matrix `S'`, `PARAMS_NBAR`.
    pub(crate) const shortDimension: usize = 8;

    /// The length of the seed of the public matrix, `BYTES_SEED_A`.
    pub(crate) const matrixSeedLength: usize = 16;

    /// The number of values in the secret matrix and in each error matrix of the dimension:
    /// `n n̄`.
    pub(crate) fn matrixValueCount(&self) -> usize {
        self.dimension * Self::shortDimension
    }

    /// The length of the packed matrix `B` of a public key, and of `B'` of a ciphertext:
    /// `D n n̄ / 8`.
    pub(crate) fn packedMatrixLength(&self) -> usize {
        Self::packedLength(self.matrixValueCount(), self.modulusBits)
    }

    /// The length of the packed message matrix `C` of a ciphertext: `D n̄ n̄ / 8`.
    pub(crate) fn packedMessageMatrixLength(&self) -> usize {
        Self::packedLength(
            Self::shortDimension * Self::shortDimension,
            self.modulusBits,
        )
    }

    /// The length of the message `mu`, `BYTES_MU`: `B n̄ n̄ / 8`.
    pub(crate) fn messageLength(&self) -> usize {
        Self::packedLength(
            Self::shortDimension * Self::shortDimension,
            self.messageBits,
        )
    }

    /// The bytes of a number of values of a number of bits.
    const fn packedLength(valueCount: usize, bits: u32) -> usize {
        valueCount * bits as usize / 8
    }

    /// The length of a public key: the matrix seed and the packed matrix `B`.
    const fn publicKeyLength(dimension: usize, modulusBits: u32) -> usize {
        Self::matrixSeedLength + Self::packedLength(dimension * Self::shortDimension, modulusBits)
    }

    /// The length of a secret key: the rejection value `s`, the public key, the secret matrix
    /// with two bytes for each value, and the hash of the public key.
    const fn secretKeyLength(
        dimension: usize,
        modulusBits: u32,
        sharedSecretLength: usize,
    ) -> usize {
        sharedSecretLength
            + Self::publicKeyLength(dimension, modulusBits)
            + 2 * dimension * Self::shortDimension
            + sharedSecretLength
    }

    /// The length of a ciphertext: the packed matrices `B'` and `C` and the salt.
    const fn ciphertextLength(dimension: usize, modulusBits: u32, saltLength: usize) -> usize {
        Self::packedLength(dimension * Self::shortDimension, modulusBits)
            + Self::packedLength(Self::shortDimension * Self::shortDimension, modulusBits)
            + saltLength
    }

    /// Makes the parameters of a set with the liboqs facts.
    ///
    /// The ephemeral sets of eFrodoKEM have no salt, and the seed of their noise matrices has
    /// the length of the shared secret. FrodoKEM doubles both.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is one fact of the liboqs parameter header"
    )]
    const fn new(
        name: &'static str,
        claimedNISTLevel: u8,
        dimension: usize,
        modulusBits: u32,
        messageBits: u32,
        errorTable: &'static [u16],
        matrixGeneration: MatrixGeneration,
        hashFunction: HashFunction,
        sharedSecretLength: usize,
        isEphemeral: bool,
    ) -> Self {
        let (noiseSeedLength, saltLength) = if isEphemeral {
            (sharedSecretLength, 0)
        } else {
            (2 * sharedSecretLength, 2 * sharedSecretLength)
        };
        Parameters {
            dimension,
            modulusBits,
            messageBits,
            errorDistribution: ErrorDistribution::new(errorTable),
            matrixGeneration,
            hashFunction,
            noiseSeedLength,
            saltLength,
            description: KEMDescription {
                name,
                algorithmVersion,
                claimedNISTLevel,
                isINDCCASecure: true,
                publicKeyLength: Self::publicKeyLength(dimension, modulusBits),
                secretKeyLength: Self::secretKeyLength(dimension, modulusBits, sharedSecretLength),
                ciphertextLength: Self::ciphertextLength(dimension, modulusBits, saltLength),
                sharedSecretLength,
                keyPairSeedLength: 0,
                encapsulationSeedLength: 0,
            },
        }
    }

    /// A set of FrodoKEM-640: `n = 640`, `D = 15`, `B = 2`, a 16-byte shared secret and SHAKE128,
    /// security category 1.
    const fn frodo640(
        name: &'static str,
        matrixGeneration: MatrixGeneration,
        isEphemeral: bool,
    ) -> Self {
        Self::new(
            name,
            1,
            640,
            15,
            2,
            &errorTable640,
            matrixGeneration,
            HashFunction::shake128,
            16,
            isEphemeral,
        )
    }

    /// A set of FrodoKEM-976: `n = 976`, `D = 16`, `B = 3`, a 24-byte shared secret and
    /// SHAKE256, security category 3.
    const fn frodo976(
        name: &'static str,
        matrixGeneration: MatrixGeneration,
        isEphemeral: bool,
    ) -> Self {
        Self::new(
            name,
            3,
            976,
            16,
            3,
            &errorTable976,
            matrixGeneration,
            HashFunction::shake256,
            24,
            isEphemeral,
        )
    }

    /// A set of FrodoKEM-1344: `n = 1344`, `D = 16`, `B = 4`, a 32-byte shared secret and
    /// SHAKE256, security category 5.
    const fn frodo1344(
        name: &'static str,
        matrixGeneration: MatrixGeneration,
        isEphemeral: bool,
    ) -> Self {
        Self::new(
            name,
            5,
            1344,
            16,
            4,
            &errorTable1344,
            matrixGeneration,
            HashFunction::shake256,
            32,
            isEphemeral,
        )
    }
}

/// FrodoKEM-640-AES.
pub(crate) const frodoKEM640AES: Parameters =
    Parameters::frodo640("FrodoKEM-640-AES", MatrixGeneration::aes128, false);

/// FrodoKEM-640-SHAKE.
pub(crate) const frodoKEM640SHAKE: Parameters =
    Parameters::frodo640("FrodoKEM-640-SHAKE", MatrixGeneration::shake128, false);

/// FrodoKEM-976-AES.
pub(crate) const frodoKEM976AES: Parameters =
    Parameters::frodo976("FrodoKEM-976-AES", MatrixGeneration::aes128, false);

/// FrodoKEM-976-SHAKE.
pub(crate) const frodoKEM976SHAKE: Parameters =
    Parameters::frodo976("FrodoKEM-976-SHAKE", MatrixGeneration::shake128, false);

/// FrodoKEM-1344-AES.
pub(crate) const frodoKEM1344AES: Parameters =
    Parameters::frodo1344("FrodoKEM-1344-AES", MatrixGeneration::aes128, false);

/// FrodoKEM-1344-SHAKE.
pub(crate) const frodoKEM1344SHAKE: Parameters =
    Parameters::frodo1344("FrodoKEM-1344-SHAKE", MatrixGeneration::shake128, false);

/// eFrodoKEM-640-AES.
pub(crate) const eFrodoKEM640AES: Parameters =
    Parameters::frodo640("eFrodoKEM-640-AES", MatrixGeneration::aes128, true);

/// eFrodoKEM-640-SHAKE.
pub(crate) const eFrodoKEM640SHAKE: Parameters =
    Parameters::frodo640("eFrodoKEM-640-SHAKE", MatrixGeneration::shake128, true);

/// eFrodoKEM-976-AES.
pub(crate) const eFrodoKEM976AES: Parameters =
    Parameters::frodo976("eFrodoKEM-976-AES", MatrixGeneration::aes128, true);

/// eFrodoKEM-976-SHAKE.
pub(crate) const eFrodoKEM976SHAKE: Parameters =
    Parameters::frodo976("eFrodoKEM-976-SHAKE", MatrixGeneration::shake128, true);

/// eFrodoKEM-1344-AES.
pub(crate) const eFrodoKEM1344AES: Parameters =
    Parameters::frodo1344("eFrodoKEM-1344-AES", MatrixGeneration::aes128, true);

/// eFrodoKEM-1344-SHAKE.
pub(crate) const eFrodoKEM1344SHAKE: Parameters =
    Parameters::frodo1344("eFrodoKEM-1344-SHAKE", MatrixGeneration::shake128, true);

#[cfg(test)]
mod tests {
    use super::{
        Parameters, eFrodoKEM640AES, eFrodoKEM640SHAKE, eFrodoKEM976AES, eFrodoKEM976SHAKE,
        eFrodoKEM1344AES, eFrodoKEM1344SHAKE, frodoKEM640AES, frodoKEM640SHAKE, frodoKEM976AES,
        frodoKEM976SHAKE, frodoKEM1344AES, frodoKEM1344SHAKE,
    };
    use crate::{HashFunction, MatrixGeneration};

    /// Every set, in liboqs order.
    const everySet: [&Parameters; 12] = [
        &frodoKEM640AES,
        &frodoKEM640SHAKE,
        &frodoKEM976AES,
        &frodoKEM976SHAKE,
        &frodoKEM1344AES,
        &frodoKEM1344SHAKE,
        &eFrodoKEM640AES,
        &eFrodoKEM640SHAKE,
        &eFrodoKEM976AES,
        &eFrodoKEM976SHAKE,
        &eFrodoKEM1344AES,
        &eFrodoKEM1344SHAKE,
    ];

    #[test]
    fn lengthsAreTheLengthsOfTheLiboqsHeader() {
        // The lengths of `kem_frodokem.h`: public key, secret key, ciphertext and shared
        // secret.
        let expected = [
            (9616, 19888, 9752, 16),
            (9616, 19888, 9752, 16),
            (15632, 31296, 15792, 24),
            (15632, 31296, 15792, 24),
            (21520, 43088, 21696, 32),
            (21520, 43088, 21696, 32),
            (9616, 19888, 9720, 16),
            (9616, 19888, 9720, 16),
            (15632, 31296, 15744, 24),
            (15632, 31296, 15744, 24),
            (21520, 43088, 21632, 32),
            (21520, 43088, 21632, 32),
        ];
        for (parameters, lengths) in everySet.iter().zip(expected) {
            let description = &parameters.description;
            assert_eq!(
                (
                    description.publicKeyLength,
                    description.secretKeyLength,
                    description.ciphertextLength,
                    description.sharedSecretLength,
                ),
                lengths,
                "{}",
                description.name
            );
            assert_eq!(
                (
                    description.keyPairSeedLength,
                    description.encapsulationSeedLength
                ),
                (0, 0)
            );
        }
    }

    #[test]
    fn partLengthsAddUpToTheKeysAndTheCiphertext() {
        for parameters in everySet {
            let description = &parameters.description;
            assert_eq!(
                parameters.packedMatrixLength() + parameters.packedMessageMatrixLength(),
                description.ciphertextLength - parameters.saltLength
            );
            assert_eq!(
                Parameters::matrixSeedLength + parameters.packedMatrixLength(),
                description.publicKeyLength
            );
            assert_eq!(
                parameters.messageLength(),
                8 * parameters.messageBits as usize
            );
        }
        // `BYTES_MU` of the headers: 16, 24 and 32 bytes.
        assert_eq!(frodoKEM640AES.messageLength(), 16);
        assert_eq!(frodoKEM976SHAKE.messageLength(), 24);
        assert_eq!(eFrodoKEM1344AES.messageLength(), 32);
        assert_eq!(frodoKEM976AES.packedMessageMatrixLength(), 128);
        assert_eq!(frodoKEM640SHAKE.packedMatrixLength(), 9600);
    }

    #[test]
    fn ephemeralSetsHaveNoSaltAndAShorterNoiseSeed() {
        for (standard, ephemeral) in everySet[..6].iter().zip(&everySet[6..]) {
            let secretLength = standard.description.sharedSecretLength;
            assert_eq!(
                (standard.noiseSeedLength, standard.saltLength),
                (2 * secretLength, 2 * secretLength)
            );
            assert_eq!(
                (ephemeral.noiseSeedLength, ephemeral.saltLength),
                (secretLength, 0)
            );
            assert_eq!(standard.dimension, ephemeral.dimension);
            assert_eq!(standard.matrixGeneration, ephemeral.matrixGeneration);
            assert_eq!(
                standard.description.claimedNISTLevel,
                ephemeral.description.claimedNISTLevel
            );
            assert_eq!(
                standard.description.algorithmVersion,
                ephemeral.description.algorithmVersion
            );
        }
    }

    #[test]
    fn eachSetHasTheMatrixGenerationAndTheHashOfItsHeader() {
        for parameters in everySet {
            let name = parameters.description.name;
            let generation = if name.ends_with("AES") {
                MatrixGeneration::aes128
            } else {
                MatrixGeneration::shake128
            };
            assert_eq!(parameters.matrixGeneration, generation, "{name}");
            let hash = if parameters.dimension == 640 {
                HashFunction::shake128
            } else {
                HashFunction::shake256
            };
            assert_eq!(parameters.hashFunction, hash, "{name}");
        }
    }
}
