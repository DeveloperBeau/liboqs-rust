use crate::{ParityMismatch, VariationGenerator};
use OQSNativeAlgorithmTests::KnownAnswerRandom;
use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeDomain::KeyEncapsulating;
use OQSNativeEntities::OQSError;
use OQSNativeKATRandom::NISTKATRandom;

/// The parity check of a Rust KEM with the C KEM of the same name.
///
/// The base case is the scheme of the Swift and Zig ports: the NIST KAT generator, seeded with
/// the bytes 0 to 47, before the key pair and again before the encapsulation. Each variation
/// draws its own entropy inputs and checks the key pair, the encapsulation, the decapsulation
/// of each side by the other side, a changed ciphertext, a short ciphertext and the seeded
/// forms.
pub struct KEMParity<'mechanism> {
    mechanism: &'mechanism dyn KeyEncapsulating,
    seed: u64,
}

/// The snapshot fields of a KEM base case, in the sorted order of their names.
pub type KEMBaseCase = Vec<(&'static str, Vec<u8>)>;

impl<'mechanism> KEMParity<'mechanism> {
    /// Makes the check of a mechanism with the seed of a run.
    pub fn new(mechanism: &'mechanism dyn KeyEncapsulating, seed: u64) -> Self {
        KEMParity { mechanism, seed }
    }

    /// Checks the base case and the variations `0..caseCount`.
    pub fn checkEveryCase(&self, caseCount: u64) -> Result<(), ParityMismatch> {
        self.checkBaseCase()?;
        (0..caseCount).try_for_each(|case| self.checkCase(case))
    }

    /// The base case of the C mechanism of a name: `ct`, `pk`, `sk`, `ss` and `ss2`.
    pub fn cBaseCase(name: &str) -> Result<KEMBaseCase, OQSError> {
        let keyPair =
            COracle::new(OracleRandomness::nist(countingEntropy())).generateKEMKeyPair(name)?;
        let mut oracle = COracle::new(OracleRandomness::nist(countingEntropy()));
        let encapsulation = oracle.encapsulate(name, &keyPair.publicKey)?;
        let recovered =
            oracle.decapsulate(name, &encapsulation.ciphertext, keyPair.secretKey.bytes())?;
        Ok(vec![
            ("ct", encapsulation.ciphertext),
            ("pk", keyPair.publicKey),
            ("sk", keyPair.secretKey.bytes().to_vec()),
            ("ss", encapsulation.sharedSecret.bytes().to_vec()),
            ("ss2", recovered.bytes().to_vec()),
        ])
    }

    /// The base case of the Rust mechanism, with the fields of `cBaseCase`.
    pub fn rustBaseCase(&self) -> Result<KEMBaseCase, OQSError> {
        let keyPair = self
            .mechanism
            .generateKeyPair(&mut NISTKATRandom::new(&countingEntropy(), None))?;
        let encapsulation = self.mechanism.encapsulate(
            &keyPair.publicKey,
            &mut NISTKATRandom::new(&countingEntropy(), None),
        )?;
        let recovered = self
            .mechanism
            .decapsulate(&encapsulation.ciphertext, keyPair.secretKey.bytes())?;
        Ok(vec![
            ("ct", encapsulation.ciphertext),
            ("pk", keyPair.publicKey),
            ("sk", keyPair.secretKey.bytes().to_vec()),
            ("ss", encapsulation.sharedSecret.bytes().to_vec()),
            ("ss2", recovered.bytes().to_vec()),
        ])
    }

    /// Checks the base case.
    pub fn checkBaseCase(&self) -> Result<(), ParityMismatch> {
        let name = self.mechanism.description().name;
        let mismatch = |step: &'static str, detail: String| ParityMismatch {
            algorithm: name.to_string(),
            case: None,
            seed: self.seed,
            step,
            detail,
        };
        let cFields =
            Self::cBaseCase(name).map_err(|error| mismatch("C base case", error.to_string()))?;
        let rustFields = self
            .rustBaseCase()
            .map_err(|error| mismatch("Rust base case", error.to_string()))?;
        for ((field, cBytes), (_, rustBytes)) in cFields.iter().zip(&rustFields) {
            if let Some(detail) = ParityMismatch::difference(cBytes, rustBytes) {
                return Err(mismatch(field, detail));
            }
        }
        Ok(())
    }

    /// Checks one variation.
    pub fn checkCase(&self, case: u64) -> Result<(), ParityMismatch> {
        let description = self.mechanism.description();
        let name = description.name;
        let mismatch = |step: &'static str, detail: String| ParityMismatch {
            algorithm: name.to_string(),
            case: Some(case),
            seed: self.seed,
            step,
            detail,
        };
        let compare =
            |step: &'static str, cBytes: &[u8], rustBytes: &[u8]| match ParityMismatch::difference(
                cBytes, rustBytes,
            ) {
                Some(detail) => Err(mismatch(step, detail)),
                None => Ok(()),
            };
        let mut generator = VariationGenerator::forCase(self.seed, name, case);
        let keyPairEntropy = generator.entropy();
        let encapsulationEntropy = generator.entropy();

        let cKeys = COracle::new(OracleRandomness::knownAnswer {
            algorithm: name,
            entropy: keyPairEntropy,
        })
        .generateKEMKeyPair(name);
        let rustKeys = self
            .mechanism
            .generateKeyPair(KnownAnswerRandom::generator(name, &keyPairEntropy).as_mut());
        let (cKeys, rustKeys) = match (cKeys, rustKeys) {
            (Ok(cKeys), Ok(rustKeys)) => (cKeys, rustKeys),
            (cKeys, rustKeys) => {
                return agreeOnFailure("key pair", &cKeys, &rustKeys)
                    .map_err(|detail| mismatch("key pair", detail));
            }
        };
        compare("public key", &cKeys.publicKey, &rustKeys.publicKey)?;
        compare(
            "secret key",
            cKeys.secretKey.bytes(),
            rustKeys.secretKey.bytes(),
        )?;

        let cEncapsulation = COracle::new(OracleRandomness::knownAnswer {
            algorithm: name,
            entropy: encapsulationEntropy,
        })
        .encapsulate(name, &cKeys.publicKey);
        let rustEncapsulation = self.mechanism.encapsulate(
            &rustKeys.publicKey,
            KnownAnswerRandom::generator(name, &encapsulationEntropy).as_mut(),
        );
        let (cEncapsulation, rustEncapsulation) = match (cEncapsulation, rustEncapsulation) {
            (Ok(cEncapsulation), Ok(rustEncapsulation)) => (cEncapsulation, rustEncapsulation),
            (cResult, rustResult) => {
                return agreeOnFailure("encapsulation", &cResult, &rustResult)
                    .map_err(|detail| mismatch("encapsulation", detail));
            }
        };
        compare(
            "ciphertext",
            &cEncapsulation.ciphertext,
            &rustEncapsulation.ciphertext,
        )?;
        compare(
            "shared secret",
            cEncapsulation.sharedSecret.bytes(),
            rustEncapsulation.sharedSecret.bytes(),
        )?;

        // Each side decapsulates the ciphertext of the other side with the key of the other side.
        let cRecovered = COracle::new(OracleRandomness::nist([0; 48])).decapsulate(
            name,
            &rustEncapsulation.ciphertext,
            rustKeys.secretKey.bytes(),
        );
        match cRecovered {
            Ok(secret) => compare(
                "C decapsulation of the Rust ciphertext",
                secret.bytes(),
                rustEncapsulation.sharedSecret.bytes(),
            )?,
            Err(error) => {
                return Err(mismatch(
                    "C decapsulation of the Rust ciphertext",
                    error.to_string(),
                ));
            }
        }
        match self
            .mechanism
            .decapsulate(&cEncapsulation.ciphertext, cKeys.secretKey.bytes())
        {
            Ok(secret) => compare(
                "Rust decapsulation of the C ciphertext",
                secret.bytes(),
                cEncapsulation.sharedSecret.bytes(),
            )?,
            Err(error) => {
                return Err(mismatch(
                    "Rust decapsulation of the C ciphertext",
                    error.to_string(),
                ));
            }
        }

        // A changed ciphertext: both sides give the same answer, the same implicit-rejection
        // secret or the same failure.
        let ciphertext = &cEncapsulation.ciphertext;
        let changed = generator.withChangedBit(ciphertext);
        let cChanged = COracle::new(OracleRandomness::nist([0; 48])).decapsulate(
            name,
            &changed,
            cKeys.secretKey.bytes(),
        );
        let rustChanged = self
            .mechanism
            .decapsulate(&changed, cKeys.secretKey.bytes());
        agree(&cChanged, &rustChanged, |secret| secret.bytes())
            .map_err(|detail| mismatch("decapsulation of a changed ciphertext", detail))?;

        // A short ciphertext is a failure on both sides.
        let short = &ciphertext[..ciphertext.len() - 1];
        let cShort = COracle::new(OracleRandomness::nist([0; 48])).decapsulate(
            name,
            short,
            cKeys.secretKey.bytes(),
        );
        let rustShort = self.mechanism.decapsulate(short, cKeys.secretKey.bytes());
        agree(&cShort, &rustShort, |secret| secret.bytes())
            .map_err(|detail| mismatch("decapsulation of a short ciphertext", detail))?;

        // The seeded forms, or the same refusal on both sides.
        let keyPairSeed = generator.bytes(description.keyPairSeedLength.max(1));
        let cSeeded = COracle::new(OracleRandomness::nist([0; 48]))
            .generateKEMKeyPairFromSeed(name, &keyPairSeed);
        let rustSeeded = self.mechanism.generateKeyPairFromSeed(&keyPairSeed);
        agree(&cSeeded, &rustSeeded, |keyPair| &keyPair.publicKey)
            .map_err(|detail| mismatch("public key from a seed", detail))?;
        agree(&cSeeded, &rustSeeded, |keyPair| keyPair.secretKey.bytes())
            .map_err(|detail| mismatch("secret key from a seed", detail))?;
        let encapsulationSeed = generator.bytes(description.encapsulationSeedLength.max(1));
        let cSeededEncapsulation = COracle::new(OracleRandomness::nist([0; 48]))
            .encapsulateWithSeed(name, &cKeys.publicKey, &encapsulationSeed);
        let rustSeededEncapsulation = self
            .mechanism
            .encapsulateWithSeed(&cKeys.publicKey, &encapsulationSeed);
        agree(
            &cSeededEncapsulation,
            &rustSeededEncapsulation,
            |encapsulation| &encapsulation.ciphertext,
        )
        .map_err(|detail| mismatch("ciphertext from a seed", detail))?;
        agree(
            &cSeededEncapsulation,
            &rustSeededEncapsulation,
            |encapsulation| encapsulation.sharedSecret.bytes(),
        )
        .map_err(|detail| mismatch("shared secret from a seed", detail))
    }
}

/// The entropy input of the base case: the bytes 0 to 47.
pub(crate) fn countingEntropy() -> [u8; 48] {
    std::array::from_fn(|index| index as u8)
}

/// Agreement of two outcomes: equal bytes, or a failure on both sides.
pub(crate) fn agree<T>(
    cResult: &Result<T, OQSError>,
    rustResult: &Result<T, OQSError>,
    bytes: impl Fn(&T) -> &[u8],
) -> Result<(), String> {
    match (cResult, rustResult) {
        (Ok(cValue), Ok(rustValue)) => {
            ParityMismatch::difference(bytes(cValue), bytes(rustValue)).map_or(Ok(()), Err)
        }
        (Err(_), Err(_)) => Ok(()),
        (Ok(_), Err(error)) => Err(format!("C succeeds and Rust fails: {error}")),
        (Err(error), Ok(_)) => Err(format!("Rust succeeds and C fails: {error}")),
    }
}

/// Agreement of two outcomes of which at least one is a failure.
pub(crate) fn agreeOnFailure<T>(
    step: &str,
    cResult: &Result<T, OQSError>,
    rustResult: &Result<T, OQSError>,
) -> Result<(), String> {
    match (cResult, rustResult) {
        (Err(_), Err(_)) => Ok(()),
        (Ok(_), Err(error)) => Err(format!(
            "the C {step} succeeds and the Rust one fails: {error}"
        )),
        (Err(error), Ok(_)) => Err(format!(
            "the Rust {step} succeeds and the C one fails: {error}"
        )),
        (Ok(_), Ok(_)) => Ok(()),
    }
}
