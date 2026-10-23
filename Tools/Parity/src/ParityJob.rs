use crate::{KEMParity, LargeStack, ParityOptions, SignatureParity, Snapshot};
use OQSNativeAlgorithmTests::{
    KEMKnownAnswerTest, KnownAnswerDigests, SignatureKnownAnswerTest, StatefulKnownAnswerDigests,
    StatefulKnownAnswerTest, TestVectorFiles,
};
use OQSNativeCOracle::{
    COracle, OracleMechanism, OracleRandomness, OracleSignatureScheme, OracleStatefulScheme,
};
use OQSNativeDomain::{KeyEncapsulating, Signing, StatefulSigning};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// One algorithm of a run of the `parity` program: its name and its check.
///
/// A check gives a short summary when it passes and the reason when it fails.
pub struct ParityJob<'check> {
    /// The liboqs name of the algorithm.
    pub name: &'check str,
    /// The check of the algorithm.
    pub check: Box<dyn Fn() -> Result<String, String> + Send + Sync + 'check>,
}

impl<'check> ParityJob<'check> {
    /// The jobs of the parity gate for the selected mechanisms and schemes, mechanisms first.
    /// The positions of the shard count over both lists.
    pub fn parityJobs(
        mechanisms: &'check [&'check dyn KeyEncapsulating],
        schemes: &'check [&'check dyn Signing],
        options: &ParityOptions,
    ) -> Vec<ParityJob<'check>> {
        let settings = options.settings;
        let summary = move || format!("base case and {} variations identical", settings.caseCount);
        let mechanismJobs = mechanisms.iter().map(move |mechanism| ParityJob {
            name: mechanism.description().name,
            check: Box::new(move || {
                KEMParity::new(*mechanism, settings.seed)
                    .checkEveryCase(settings.caseCount)
                    .map(|()| summary())
                    .map_err(|mismatch| mismatch.to_string())
            }),
        });
        let schemeJobs = schemes.iter().map(move |scheme| ParityJob {
            name: scheme.description().name,
            check: Box::new(move || {
                SignatureParity::new(*scheme, settings.seed)
                    .checkEveryCase(settings.caseCount)
                    .map(|()| summary())
                    .map_err(|mismatch| mismatch.to_string())
            }),
        });
        mechanismJobs
            .chain(schemeJobs)
            .enumerate()
            .filter(|(position, job)| options.isSelected(*position, job.name))
            .map(|(_, job)| job)
            .collect()
    }

    /// The jobs of the known-answer run: each algorithm of the digest files, KEMs first, then
    /// the signature schemes and the stateful schemes.
    ///
    /// Each job runs the program on the C algorithm through the Rust harness, which proves the
    /// harness, and then on the Rust algorithm of the same name when the lists hold one, which
    /// proves the port. Each digest must equal the digest of liboqs.
    pub fn knownAnswerJobs(
        mechanisms: &'check [&'check dyn KeyEncapsulating],
        schemes: &'check [&'check dyn Signing],
        statefulSchemes: &'check [&'check dyn StatefulSigning],
        options: &ParityOptions,
    ) -> Vec<ParityJob<'check>> {
        let isAll = options.isAll;
        let mechanismJobs = KnownAnswerDigests::kem()
            .names()
            .into_iter()
            .map(move |name| ParityJob {
                name,
                check: Box::new(move || {
                    let digests = KnownAnswerDigests::kem();
                    let check = |mechanism: &dyn KeyEncapsulating, side: &str| {
                        let single = KEMKnownAnswerTest::digest(mechanism, false)?;
                        let run = format!("{side} single");
                        Self::compareDigest(&single, digests.singleDigest(name), &run)?;
                        if isAll {
                            let all = KEMKnownAnswerTest::digest(mechanism, true)?;
                            let run = format!("{side} all");
                            Self::compareDigest(&all, digests.allDigest(name), &run)?;
                        }
                        Ok::<(), String>(())
                    };
                    let cMechanism =
                        OracleMechanism::named(name).ok_or("the C library has no such KEM")?;
                    check(&cMechanism, "C")?;
                    let rustMechanism = mechanisms
                        .iter()
                        .find(|mechanism| mechanism.description().name == name);
                    if let Some(rustMechanism) = rustMechanism {
                        check(*rustMechanism, "Rust")?;
                    }
                    Ok(Self::knownAnswerSummary(isAll, rustMechanism.is_some()))
                }),
            });
        let schemeJobs = KnownAnswerDigests::signature()
            .names()
            .into_iter()
            .map(move |name| ParityJob {
                name,
                check: Box::new(move || {
                    let digests = KnownAnswerDigests::signature();
                    let check = |scheme: &dyn Signing, side: &str| {
                        let single = SignatureKnownAnswerTest::digest(scheme, false)?;
                        let run = format!("{side} single");
                        Self::compareDigest(&single, digests.singleDigest(name), &run)?;
                        if isAll {
                            let all = SignatureKnownAnswerTest::digest(scheme, true)?;
                            let run = format!("{side} all");
                            Self::compareDigest(&all, digests.allDigest(name), &run)?;
                        }
                        Ok::<(), String>(())
                    };
                    let cScheme = OracleSignatureScheme::named(name)
                        .ok_or("the C library has no such scheme")?;
                    check(&cScheme, "C")?;
                    let rustScheme = schemes
                        .iter()
                        .find(|scheme| scheme.description().name == name);
                    if let Some(rustScheme) = rustScheme {
                        check(*rustScheme, "Rust")?;
                    }
                    Ok(Self::knownAnswerSummary(isAll, rustScheme.is_some()))
                }),
            });
        // The stateful program has one run for each response file, so the digest file holds
        // one digest for each scheme.
        let statefulJobs = StatefulKnownAnswerDigests::names()
            .into_iter()
            .map(move |name| ParityJob {
                name,
                check: Box::new(move || {
                    let responseFile = TestVectorFiles::responseFile(name)?;
                    let check = |scheme: &dyn StatefulSigning, side: &str| {
                        let digest = StatefulKnownAnswerTest::digest(scheme, &responseFile)?;
                        let run = format!("{side} response file");
                        Self::compareDigest(&digest, StatefulKnownAnswerDigests::digest(name), &run)
                    };
                    let cScheme = OracleStatefulScheme::named(name)
                        .ok_or("the C library has no such stateful scheme")?;
                    check(&cScheme, "C")?;
                    let rustScheme = statefulSchemes
                        .iter()
                        .find(|scheme| scheme.description().name == name);
                    if let Some(rustScheme) = rustScheme {
                        check(*rustScheme, "Rust")?;
                    }
                    let sides = if rustScheme.is_some() {
                        "C and Rust"
                    } else {
                        "C"
                    };
                    Ok(format!("response file, {sides}"))
                }),
            });
        mechanismJobs
            .chain(schemeJobs)
            .chain(statefulJobs)
            .enumerate()
            .filter(|(position, job)| options.isSelected(*position, job.name))
            .map(|(_, job)| job)
            .collect()
    }

    /// The snapshot of the selected KEMs and signature schemes of the C library, with a line
    /// for each algorithm whose base case failed.
    pub fn cSnapshot(options: &ParityOptions) -> (Snapshot, Vec<String>) {
        let oracle = COracle::new(OracleRandomness::nist([0; 48]));
        let kemNames = oracle.kemNames();
        let signatureNames = oracle.signatureNames();
        drop(oracle);
        let mut snapshot = Snapshot::new();
        let mut failures = Vec::new();
        let names = kemNames
            .into_iter()
            .map(|name| (name, true))
            .chain(signatureNames.into_iter().map(|name| (name, false)));
        for (position, (name, isKEM)) in names.enumerate() {
            if !options.isSelected(position, name) {
                continue;
            }
            let fields = LargeStack::run(|| {
                if isKEM {
                    KEMParity::cBaseCase(name)
                } else {
                    SignatureParity::cBaseCase(name)
                }
            });
            match fields {
                Ok(fields) => snapshot.insert(name, &fields),
                Err(error) => failures.push(format!("FAIL  {name}: {error}")),
            }
        }
        (snapshot, failures)
    }

    /// The lines of a snapshot check: one line for each failed base case, and one line for
    /// each algorithm that matches or misses its frozen digest. Returns the lines and the number
    /// of failures.
    pub fn snapshotCheck(
        snapshot: &Snapshot,
        failures: &[String],
        frozen: &Snapshot,
    ) -> (Vec<String>, usize) {
        let mut lines = failures.to_vec();
        let mut failureCount = failures.len();
        for name in snapshot.names() {
            if snapshot.digestOf(name) == frozen.digestOf(name) {
                lines.push(format!("ok    {name} matches the frozen snapshot"));
            } else {
                failureCount += 1;
                lines.push(format!(
                    "FAIL  {name}: the C library does not give the frozen digest"
                ));
            }
        }
        (lines, failureCount)
    }

    /// Runs jobs on every processor, each on a large stack, and reports one line for each job
    /// as it ends. Returns the number of failed jobs.
    pub fn runAll(jobs: Vec<ParityJob<'_>>, report: &(dyn Fn(String) + Sync)) -> usize {
        let next = AtomicUsize::new(0);
        let failures = AtomicUsize::new(0);
        let workers = std::thread::available_parallelism().map_or(1, usize::from);
        std::thread::scope(|scope| {
            for _ in 0..workers.min(jobs.len()) {
                scope.spawn(|| {
                    LargeStack::run(|| {
                        while let Some(job) = jobs.get(next.fetch_add(1, Ordering::SeqCst)) {
                            let start = Instant::now();
                            let result = (job.check)();
                            let seconds = start.elapsed().as_secs_f64();
                            match result {
                                Ok(summary) => {
                                    report(format!(
                                        "ok    {} ({summary}, {seconds:.1} s)",
                                        job.name
                                    ));
                                }
                                Err(message) => {
                                    failures.fetch_add(1, Ordering::SeqCst);
                                    report(format!("FAIL  {}: {message}", job.name));
                                }
                            }
                        }
                    })
                });
            }
        });
        failures.into_inner()
    }

    /// The summary of a passed known-answer job: the runs and the sides that it checked.
    fn knownAnswerSummary(isAll: bool, hasRustAlgorithm: bool) -> String {
        let runs = if isAll { "single and all" } else { "single" };
        let sides = if hasRustAlgorithm { "C and Rust" } else { "C" };
        format!("{runs}, {sides}")
    }

    /// Compares a digest with the digest of liboqs for a run.
    pub fn compareDigest(actual: &str, expected: Option<&str>, run: &str) -> Result<(), String> {
        match expected {
            Some(expected) if expected == actual => Ok(()),
            Some(expected) => Err(format!(
                "the {run} digest is {actual}, and liboqs has {expected}"
            )),
            None => Err(format!("liboqs has no {run} digest")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ParityJob;
    use crate::{ParityOptions, Snapshot};
    use OQSNativeCOracle::{OracleMechanism, OracleSignatureScheme, OracleStatefulScheme};
    use OQSNativeDomain::{
        KeyEncapsulating, KeyStatePersisting, RandomGenerating, Signing, StatefulSigning,
    };
    use OQSNativeEntities::{
        Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes, SignatureDescription,
        StatefulSignatureDescription,
    };
    use std::sync::Mutex;

    /// A C mechanism whose shared secrets have their first bit changed, as a port with a
    /// defect in its last step gives them.
    struct ChangedSecretMechanism(OracleMechanism);

    fn changed(secret: SecretBytes) -> SecretBytes {
        let mut bytes = secret.bytes().to_vec();
        bytes[0] ^= 1;
        SecretBytes::new(bytes)
    }

    impl KeyEncapsulating for ChangedSecretMechanism {
        fn description(&self) -> &'static KEMDescription {
            self.0.description()
        }

        fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
            self.0.generateKeyPair(random)
        }

        fn generateKeyPairFromSeed(&self, seed: &[u8]) -> Result<KeyPair, OQSError> {
            self.0.generateKeyPairFromSeed(seed)
        }

        fn encapsulate(
            &self,
            publicKey: &[u8],
            random: &mut dyn RandomGenerating,
        ) -> Result<Encapsulation, OQSError> {
            let encapsulation = self.0.encapsulate(publicKey, random)?;
            Ok(Encapsulation {
                ciphertext: encapsulation.ciphertext,
                sharedSecret: changed(encapsulation.sharedSecret),
            })
        }

        fn encapsulateWithSeed(
            &self,
            publicKey: &[u8],
            seed: &[u8],
        ) -> Result<Encapsulation, OQSError> {
            self.0.encapsulateWithSeed(publicKey, seed)
        }

        fn decapsulate(
            &self,
            ciphertext: &[u8],
            secretKey: &[u8],
        ) -> Result<SecretBytes, OQSError> {
            self.0.decapsulate(ciphertext, secretKey).map(changed)
        }
    }

    /// A C scheme whose signatures have their last bit changed, and whose verification takes
    /// the change back, so the program runs to its end with other bytes.
    struct ChangedSignatureScheme(OracleSignatureScheme);

    fn flipped(signature: &[u8]) -> Vec<u8> {
        let mut signature = signature.to_vec();
        if let Some(last) = signature.last_mut() {
            *last ^= 1;
        }
        signature
    }

    impl Signing for ChangedSignatureScheme {
        fn description(&self) -> &'static SignatureDescription {
            self.0.description()
        }

        fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
            self.0.generateKeyPair(random)
        }

        fn sign(
            &self,
            message: &[u8],
            secretKey: &[u8],
            random: &mut dyn RandomGenerating,
        ) -> Result<Vec<u8>, OQSError> {
            self.0
                .sign(message, secretKey, random)
                .map(|signature| flipped(&signature))
        }

        fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
            self.0
                .isValidSignature(&flipped(signature), message, publicKey)
        }
    }

    /// A C stateful scheme whose signatures have their last bit changed.
    struct ChangedStatefulScheme(OracleStatefulScheme);

    impl StatefulSigning for ChangedStatefulScheme {
        fn description(&self) -> &'static StatefulSignatureDescription {
            self.0.description()
        }

        fn generateKeyPair(&self, random: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
            self.0.generateKeyPair(random)
        }

        fn sign(
            &self,
            message: &[u8],
            secretKey: &mut SecretBytes,
            persisting: &mut dyn KeyStatePersisting,
        ) -> Result<Vec<u8>, OQSError> {
            self.0
                .sign(message, secretKey, persisting)
                .map(|signature| flipped(&signature))
        }

        fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
            self.0
                .isValidSignature(&flipped(signature), message, publicKey)
        }

        fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
            self.0.remainingSignatureCount(secretKey)
        }

        fn totalSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
            self.0.totalSignatureCount(secretKey)
        }
    }

    fn selection(names: &[&str]) -> ParityOptions {
        let arguments: Vec<String> = names
            .iter()
            .flat_map(|name| ["--only".to_string(), name.to_string()])
            .collect();
        ParityOptions::parse(&arguments).expect("valid")
    }

    fn results(jobs: Vec<ParityJob<'_>>) -> Vec<(String, Result<String, String>)> {
        jobs.iter()
            .map(|job| (job.name.to_string(), (job.check)()))
            .collect()
    }

    #[test]
    fn knownAnswerJobsCheckTheRegisteredRustMechanismOfAName() {
        let options = selection(&["ML-KEM-512", "ML-KEM-768"]);
        let correct = OracleMechanism::named("ML-KEM-512").expect("the C mechanism");
        let mechanisms: [&dyn KeyEncapsulating; 1] = [&correct];
        assert_eq!(
            results(ParityJob::knownAnswerJobs(&mechanisms, &[], &[], &options)),
            vec![
                (
                    "ML-KEM-512".to_string(),
                    Ok("single, C and Rust".to_string())
                ),
                ("ML-KEM-768".to_string(), Ok("single, C".to_string())),
            ]
        );
        let broken =
            ChangedSecretMechanism(OracleMechanism::named("ML-KEM-512").expect("the C mechanism"));
        let mechanisms: [&dyn KeyEncapsulating; 1] = [&broken];
        let failures = results(ParityJob::knownAnswerJobs(&mechanisms, &[], &[], &options));
        let message = failures[0].1.clone().expect_err("the Rust digest differs");
        assert!(
            message.starts_with("the Rust single digest is "),
            "{message}"
        );
        assert_eq!(failures[1].1, Ok("single, C".to_string()));
    }

    #[test]
    fn knownAnswerJobsCheckTheRegisteredRustSchemeOfAName() {
        let options = selection(&["ML-DSA-44"]);
        let correct = OracleSignatureScheme::named("ML-DSA-44").expect("the C scheme");
        let schemes: [&dyn Signing; 1] = [&correct];
        assert_eq!(
            results(ParityJob::knownAnswerJobs(&[], &schemes, &[], &options)),
            vec![(
                "ML-DSA-44".to_string(),
                Ok("single, C and Rust".to_string())
            )]
        );
        let broken = ChangedSignatureScheme(
            OracleSignatureScheme::named("ML-DSA-44").expect("the C scheme"),
        );
        let schemes: [&dyn Signing; 1] = [&broken];
        let failures = results(ParityJob::knownAnswerJobs(&[], &schemes, &[], &options));
        let message = failures[0].1.clone().expect_err("the Rust digest differs");
        assert!(
            message.starts_with("the Rust single digest is "),
            "{message}"
        );
    }

    #[test]
    fn knownAnswerJobsCheckTheRegisteredRustStatefulSchemeOfAName() {
        let options = selection(&["XMSS-SHA2_10_256"]);
        let correct = OracleStatefulScheme::named("XMSS-SHA2_10_256").expect("the C scheme");
        let schemes: [&dyn StatefulSigning; 1] = [&correct];
        assert_eq!(
            results(ParityJob::knownAnswerJobs(&[], &[], &schemes, &options)),
            vec![(
                "XMSS-SHA2_10_256".to_string(),
                Ok("response file, C and Rust".to_string())
            )]
        );
        let broken = ChangedStatefulScheme(
            OracleStatefulScheme::named("XMSS-SHA2_10_256").expect("the C scheme"),
        );
        let schemes: [&dyn StatefulSigning; 1] = [&broken];
        let failures = results(ParityJob::knownAnswerJobs(&[], &[], &schemes, &options));
        assert_eq!(
            failures[0].1,
            Err(
                "XMSS-SHA2_10_256: the signature differs from the signature of the file"
                    .to_string()
            )
        );
    }

    fn job(name: &'static str, isPassing: bool) -> ParityJob<'static> {
        ParityJob {
            name,
            check: Box::new(move || {
                if isPassing {
                    Ok("fine".to_string())
                } else {
                    Err("broken".to_string())
                }
            }),
        }
    }

    #[test]
    fn runAllReportsEachJobOnceAndCountsTheFailures() {
        let lines = Mutex::new(Vec::new());
        let failures = ParityJob::runAll(
            vec![
                job("A", true),
                job("B", false),
                job("C", true),
                job("D", false),
            ],
            &|line| lines.lock().expect("lines").push(line),
        );
        assert_eq!(failures, 2);
        let mut lines = lines.into_inner().expect("lines");
        lines.sort();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("FAIL  B: broken"));
        assert!(lines[1].starts_with("FAIL  D: broken"));
        assert!(lines[2].starts_with("ok    A (fine, "));
        assert!(lines[3].starts_with("ok    C (fine, "));
    }

    #[test]
    fn runAllOfNoJobReportsNothing() {
        assert_eq!(ParityJob::runAll(Vec::new(), &|_| panic!("no line")), 0);
    }

    #[test]
    fn snapshotCheckCountsEachFailureAndEachMissedDigest() {
        let mut snapshot = Snapshot::new();
        snapshot.insert("A", &[("pk", vec![1])]);
        snapshot.insert("B", &[("pk", vec![2])]);
        snapshot.insert("C", &[("pk", vec![3])]);
        let mut frozen = Snapshot::new();
        frozen.insert("A", &[("pk", vec![1])]);
        frozen.insert("B", &[("pk", vec![9])]);
        let (lines, failureCount) =
            ParityJob::snapshotCheck(&snapshot, &["FAIL  D: broken".to_string()], &frozen);
        assert_eq!(failureCount, 3);
        assert_eq!(
            lines,
            vec![
                "FAIL  D: broken",
                "ok    A matches the frozen snapshot",
                "FAIL  B: the C library does not give the frozen digest",
                "FAIL  C: the C library does not give the frozen digest",
            ]
        );
        assert_eq!(ParityJob::snapshotCheck(&frozen, &[], &frozen).1, 0);
    }

    #[test]
    fn compareDigestNamesTheRunAndBothDigests() {
        assert_eq!(ParityJob::compareDigest("ab", Some("ab"), "single"), Ok(()));
        assert_eq!(
            ParityJob::compareDigest("ab", Some("cd"), "all"),
            Err("the all digest is ab, and liboqs has cd".to_string())
        );
        assert_eq!(
            ParityJob::compareDigest("ab", None, "single"),
            Err("liboqs has no single digest".to_string())
        );
    }

    #[test]
    fn knownAnswerJobsFollowTheDigestFilesAndTheSelection() {
        let every =
            ParityJob::knownAnswerJobs(&[], &[], &[], &ParityOptions::parse(&[]).expect("valid"));
        assert_eq!(every.len(), 41 + 65 + 55);
        assert_eq!(every[0].name, "BIKE-L1");
        assert_eq!(every[41].name, "Falcon-1024");
        assert_eq!(every[106].name, "XMSS-SHA2_10_256");
        assert_eq!(every[160].name, "LMS_SHA256_H10_W4_H5_W8");
        let shard = ParityJob::knownAnswerJobs(
            &[],
            &[],
            &[],
            &ParityOptions::parse(&["--shard".to_string(), "1/2".to_string()]).expect("valid"),
        );
        assert_eq!(shard.len(), 80);
        assert_eq!(shard[0].name, every[1].name);
    }
}
