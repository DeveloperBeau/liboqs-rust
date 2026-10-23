use crate::{KEMParity, LargeStack, ParityOptions, SignatureParity, Snapshot};
use OQSNativeAlgorithmTests::{
    KEMKnownAnswerTest, KnownAnswerDigests, SignatureKnownAnswerTest, StatefulKnownAnswerDigests,
    StatefulKnownAnswerTest, TestVectorFiles,
};
use OQSNativeCOracle::{
    COracle, OracleMechanism, OracleRandomness, OracleSignatureScheme, OracleStatefulScheme,
};
use OQSNativeDomain::{KeyEncapsulating, Signing};
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

    /// The jobs of the known-answer run: each C algorithm of the digest files, KEMs first, then
    /// the signature schemes and the stateful schemes, through the Rust harness.
    pub fn knownAnswerJobs(options: &ParityOptions) -> Vec<ParityJob<'static>> {
        let isAll = options.isAll;
        let mechanismJobs = KnownAnswerDigests::kem()
            .names()
            .into_iter()
            .map(move |name| ParityJob {
                name,
                check: Box::new(move || {
                    let mechanism =
                        OracleMechanism::named(name).ok_or("the C library has no such KEM")?;
                    let digests = KnownAnswerDigests::kem();
                    let single = KEMKnownAnswerTest::digest(&mechanism, false)?;
                    Self::compareDigest(&single, digests.singleDigest(name), "single")?;
                    if isAll {
                        let all = KEMKnownAnswerTest::digest(&mechanism, true)?;
                        Self::compareDigest(&all, digests.allDigest(name), "all")?;
                    }
                    Ok(Self::knownAnswerSummary(isAll))
                }),
            });
        let schemeJobs = KnownAnswerDigests::signature()
            .names()
            .into_iter()
            .map(move |name| ParityJob {
                name,
                check: Box::new(move || {
                    let scheme = OracleSignatureScheme::named(name)
                        .ok_or("the C library has no such scheme")?;
                    let digests = KnownAnswerDigests::signature();
                    let single = SignatureKnownAnswerTest::digest(&scheme, false)?;
                    Self::compareDigest(&single, digests.singleDigest(name), "single")?;
                    if isAll {
                        let all = SignatureKnownAnswerTest::digest(&scheme, true)?;
                        Self::compareDigest(&all, digests.allDigest(name), "all")?;
                    }
                    Ok(Self::knownAnswerSummary(isAll))
                }),
            });
        // The stateful program has one run for each response file, so the digest file holds
        // one digest for each scheme.
        let statefulJobs = StatefulKnownAnswerDigests::names()
            .into_iter()
            .map(move |name| ParityJob {
                name,
                check: Box::new(move || {
                    let scheme = OracleStatefulScheme::named(name)
                        .ok_or("the C library has no such stateful scheme")?;
                    let responseFile = TestVectorFiles::responseFile(name)?;
                    let digest = StatefulKnownAnswerTest::digest(&scheme, &responseFile)?;
                    Self::compareDigest(
                        &digest,
                        StatefulKnownAnswerDigests::digest(name),
                        "response file",
                    )?;
                    Ok("response file digest identical".to_string())
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

    fn knownAnswerSummary(isAll: bool) -> String {
        if isAll { "single and all" } else { "single" }.to_string()
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
    use std::sync::Mutex;

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
        let every = ParityJob::knownAnswerJobs(&ParityOptions::parse(&[]).expect("valid"));
        assert_eq!(every.len(), 41 + 65 + 55);
        assert_eq!(every[0].name, "BIKE-L1");
        assert_eq!(every[41].name, "Falcon-1024");
        assert_eq!(every[106].name, "XMSS-SHA2_10_256");
        assert_eq!(every[160].name, "LMS_SHA256_H10_W4_H5_W8");
        let shard = ParityJob::knownAnswerJobs(
            &ParityOptions::parse(&["--shard".to_string(), "1/2".to_string()]).expect("valid"),
        );
        assert_eq!(shard.len(), 80);
        assert_eq!(shard[0].name, every[1].name);
    }
}
