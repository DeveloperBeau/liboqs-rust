//! Parity of every registered algorithm with the C library: the base case and the variations of
//! `PARITY_CASES` (2 by default here, and 1000 in the full gate of `parity run`), with the seed
//! of `PARITY_SEED`.
//!
//! The default suite checks the signature schemes and the stateful schemes of `SuiteSample`. The
//! C library signs a small set of SLH-DSA in one to two seconds, and generates a key of a
//! stateful tree of height 16 in two minutes, so the ignored tests check every registered
//! scheme.

use OQSNative::Registry;
use OQSNativeAlgorithmTests::SuiteSample;
use OQSNativeParity::{KEMParity, LargeStack, ParitySettings, SignatureParity, StatefulParity};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The variations of each algorithm in the test suite. The suite runs in the dev profile, where
/// the large families take a large part of a second for each variation, so the release runs of
/// `parity run` carry the full gate.
const testCaseCount: u64 = 2;

/// Runs checks on every processor, each on a thread with a large stack, and returns the
/// failures.
fn failures(checks: Vec<Box<dyn Fn() -> Result<(), String> + Send + Sync>>) -> Vec<String> {
    let next = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism().map_or(1, usize::from);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                LargeStack::run(|| {
                    while let Some(check) = checks.get(next.fetch_add(1, Ordering::SeqCst)) {
                        if let Err(message) = check() {
                            failures.lock().expect("the failure list").push(message);
                        }
                    }
                })
            });
        }
    });
    failures.into_inner().expect("the failure list")
}

#[test]
fn everyRegisteredMechanismIsIdenticalToTheCLibrary() {
    let settings = ParitySettings::fromEnvironment(testCaseCount);
    let checks = Registry::mechanisms()
        .iter()
        .map(|mechanism| {
            Box::new(move || {
                KEMParity::new(*mechanism, settings.seed)
                    .checkEveryCase(settings.caseCount)
                    .map_err(|mismatch| mismatch.to_string())
            }) as Box<dyn Fn() -> Result<(), String> + Send + Sync>
        })
        .collect();
    let failures = failures(checks);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The failures of the registered signature schemes whose names pass a filter.
fn signatureFailures(isSelected: fn(&str) -> bool) -> Vec<String> {
    let settings = ParitySettings::fromEnvironment(testCaseCount);
    let checks = Registry::signatureSchemes()
        .iter()
        .filter(|scheme| isSelected(scheme.description().name))
        .map(|scheme| {
            Box::new(move || {
                SignatureParity::new(*scheme, settings.seed)
                    .checkEveryCase(settings.caseCount)
                    .map_err(|mismatch| mismatch.to_string())
            }) as Box<dyn Fn() -> Result<(), String> + Send + Sync>
        })
        .collect();
    failures(checks)
}

#[test]
fn eachRegisteredSignatureSchemeOfTheSuiteSampleIsIdenticalToTheCLibrary() {
    let failures = signatureFailures(SuiteSample::contains);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "the C library signs each small set of SLH-DSA in one to two seconds, so the 156 SLH-DSA schemes take an hour, and parity run checks them in release builds"]
fn everyRegisteredSignatureSchemeIsIdenticalToTheCLibrary() {
    let failures = signatureFailures(|_| true);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The failures of the registered stateful schemes whose names pass a filter.
fn statefulFailures(isSelected: fn(&str) -> bool) -> Vec<String> {
    let settings = ParitySettings::fromEnvironment(testCaseCount);
    let checks = Registry::statefulSignatureSchemes()
        .iter()
        .filter(|scheme| isSelected(scheme.description().name))
        .map(|scheme| {
            Box::new(move || {
                StatefulParity::new(*scheme, settings.seed)
                    .checkEveryCase(settings.caseCount)
                    .map(|_| ())
                    .map_err(|mismatch| mismatch.to_string())
            }) as Box<dyn Fn() -> Result<(), String> + Send + Sync>
        })
        .collect();
    failures(checks)
}

#[test]
fn eachRegisteredStatefulSchemeOfTheSuiteSampleIsIdenticalToTheCLibrary() {
    let failures = statefulFailures(SuiteSample::contains);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "a key generation of a stateful set with a tree of height 16 or more takes minutes to a day, and parity run checks the stateful sets in release builds"]
fn everyRegisteredStatefulSchemeIsIdenticalToTheCLibrary() {
    let failures = statefulFailures(|_| true);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
