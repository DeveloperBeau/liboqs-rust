//! Parity of every registered algorithm with the C library: the base case and the variations of
//! `PARITY_CASES` (10 by default here, and 1000 in the full gate of `parity run`), with the seed
//! of `PARITY_SEED`.

use OQSNative::Registry;
use OQSNativeParity::{KEMParity, LargeStack, ParitySettings, SignatureParity};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The variations of each algorithm in the test suite.
const testCaseCount: u64 = 10;

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

#[test]
fn everyRegisteredSignatureSchemeIsIdenticalToTheCLibrary() {
    let settings = ParitySettings::fromEnvironment(testCaseCount);
    let checks = Registry::signatureSchemes()
        .iter()
        .map(|scheme| {
            Box::new(move || {
                SignatureParity::new(*scheme, settings.seed)
                    .checkEveryCase(settings.caseCount)
                    .map_err(|mismatch| mismatch.to_string())
            }) as Box<dyn Fn() -> Result<(), String> + Send + Sync>
        })
        .collect();
    let failures = failures(checks);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
