//! Coverage of the C library: each algorithm of the C library is in the registry, with the
//! facts of the C algorithm, or in `NotYetPorted.txt`. The list shrinks with each family, and
//! the port is complete when it is empty.

use OQSNative::Registry;
use OQSNativeCOracle::{COracle, OracleRandomness};

/// The names of `NotYetPorted.txt`, one on each line.
fn notYetPorted() -> Vec<&'static str> {
    include_str!("../NotYetPorted.txt")
        .lines()
        .filter(|line| !line.is_empty())
        .collect()
}

/// The names of the C library that the registry does not hold, in liboqs order.
fn cNamesOutsideTheRegistry() -> Vec<&'static str> {
    let oracle = COracle::new(OracleRandomness::nist([0; 48]));
    let kems = oracle
        .kemNames()
        .into_iter()
        .filter(|name| Registry::mechanism(name).is_none());
    let schemes = oracle
        .signatureNames()
        .into_iter()
        .filter(|name| Registry::signatureScheme(name).is_none());
    let statefulSchemes = oracle
        .statefulSignatureNames()
        .into_iter()
        .filter(|name| Registry::statefulSignatureScheme(name).is_none());
    kems.chain(schemes).chain(statefulSchemes).collect()
}

#[test]
fn everyCAlgorithmIsRegisteredOrListedAsNotYetPorted() {
    let expected = cNamesOutsideTheRegistry();
    let listed = notYetPorted();
    assert!(
        listed == expected,
        "NotYetPorted.txt must list the C algorithms outside the registry, in liboqs order. It should be:\n{}",
        expected.join("\n")
    );
}

#[test]
fn eachRegisteredMechanismHasTheFactsOfTheCMechanism() {
    let oracle = COracle::new(OracleRandomness::nist([0; 48]));
    for mechanism in Registry::mechanisms() {
        let description = mechanism.description();
        assert_eq!(
            oracle.kemDescription(description.name).as_ref(),
            Some(description),
            "{}",
            description.name
        );
    }
    for scheme in Registry::signatureSchemes() {
        let description = scheme.description();
        assert_eq!(
            oracle.signatureDescription(description.name).as_ref(),
            Some(description),
            "{}",
            description.name
        );
    }
    for scheme in Registry::statefulSignatureSchemes() {
        let description = scheme.description();
        assert_eq!(
            oracle
                .statefulSignatureDescription(description.name)
                .as_ref(),
            Some(description),
            "{}",
            description.name
        );
    }
}

#[test]
fn theRegistryKeepsTheOrderOfTheCLists() {
    let oracle = COracle::new(OracleRandomness::nist([0; 48]));
    let inCOrder = |cNames: Vec<&'static str>, registered: Vec<&'static str>| {
        let positions: Vec<usize> = registered
            .iter()
            .map(|name| {
                cNames
                    .iter()
                    .position(|cName| cName == name)
                    .expect("a C name")
            })
            .collect();
        positions.windows(2).all(|pair| pair[0] < pair[1])
    };
    assert!(inCOrder(
        oracle.kemNames(),
        Registry::mechanisms()
            .iter()
            .map(|mechanism| mechanism.description().name)
            .collect()
    ));
    assert!(inCOrder(
        oracle.signatureNames(),
        Registry::signatureSchemes()
            .iter()
            .map(|scheme| scheme.description().name)
            .collect()
    ));
    assert!(inCOrder(
        oracle.statefulSignatureNames(),
        Registry::statefulSignatureSchemes()
            .iter()
            .map(|scheme| scheme.description().name)
            .collect()
    ));
}

#[test]
fn theListNamesOnlyAlgorithmsOfTheCLibraryAndEachOnce() {
    let oracle = COracle::new(OracleRandomness::nist([0; 48]));
    let cNames: Vec<&str> = oracle
        .kemNames()
        .into_iter()
        .chain(oracle.signatureNames())
        .chain(oracle.statefulSignatureNames())
        .collect();
    let listed = notYetPorted();
    for name in &listed {
        assert!(
            cNames.contains(name),
            "{name} is not an algorithm of the C library"
        );
    }
    let mut unique = listed.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), listed.len(), "a name is listed twice");
}
