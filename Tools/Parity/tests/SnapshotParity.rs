//! The snapshot of the version: the frozen file `Snapshots/<version>.txt` holds the digest of
//! the base case of each KEM and signature scheme of the C library. `parity snapshot` makes it
//! from the C library, and the file is byte-identical to the snapshot of the Zig port.

use OQSNative::Registry;
use OQSNativeCOracle::{COracle, OracleRandomness};
use OQSNativeParity::{KEMParity, LargeStack, SignatureParity, Snapshot};

/// The frozen snapshot of the version in `LIBOQS_VERSION`, which is the crate version.
fn frozenSnapshot() -> Snapshot {
    let text = include_str!(concat!("../Snapshots/", env!("CARGO_PKG_VERSION"), ".txt"));
    Snapshot::parse(text).expect("the frozen snapshot is well formed")
}

#[test]
fn snapshotHoldsEveryKEMAndSignatureSchemeOfTheCLibrary() {
    let oracle = COracle::new(OracleRandomness::nist([0; 48]));
    let mut cNames: Vec<&str> = oracle
        .kemNames()
        .into_iter()
        .chain(oracle.signatureNames())
        .collect();
    cNames.sort_unstable();
    assert_eq!(frozenSnapshot().names(), cNames);
}

#[test]
fn eachRegisteredAlgorithmReproducesItsSnapshotLine() {
    let snapshot = frozenSnapshot();
    LargeStack::run(|| {
        for mechanism in Registry::mechanisms() {
            let name = mechanism.description().name;
            let fields = KEMParity::new(*mechanism, 0)
                .rustBaseCase()
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                Some(Snapshot::digest(&fields).as_str()),
                snapshot.digestOf(name),
                "{name}"
            );
        }
        for scheme in Registry::signatureSchemes() {
            let name = scheme.description().name;
            let fields = SignatureParity::new(*scheme, 0)
                .rustBaseCase()
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                Some(Snapshot::digest(&fields).as_str()),
                snapshot.digestOf(name),
                "{name}"
            );
        }
    });
}

#[test]
fn cBaseCaseOfASmallAlgorithmReproducesItsFrozenLine() {
    // The full check of the C library is `parity snapshot`, which takes minutes. One fast
    // algorithm of each kind shows here that the frozen file and the C library agree.
    let snapshot = frozenSnapshot();
    LargeStack::run(|| {
        let kemFields = KEMParity::cBaseCase("ML-KEM-512").expect("the C base case");
        assert_eq!(
            Some(Snapshot::digest(&kemFields).as_str()),
            snapshot.digestOf("ML-KEM-512")
        );
        let signatureFields = SignatureParity::cBaseCase("ML-DSA-44").expect("the C base case");
        assert_eq!(
            Some(Snapshot::digest(&signatureFields).as_str()),
            snapshot.digestOf("ML-DSA-44")
        );
    });
}
