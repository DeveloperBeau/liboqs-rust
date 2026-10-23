use OQSNativeDomain::{KeyEncapsulating, Signing, StatefulSigning};
use OQSNativeFrodoKEM::FrodoKEM;
use OQSNativeHQC::HQC;
use OQSNativeMLKEM::{Kyber, MLKEM};

/// Every algorithm of the port, by its liboqs name.
///
/// The lists follow the order of the liboqs algorithm lists. A name is the liboqs name, such
/// as `ML-KEM-768`, and each algorithm gives the same bytes as the C algorithm of that name.
pub struct Registry;

/// The key encapsulation mechanisms.
const mechanisms: &[&dyn KeyEncapsulating] = &[
    &HQC::hqc1,
    &HQC::hqc3,
    &HQC::hqc5,
    &Kyber::kyber512,
    &Kyber::kyber768,
    &Kyber::kyber1024,
    &MLKEM::mlkem512,
    &MLKEM::mlkem768,
    &MLKEM::mlkem1024,
    &FrodoKEM::frodoKEM640AES,
    &FrodoKEM::frodoKEM640SHAKE,
    &FrodoKEM::frodoKEM976AES,
    &FrodoKEM::frodoKEM976SHAKE,
    &FrodoKEM::frodoKEM1344AES,
    &FrodoKEM::frodoKEM1344SHAKE,
    &FrodoKEM::eFrodoKEM640AES,
    &FrodoKEM::eFrodoKEM640SHAKE,
    &FrodoKEM::eFrodoKEM976AES,
    &FrodoKEM::eFrodoKEM976SHAKE,
    &FrodoKEM::eFrodoKEM1344AES,
    &FrodoKEM::eFrodoKEM1344SHAKE,
];

/// The signature schemes.
const signatureSchemes: &[&dyn Signing] = &[];

/// The stateful signature schemes.
const statefulSignatureSchemes: &[&dyn StatefulSigning] = &[];

/// An algorithm with a liboqs name, so that one lookup serves the three lists.
trait Named {
    fn liboqsName(&self) -> &'static str;
}

impl Named for dyn KeyEncapsulating {
    fn liboqsName(&self) -> &'static str {
        self.description().name
    }
}

impl Named for dyn Signing {
    fn liboqsName(&self) -> &'static str {
        self.description().name
    }
}

impl Named for dyn StatefulSigning {
    fn liboqsName(&self) -> &'static str {
        self.description().name
    }
}

/// The algorithm of a list with a name, or `None`.
fn named<Algorithm: Named + ?Sized>(
    list: &'static [&'static Algorithm],
    name: &str,
) -> Option<&'static Algorithm> {
    list.iter()
        .copied()
        .find(|algorithm| algorithm.liboqsName() == name)
}

impl Registry {
    /// Every key encapsulation mechanism.
    pub fn mechanisms() -> &'static [&'static dyn KeyEncapsulating] {
        mechanisms
    }

    /// The key encapsulation mechanism of a liboqs name, or `None` when the port has none.
    pub fn mechanism(named: &str) -> Option<&'static dyn KeyEncapsulating> {
        self::named(mechanisms, named)
    }

    /// Every signature scheme.
    pub fn signatureSchemes() -> &'static [&'static dyn Signing] {
        signatureSchemes
    }

    /// The signature scheme of a liboqs name, or `None` when the port has none.
    pub fn signatureScheme(named: &str) -> Option<&'static dyn Signing> {
        self::named(signatureSchemes, named)
    }

    /// Every stateful signature scheme.
    pub fn statefulSignatureSchemes() -> &'static [&'static dyn StatefulSigning] {
        statefulSignatureSchemes
    }

    /// The stateful signature scheme of a liboqs name, or `None` when the port has none.
    pub fn statefulSignatureScheme(named: &str) -> Option<&'static dyn StatefulSigning> {
        self::named(statefulSignatureSchemes, named)
    }
}

#[cfg(test)]
mod tests {
    use super::{Named, Registry, named};

    /// A test algorithm that is only a name.
    struct NameOnly(&'static str);

    impl Named for NameOnly {
        fn liboqsName(&self) -> &'static str {
            self.0
        }
    }

    const testList: &[&NameOnly] = &[&NameOnly("A-1"), &NameOnly("B-2"), &NameOnly("C-3")];

    #[test]
    fn lookupFindsTheAlgorithmOfTheExactName() {
        assert_eq!(named(testList, "B-2").map(|found| found.0), Some("B-2"));
        assert_eq!(named(testList, "C-3").map(|found| found.0), Some("C-3"));
        assert!(named(testList, "b-2").is_none());
        assert!(named(testList, "B").is_none());
    }

    #[test]
    fn everyNameIsUniqueAcrossTheThreeLists() {
        let mut names: Vec<&str> = Registry::mechanisms()
            .iter()
            .map(|mechanism| mechanism.description().name)
            .chain(
                Registry::signatureSchemes()
                    .iter()
                    .map(|scheme| scheme.description().name),
            )
            .chain(
                Registry::statefulSignatureSchemes()
                    .iter()
                    .map(|scheme| scheme.description().name),
            )
            .collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn eachAlgorithmIsFoundByItsOwnName() {
        for mechanism in Registry::mechanisms() {
            let name = mechanism.description().name;
            assert_eq!(
                Registry::mechanism(name).map(|found| found.description().name),
                Some(name)
            );
        }
        for scheme in Registry::signatureSchemes() {
            let name = scheme.description().name;
            assert_eq!(
                Registry::signatureScheme(name).map(|found| found.description().name),
                Some(name)
            );
        }
        for scheme in Registry::statefulSignatureSchemes() {
            let name = scheme.description().name;
            assert_eq!(
                Registry::statefulSignatureScheme(name).map(|found| found.description().name),
                Some(name)
            );
        }
    }

    #[test]
    fn anUnknownNameFindsNothing() {
        assert!(Registry::mechanism("No-Such-KEM").is_none());
        assert!(Registry::signatureScheme("No-Such-Scheme").is_none());
        assert!(Registry::statefulSignatureScheme("No-Such-Scheme").is_none());
    }
}
