use OQSNativeBIKE::BIKE;
use OQSNativeCROSS::CROSS;
use OQSNativeDomain::{KeyEncapsulating, Signing, StatefulSigning};
use OQSNativeFalcon::Falcon;
use OQSNativeFrodoKEM::FrodoKEM;
use OQSNativeHQC::HQC;
use OQSNativeMAYO::MAYO;
use OQSNativeMLDSA::MLDSA;
use OQSNativeMLKEM::{Kyber, MLKEM};
use OQSNativeNTRU::NTRU;
use OQSNativeNTRUPrime::NTRUPrime;
use OQSNativeSLHDSA::SLHDSA;

/// Every algorithm of the port, by its liboqs name.
///
/// The lists follow the order of the liboqs algorithm lists. A name is the liboqs name, such
/// as `ML-KEM-768`, and each algorithm gives the same bytes as the C algorithm of that name.
pub struct Registry;

/// The key encapsulation mechanisms.
const mechanisms: &[&dyn KeyEncapsulating] = &[
    &BIKE::bikeL1,
    &BIKE::bikeL3,
    &BIKE::bikeL5,
    &HQC::hqc1,
    &HQC::hqc3,
    &HQC::hqc5,
    &Kyber::kyber512,
    &Kyber::kyber768,
    &Kyber::kyber1024,
    &MLKEM::mlkem512,
    &MLKEM::mlkem768,
    &MLKEM::mlkem1024,
    &NTRU::ntruHPS2048509,
    &NTRU::ntruHPS2048677,
    &NTRU::ntruHPS4096821,
    &NTRU::ntruHPS40961229,
    &NTRU::ntruHRSS701,
    &NTRU::ntruHRSS1373,
    &NTRUPrime::sntrup761,
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

/// The signature schemes, in groups in the order of the liboqs list. A family with many
/// schemes gives them as one group, such as the 156 schemes of `SLHDSA::schemes`.
const signatureSchemeGroups: &[&[&dyn Signing]] = &[
    &[
        &MLDSA::mldsa44,
        &MLDSA::mldsa65,
        &MLDSA::mldsa87,
        &Falcon::falcon512,
        &Falcon::falcon1024,
        &Falcon::falconPadded512,
        &Falcon::falconPadded1024,
        &MAYO::mayo1,
        &MAYO::mayo2,
        &MAYO::mayo3,
        &MAYO::mayo5,
        &CROSS::crossRSDP128Balanced,
        &CROSS::crossRSDP128Fast,
        &CROSS::crossRSDP128Small,
        &CROSS::crossRSDP192Balanced,
        &CROSS::crossRSDP192Fast,
        &CROSS::crossRSDP192Small,
        &CROSS::crossRSDP256Balanced,
        &CROSS::crossRSDP256Fast,
        &CROSS::crossRSDP256Small,
        &CROSS::crossRSDPG128Balanced,
        &CROSS::crossRSDPG128Fast,
        &CROSS::crossRSDPG128Small,
        &CROSS::crossRSDPG192Balanced,
        &CROSS::crossRSDPG192Fast,
        &CROSS::crossRSDPG192Small,
        &CROSS::crossRSDPG256Balanced,
        &CROSS::crossRSDPG256Fast,
        &CROSS::crossRSDPG256Small,
    ],
    SLHDSA::schemes,
];

/// The signature schemes, the groups one after another.
const signatureSchemes: &[&dyn Signing] =
    &joined::<_, { countOf(signatureSchemeGroups) }>(signatureSchemeGroups);

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

/// The number of algorithms in groups.
const fn countOf<Algorithm: ?Sized>(groups: &[&[&Algorithm]]) -> usize {
    let mut count = 0;
    let mut group = 0;
    while group < groups.len() {
        count += groups[group].len();
        group += 1;
    }
    count
}

/// The algorithms of groups, one after another, in a list of `Count` algorithms. The first
/// algorithm of the groups fills the list before each place gets its algorithm, so the groups
/// must hold one algorithm or more.
const fn joined<Algorithm: ?Sized + 'static, const Count: usize>(
    groups: &[&'static [&'static Algorithm]],
) -> [&'static Algorithm; Count] {
    let mut first = 0;
    while groups[first].is_empty() {
        first += 1;
    }
    let mut list = [groups[first][0]; Count];
    let mut position = 0;
    let mut group = 0;
    while group < groups.len() {
        let mut index = 0;
        while index < groups[group].len() {
            list[position] = groups[group][index];
            position += 1;
            index += 1;
        }
        group += 1;
    }
    assert!(position == Count, "the count is the number of algorithms");
    list
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
    use super::{Named, Registry, countOf, joined, named, signatureSchemeGroups};
    use OQSNativeSLHDSA::SLHDSA;

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
    fn groupsJoinInTheirOrderAndSkipEmptyGroups() {
        const groups: &[&[&NameOnly]] = &[
            &[],
            &[&NameOnly("A-1")],
            &[],
            &[&NameOnly("B-2"), &NameOnly("C-3")],
        ];
        assert_eq!(countOf(groups), 3);
        let list: [&NameOnly; 3] = joined::<_, 3>(groups);
        let names: Vec<&str> = list.iter().map(|algorithm| algorithm.0).collect();
        assert_eq!(names, ["A-1", "B-2", "C-3"]);
        assert_eq!(countOf::<NameOnly>(&[]), 0);
    }

    #[test]
    fn signatureSchemesAreTheSchemesOfTheGroupsInOrder() {
        let names: Vec<&str> = Registry::signatureSchemes()
            .iter()
            .map(|scheme| scheme.description().name)
            .collect();
        let groupNames: Vec<&str> = signatureSchemeGroups
            .iter()
            .flat_map(|group| group.iter())
            .map(|scheme| scheme.description().name)
            .collect();
        assert_eq!(names, groupNames);
        // The 156 schemes of SLH-DSA end the list, as in liboqs.
        let slhdsaNames: Vec<&str> = SLHDSA::schemes
            .iter()
            .map(|scheme| scheme.description().name)
            .collect();
        assert_eq!(slhdsaNames.len(), 156);
        assert_eq!(names[names.len() - slhdsaNames.len()..], slhdsaNames[..]);
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
