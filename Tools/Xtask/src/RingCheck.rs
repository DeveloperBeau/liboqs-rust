use crate::DependencyKind;
use crate::FileReading;
use crate::Finding;
use crate::MarkdownTable;
use crate::WorkspaceLayout;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Checks that each crate depends only on the rings and the third-party crates that the
/// registers allow.
#[derive(Debug)]
pub struct RingCheck {
    allowedRings: BTreeMap<String, AllowedRings>,
    approvedDependencies: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug)]
struct AllowedRings {
    inCode: BTreeSet<String>,
    inTests: BTreeSet<String>,
}

impl RingCheck {
    /// The name of the check in each finding.
    pub const name: &'static str = "rings";
    /// The register that says which ring may depend on which ring.
    pub const ringRegisterPath: &'static str = "Documentation/Registers/RingDependencies.md";
    /// The register of the third-party crates that the owner approved.
    pub const approvedDependenciesPath: &'static str =
        "Documentation/Registers/ApprovedDependencies.md";

    /// Reads the rules from the two registers.
    pub fn load(files: &dyn FileReading) -> Result<Self, Finding> {
        let ringTable = Self::table(files, Self::ringRegisterPath)?;
        let (Some(rings), Some(inCode), Some(inTests)) = (
            ringTable.column("Ring"),
            ringTable.column("May depend on"),
            ringTable.column("May use in tests"),
        ) else {
            return Err(Self::registerFinding(
                Self::ringRegisterPath,
                "needs the columns Ring, May depend on, May use in tests",
            ));
        };
        let mut allowedRings = BTreeMap::new();
        for ((ring, inCode), inTests) in rings.iter().zip(inCode).zip(inTests) {
            let inCode: BTreeSet<String> = MarkdownTable::listItems(inCode).into_iter().collect();
            let mut inTests: BTreeSet<String> =
                MarkdownTable::listItems(inTests).into_iter().collect();
            // Whatever the code may use, its tests may use too.
            inTests.extend(inCode.iter().cloned());
            allowedRings.insert(
                ring.trim_matches('`').to_string(),
                AllowedRings { inCode, inTests },
            );
        }
        let dependencyTable = Self::table(files, Self::approvedDependenciesPath)?;
        let (Some(names), Some(users)) = (
            dependencyTable.column("Dependency"),
            dependencyTable.column("Used by"),
        ) else {
            return Err(Self::registerFinding(
                Self::approvedDependenciesPath,
                "needs the columns Dependency, Used by",
            ));
        };
        let approvedDependencies = names
            .iter()
            .zip(users)
            .map(|(name, users)| {
                (
                    name.trim_matches('`').to_string(),
                    MarkdownTable::listItems(users).into_iter().collect(),
                )
            })
            .collect();
        Ok(RingCheck {
            allowedRings,
            approvedDependencies,
        })
    }

    /// Returns a finding for each crate without a known ring and for each forbidden dependency.
    pub fn findings(&self, layout: &WorkspaceLayout) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut ringOfPackage: BTreeMap<String, String> = BTreeMap::new();
        for member in &layout.members {
            let path = &member.manifestPath;
            match (member.manifest.packageName(), member.manifest.ring()) {
                (None, _) => findings.push(Finding::new(
                    Self::name,
                    path,
                    0,
                    "the manifest has no package name",
                )),
                (Some(_), None) => findings.push(Finding::new(
                    Self::name,
                    path,
                    0,
                    "the crate declares no ring in [package.metadata]",
                )),
                (Some(_), Some(ring)) if !self.allowedRings.contains_key(&ring) => {
                    let line = member
                        .manifest
                        .line("package.metadata", "ring")
                        .unwrap_or(0);
                    findings.push(Finding::new(
                        Self::name,
                        path,
                        line,
                        format!("ring `{ring}` is not in the ring register"),
                    ));
                }
                (Some(package), Some(ring)) => {
                    ringOfPackage.insert(package, ring);
                }
            }
        }
        let workspacePaths: BTreeSet<String> = layout
            .rootManifest
            .workspacePathDependencies()
            .into_iter()
            .collect();
        for member in &layout.members {
            let (Some(package), Some(ring)) =
                (member.manifest.packageName(), member.manifest.ring())
            else {
                continue;
            };
            let Some(allowed) = self.allowedRings.get(&ring) else {
                continue;
            };
            for dependency in member.manifest.dependencies() {
                let path = &member.manifestPath;
                // A dependency with only a version comes from the registry, even when a member
                // has the same name, so only a path makes a dependency local.
                let isLocal = dependency.hasPath
                    || (dependency.isInheritedFromWorkspace
                        && workspacePaths.contains(&dependency.packageName));
                if isLocal {
                    let Some(targetRing) = ringOfPackage.get(&dependency.packageName) else {
                        findings.push(Finding::new(
                            Self::name,
                            path,
                            dependency.line,
                            format!(
                                "`{}` is a local crate outside the workspace members",
                                dependency.packageName
                            ),
                        ));
                        continue;
                    };
                    let rings = match dependency.kind {
                        DependencyKind::development => &allowed.inTests,
                        DependencyKind::normal | DependencyKind::build => &allowed.inCode,
                    };
                    if !rings.contains(targetRing) {
                        findings.push(Finding::new(
                            Self::name,
                            path,
                            dependency.line,
                            format!(
                                "ring `{ring}` may not depend on ring `{targetRing}` (`{}`)",
                                dependency.packageName
                            ),
                        ));
                    }
                } else {
                    let isApproved = self
                        .approvedDependencies
                        .get(&dependency.packageName)
                        .is_some_and(|users| users.contains(&package) || users.contains("*"));
                    if !isApproved {
                        findings.push(Finding::new(
                            Self::name,
                            path,
                            dependency.line,
                            format!(
                                "third-party crate `{}` is not approved for `{package}`",
                                dependency.packageName
                            ),
                        ));
                    }
                }
            }
        }
        findings
    }

    fn table(files: &dyn FileReading, path: &str) -> Result<MarkdownTable, Finding> {
        let text = files
            .text(Path::new(path))
            .map_err(|error| Self::registerFinding(path, &error.to_string()))?;
        MarkdownTable::firstTable(&text)
            .ok_or_else(|| Self::registerFinding(path, "the register has no table"))
    }

    fn registerFinding(path: &str, message: &str) -> Finding {
        Finding::new(Self::name, Path::new(path), 0, message)
    }
}

#[cfg(test)]
mod tests {
    use super::RingCheck;
    use crate::MemoryFileSystem;
    use crate::SeededGenerator;
    use crate::WorkspaceLayout;

    const ringRegister: &str = "| Ring | May depend on | May use in tests |\n|---|---|---|\n\
| entities | none | none |\n\
| domain | entities | none |\n\
| sharedComponents | entities, sharedComponents | none |\n\
| infrastructure | entities, domain, sharedComponents | none |\n\
| features | entities, domain, sharedComponents | infrastructure |\n\
| composition | entities, domain, sharedComponents, infrastructure, features | none |\n\
| tooling | entities, domain, sharedComponents, infrastructure, features, composition | none |\n";

    const approvedRegister: &str = "| Dependency | Used by | Reason |\n|---|---|---|\n| `approvedCrate` | `alpha` | test |\n| `everywhere` | * | test |\n";

    const rings: [&str; 7] = [
        "entities",
        "domain",
        "sharedComponents",
        "infrastructure",
        "features",
        "composition",
        "tooling",
    ];

    /// The allowed edges, written by hand from the ring table in `standards.md`, not read from
    /// the register, so that the test does not check the register against itself.
    fn isAllowedByHand(from: &str, to: &str, isTest: bool) -> bool {
        let code: &[&str] = match from {
            "entities" => &[],
            "domain" => &["entities"],
            "sharedComponents" => &["entities", "sharedComponents"],
            "infrastructure" => &["entities", "domain", "sharedComponents"],
            "features" => &["entities", "domain", "sharedComponents"],
            "composition" => &[
                "entities",
                "domain",
                "sharedComponents",
                "infrastructure",
                "features",
            ],
            "tooling" => &[
                "entities",
                "domain",
                "sharedComponents",
                "infrastructure",
                "features",
                "composition",
            ],
            _ => unreachable!(),
        };
        code.contains(&to) || (isTest && from == "features" && to == "infrastructure")
    }

    fn repository(members: &[(&str, &str)]) -> MemoryFileSystem {
        let mut files = MemoryFileSystem::withFiles(&[
            ("Cargo.toml", "[workspace]\nmembers = [\"Modules/*\"]\n"),
            (RingCheck::ringRegisterPath, ringRegister),
            (RingCheck::approvedDependenciesPath, approvedRegister),
        ]);
        for (path, text) in members {
            files.add(path, text);
        }
        files
    }

    fn crateManifest(name: &str, ring: &str, dependencies: &str) -> String {
        format!(
            "[package]\nname = \"{name}\"\n\n[package.metadata]\nring = \"{ring}\"\n\n{dependencies}"
        )
    }

    fn findingMessages(files: &MemoryFileSystem) -> Vec<String> {
        let check = RingCheck::load(files).expect("registers");
        let layout = WorkspaceLayout::load(files).expect("layout");
        check
            .findings(&layout)
            .into_iter()
            .map(|finding| finding.message)
            .collect()
    }

    #[test]
    fn allowedEdgeHasNoFinding() {
        let files = repository(&[
            (
                "Modules/A/Cargo.toml",
                &crateManifest(
                    "alpha",
                    "domain",
                    "[dependencies]\nbeta = { path = \"../B\" }\n",
                ),
            ),
            (
                "Modules/B/Cargo.toml",
                &crateManifest("beta", "entities", ""),
            ),
        ]);
        assert!(findingMessages(&files).is_empty());
    }

    #[test]
    fn inwardRingDependingOnOutwardRingIsAFinding() {
        let files = repository(&[
            (
                "Modules/A/Cargo.toml",
                &crateManifest(
                    "alpha",
                    "entities",
                    "[dependencies]\nbeta = { path = \"../B\" }\n",
                ),
            ),
            ("Modules/B/Cargo.toml", &crateManifest("beta", "domain", "")),
        ]);
        assert_eq!(
            findingMessages(&files),
            vec!["ring `entities` may not depend on ring `domain` (`beta`)"]
        );
    }

    #[test]
    fn featureMayUseInfrastructureInTestsButNotInCode() {
        let testOnly = repository(&[
            (
                "Modules/A/Cargo.toml",
                &crateManifest(
                    "alpha",
                    "features",
                    "[dev-dependencies]\nbeta = { path = \"../B\" }\n",
                ),
            ),
            (
                "Modules/B/Cargo.toml",
                &crateManifest("beta", "infrastructure", ""),
            ),
        ]);
        assert!(findingMessages(&testOnly).is_empty());
        let inCode = repository(&[
            (
                "Modules/A/Cargo.toml",
                &crateManifest(
                    "alpha",
                    "features",
                    "[dependencies]\nbeta = { path = \"../B\" }\n",
                ),
            ),
            (
                "Modules/B/Cargo.toml",
                &crateManifest("beta", "infrastructure", ""),
            ),
        ]);
        assert_eq!(
            findingMessages(&inCode),
            vec!["ring `features` may not depend on ring `infrastructure` (`beta`)"]
        );
    }

    #[test]
    fn featureDependingOnAnotherFeatureIsAFinding() {
        let files = repository(&[
            (
                "Modules/A/Cargo.toml",
                &crateManifest(
                    "alpha",
                    "features",
                    "[dependencies]\nbeta = { path = \"../B\" }\n",
                ),
            ),
            (
                "Modules/B/Cargo.toml",
                &crateManifest("beta", "features", ""),
            ),
        ]);
        assert_eq!(
            findingMessages(&files),
            vec!["ring `features` may not depend on ring `features` (`beta`)"]
        );
    }

    #[test]
    fn nothingMayDependOnTooling() {
        let files = repository(&[
            (
                "Modules/A/Cargo.toml",
                &crateManifest(
                    "alpha",
                    "composition",
                    "[dependencies]\nbeta = { path = \"../B\" }\n",
                ),
            ),
            (
                "Modules/B/Cargo.toml",
                &crateManifest("beta", "tooling", ""),
            ),
        ]);
        assert_eq!(
            findingMessages(&files),
            vec!["ring `composition` may not depend on ring `tooling` (`beta`)"]
        );
    }

    #[test]
    fn workspaceInheritedPathDependencyIsCheckedAsLocal() {
        let mut files = repository(&[
            (
                "Modules/A/Cargo.toml",
                &crateManifest(
                    "alpha",
                    "entities",
                    "[dependencies]\nbeta.workspace = true\n",
                ),
            ),
            ("Modules/B/Cargo.toml", &crateManifest("beta", "domain", "")),
        ]);
        files.add("Cargo.toml", "[workspace]\nmembers = [\"Modules/*\"]\n\n[workspace.dependencies]\nbeta = { path = \"Modules/B\" }\n");
        assert_eq!(
            findingMessages(&files),
            vec!["ring `entities` may not depend on ring `domain` (`beta`)"]
        );
    }

    #[test]
    fn inheritedRegistryDependencyIsThirdPartyNotLocal() {
        let mut files = repository(&[(
            "Modules/A/Cargo.toml",
            &crateManifest(
                "alpha",
                "domain",
                "[dependencies]\napprovedCrate.workspace = true\nunlisted.workspace = true\n",
            ),
        )]);
        files.add(
            "Cargo.toml",
            "[workspace]\nmembers = [\"Modules/*\"]\n\n[workspace.dependencies]\napprovedCrate = \"1\"\nunlisted = \"1\"\n",
        );
        assert_eq!(
            findingMessages(&files),
            vec!["third-party crate `unlisted` is not approved for `alpha`"]
        );
    }

    #[test]
    fn versionOnlyDependencyWithTheNameOfAMemberIsThirdParty() {
        let files = repository(&[
            (
                "Modules/A/Cargo.toml",
                &crateManifest("alpha", "entities", "[dependencies]\nbeta = \"1\"\n"),
            ),
            ("Modules/B/Cargo.toml", &crateManifest("beta", "domain", "")),
        ]);
        assert_eq!(
            findingMessages(&files),
            vec!["third-party crate `beta` is not approved for `alpha`"]
        );
    }

    #[test]
    fn crateWithoutRingAndCrateWithUnknownRingAreFindings() {
        let files = repository(&[
            ("Modules/A/Cargo.toml", "[package]\nname = \"alpha\"\n"),
            (
                "Modules/B/Cargo.toml",
                &crateManifest("beta", "presentation", ""),
            ),
        ]);
        assert_eq!(
            findingMessages(&files),
            vec![
                "the crate declares no ring in [package.metadata]",
                "ring `presentation` is not in the ring register"
            ]
        );
    }

    #[test]
    fn localPathOutsideTheWorkspaceIsAFinding() {
        let files = repository(&[(
            "Modules/A/Cargo.toml",
            &crateManifest(
                "alpha",
                "domain",
                "[dependencies]\nstray = { path = \"../../Elsewhere\" }\n",
            ),
        )]);
        assert_eq!(
            findingMessages(&files),
            vec!["`stray` is a local crate outside the workspace members"]
        );
    }

    #[test]
    fn thirdPartyCrateNeedsApprovalForThatCrate() {
        let files = repository(&[
            (
                "Modules/A/Cargo.toml",
                &crateManifest(
                    "alpha",
                    "domain",
                    "[dependencies]\napprovedCrate = \"1\"\neverywhere = \"1\"\n",
                ),
            ),
            (
                "Modules/B/Cargo.toml",
                &crateManifest(
                    "beta",
                    "domain",
                    "[dependencies]\napprovedCrate = \"1\"\nunknownCrate = \"1\"\n",
                ),
            ),
        ]);
        assert_eq!(
            findingMessages(&files),
            vec![
                "third-party crate `approvedCrate` is not approved for `beta`",
                "third-party crate `unknownCrate` is not approved for `beta`",
            ]
        );
    }

    #[test]
    fn loadFailsWhenARegisterIsMissingOrHasWrongColumns() {
        let missing =
            MemoryFileSystem::withFiles(&[(RingCheck::approvedDependenciesPath, approvedRegister)]);
        assert_eq!(
            RingCheck::load(&missing)
                .expect_err("missing")
                .path
                .to_str(),
            Some(RingCheck::ringRegisterPath)
        );
        let wrongColumns = MemoryFileSystem::withFiles(&[
            (
                RingCheck::ringRegisterPath,
                "| Ring | Other |\n|---|---|\n| a | b |\n",
            ),
            (RingCheck::approvedDependenciesPath, approvedRegister),
        ]);
        assert!(
            RingCheck::load(&wrongColumns)
                .expect_err("columns")
                .message
                .contains("columns")
        );
    }

    /// Every pair of rings, in code and in tests, against the hand-written table. This covers
    /// false positives (an allowed edge reported) and false negatives (a forbidden edge missed).
    #[test]
    fn everyRingPairMatchesTheHandWrittenTable() {
        for from in rings {
            for to in rings {
                for isTest in [false, true] {
                    let section = if isTest {
                        "[dev-dependencies]"
                    } else {
                        "[dependencies]"
                    };
                    let files = repository(&[
                        (
                            "Modules/A/Cargo.toml",
                            &crateManifest(
                                "alpha",
                                from,
                                &format!("{section}\nbeta = {{ path = \"../B\" }}\n"),
                            ),
                        ),
                        ("Modules/B/Cargo.toml", &crateManifest("beta", to, "")),
                    ]);
                    let isReported = !findingMessages(&files).is_empty();
                    assert_eq!(
                        isReported,
                        !isAllowedByHand(from, to, isTest),
                        "from {from} to {to}, test {isTest}"
                    );
                }
            }
        }
    }

    /// Random workspaces of up to six crates with random edges. The number of findings must
    /// equal the number of forbidden edges that the hand-written table predicts.
    #[test]
    fn randomWorkspacesReportExactlyTheForbiddenEdges() {
        let mut generator = SeededGenerator::new(0x52_49_4E_47);
        for _ in 0..200 {
            let count = 1 + generator.nextIndex(6);
            let crateRings: Vec<&str> = (0..count).map(|_| *generator.element(&rings)).collect();
            let mut manifests = Vec::new();
            let mut expectedFindings = 0;
            for (index, ring) in crateRings.iter().enumerate() {
                let mut dependencies = String::from("[dependencies]\n");
                let mut testDependencies = String::from("[dev-dependencies]\n");
                for (target, targetRing) in crateRings.iter().enumerate() {
                    if target == index {
                        continue;
                    }
                    match generator.nextIndex(3) {
                        0 => {
                            dependencies.push_str(&format!(
                                "crate{target} = {{ path = \"../C{target}\" }}\n"
                            ));
                            expectedFindings +=
                                usize::from(!isAllowedByHand(ring, targetRing, false));
                        }
                        1 => {
                            testDependencies.push_str(&format!(
                                "crate{target} = {{ path = \"../C{target}\" }}\n"
                            ));
                            expectedFindings +=
                                usize::from(!isAllowedByHand(ring, targetRing, true));
                        }
                        _ => {}
                    }
                }
                manifests.push((
                    format!("Modules/C{index}/Cargo.toml"),
                    crateManifest(
                        &format!("crate{index}"),
                        ring,
                        &format!("{dependencies}\n{testDependencies}"),
                    ),
                ));
            }
            let entries: Vec<(&str, &str)> = manifests
                .iter()
                .map(|(path, text)| (path.as_str(), text.as_str()))
                .collect();
            assert_eq!(
                findingMessages(&repository(&entries)).len(),
                expectedFindings,
                "rings {crateRings:?}"
            );
        }
    }
}
