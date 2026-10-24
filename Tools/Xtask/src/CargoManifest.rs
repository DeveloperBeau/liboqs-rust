use crate::Dependency;
use crate::DependencyKind;

/// The parts of a `Cargo.toml` file that the checks read.
///
/// The reader knows the small TOML subset that Cargo manifests use: table headers, dotted keys,
/// strings, inline tables and arrays that span lines. It is not a general TOML parser, because
/// the workspace takes no third-party dependency.
#[derive(Debug, Default)]
pub struct CargoManifest {
    entries: Vec<ManifestEntry>,
}

#[derive(Debug)]
struct ManifestEntry {
    table: String,
    key: String,
    value: String,
    line: usize,
}

impl CargoManifest {
    /// Reads a manifest from its text.
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        let mut table = String::new();
        let mut lines = text.lines().enumerate();
        while let Some((index, rawLine)) = lines.next() {
            let line = Self::withoutComment(rawLine).trim().to_string();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                table = line
                    .trim_matches(|character| character == '[' || character == ']')
                    .trim()
                    .to_string();
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let mut value = value.trim().to_string();
            // An array or inline table can continue on the next lines until its brackets close.
            while Self::openBracketCount(&value) > 0 {
                let Some((_, nextLine)) = lines.next() else {
                    break;
                };
                value.push(' ');
                value.push_str(Self::withoutComment(nextLine).trim());
            }
            entries.push(ManifestEntry {
                table: table.clone(),
                key: key.trim().trim_matches('"').to_string(),
                value,
                line: index + 1,
            });
        }
        CargoManifest { entries }
    }

    /// Returns the value of a key in a table, without the quotes of a string.
    pub fn value(&self, table: &str, key: &str) -> Option<String> {
        self.entries
            .iter()
            .find(|entry| entry.table == table && entry.key == key)
            .map(|entry| Self::unquoted(&entry.value))
    }

    /// Returns the line that declares a key in a table.
    pub fn line(&self, table: &str, key: &str) -> Option<usize> {
        self.entries
            .iter()
            .find(|entry| entry.table == table && entry.key == key)
            .map(|entry| entry.line)
    }

    /// The package name, from `[package] name`.
    pub fn packageName(&self) -> Option<String> {
        self.value("package", "name")
    }

    /// The ring of the crate, from `[package.metadata] ring`.
    pub fn ring(&self) -> Option<String> {
        self.value("package.metadata", "ring")
    }

    /// The name of the library target as code sees it, from `[lib] name`.
    pub fn libraryName(&self) -> Option<String> {
        self.value("lib", "name")
    }

    /// The member patterns of a workspace, from `[workspace] members`.
    pub fn workspaceMembers(&self) -> Vec<String> {
        self.value("workspace", "members")
            .map(|value| Self::arrayItems(&value))
            .unwrap_or_default()
    }

    /// True when the package takes its version from the workspace.
    pub fn inheritsWorkspaceVersion(&self) -> bool {
        self.value("package", "version.workspace").as_deref() == Some("true")
            || self
                .value("package", "version")
                .is_some_and(|value| Self::inlineTableFlag(&value, "workspace"))
    }

    /// The names of the workspace dependencies that point to a local path.
    pub fn workspacePathDependencies(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.table == "workspace.dependencies")
            .filter(|entry| entry.key.ends_with(".path") || entry.value.contains("path"))
            .map(|entry| entry.key.split('.').next().unwrap_or_default().to_string())
            .collect()
    }

    /// Every dependency that the manifest declares, in all dependency sections.
    pub fn dependencies(&self) -> Vec<Dependency> {
        let mut dependencies: Vec<Dependency> = Vec::new();
        for entry in &self.entries {
            if let Some(kind) = Self::dependencyKind(&entry.table) {
                // Inline form: `name = "1"`, `name = { path = ".." }` or `name.workspace = true`.
                let (name, attribute) = match entry.key.split_once('.') {
                    Some((name, attribute)) => (name.to_string(), Some(attribute.to_string())),
                    None => (entry.key.clone(), None),
                };
                Self::merge(
                    &mut dependencies,
                    name,
                    kind,
                    attribute.as_deref(),
                    &entry.value,
                    entry.line,
                );
            } else if let Some((tableName, name)) = entry.table.rsplit_once('.') {
                // Table form: `[dependencies.name]` followed by `path = ".."` lines.
                if let Some(kind) = Self::dependencyKind(tableName) {
                    Self::merge(
                        &mut dependencies,
                        name.to_string(),
                        kind,
                        Some(&entry.key),
                        &entry.value,
                        entry.line,
                    );
                }
            }
        }
        dependencies
    }

    fn merge(
        dependencies: &mut Vec<Dependency>,
        key: String,
        kind: DependencyKind,
        attribute: Option<&str>,
        value: &str,
        line: usize,
    ) {
        let hasPath = attribute == Some("path")
            || (attribute.is_none() && Self::inlineTableHasKey(value, "path"));
        let isInherited = (attribute == Some("workspace") && value.trim() == "true")
            || (attribute.is_none() && Self::inlineTableFlag(value, "workspace"));
        let renamed = match attribute {
            Some("package") => Some(Self::unquoted(value)),
            None => Self::inlineTableString(value, "package"),
            Some(_) => None,
        };
        // Dotted keys and table rows of one dependency arrive as separate entries.
        if let Some(dependency) = dependencies.iter_mut().find(|dependency| {
            dependency.kind == kind && dependency.packageName == key && attribute.is_some()
        }) {
            dependency.hasPath |= hasPath;
            dependency.isInheritedFromWorkspace |= isInherited;
            if let Some(renamed) = renamed {
                dependency.packageName = renamed;
            }
            return;
        }
        dependencies.push(Dependency {
            packageName: renamed.unwrap_or(key),
            kind,
            hasPath,
            isInheritedFromWorkspace: isInherited,
            line,
        });
    }

    fn dependencyKind(table: &str) -> Option<DependencyKind> {
        // A target table such as `target.'cfg(unix)'.dependencies` counts as its plain section.
        let section = table.rsplit('.').next().unwrap_or(table);
        let isSection = table == section || table.starts_with("target.");
        match section {
            "dependencies" if isSection => Some(DependencyKind::normal),
            "dev-dependencies" if isSection => Some(DependencyKind::development),
            "build-dependencies" if isSection => Some(DependencyKind::build),
            _ => None,
        }
    }

    fn inlineTablePairs(value: &str) -> Vec<(String, String)> {
        let trimmed = value.trim();
        if !trimmed.starts_with('{') {
            return Vec::new();
        }
        trimmed
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split(',')
            .filter_map(|pair| pair.split_once('='))
            .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
            .collect()
    }

    fn inlineTableHasKey(value: &str, key: &str) -> bool {
        Self::inlineTablePairs(value)
            .iter()
            .any(|(pairKey, _)| pairKey == key)
    }

    fn inlineTableFlag(value: &str, key: &str) -> bool {
        Self::inlineTablePairs(value)
            .iter()
            .any(|(pairKey, pairValue)| pairKey == key && pairValue == "true")
    }

    fn inlineTableString(value: &str, key: &str) -> Option<String> {
        Self::inlineTablePairs(value)
            .into_iter()
            .find(|(pairKey, _)| pairKey == key)
            .map(|(_, pairValue)| Self::unquoted(&pairValue))
    }

    fn arrayItems(value: &str) -> Vec<String> {
        value
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(Self::unquoted)
            .filter(|item| !item.is_empty())
            .collect()
    }

    fn unquoted(value: &str) -> String {
        value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string()
    }

    fn openBracketCount(value: &str) -> i32 {
        let mut count = 0;
        let mut isInString = false;
        for character in value.chars() {
            match character {
                '"' => isInString = !isInString,
                '[' | '{' if !isInString => count += 1,
                ']' | '}' if !isInString => count -= 1,
                _ => {}
            }
        }
        count
    }

    fn withoutComment(line: &str) -> &str {
        let mut isInString = false;
        for (index, character) in line.char_indices() {
            match character {
                '"' => isInString = !isInString,
                '#' if !isInString => return &line[..index],
                _ => {}
            }
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use super::CargoManifest;
    use crate::DependencyKind;

    const manifest: &str = r#"
[package]
name = "oqs-native-domain" # trailing comment
version.workspace = true

[package.metadata]
ring = "domain"

[lib]
name = "OQSNativeDomain"

[dependencies]
oqs-native-entities = { path = "../Entities" }
renamed = { path = "../Other", package = "oqs-native-other" }
sharedThing.workspace = true
registryCrate = "1.0"

[dev-dependencies.oqs-native-kat-random]
path = "../KATRandom"

[target.'cfg(unix)'.build-dependencies]
builder = { version = "2" }
"#;

    #[test]
    fn packageFieldsAreRead() {
        let parsed = CargoManifest::parse(manifest);
        assert_eq!(parsed.packageName().as_deref(), Some("oqs-native-domain"));
        assert_eq!(parsed.ring().as_deref(), Some("domain"));
        assert_eq!(parsed.libraryName().as_deref(), Some("OQSNativeDomain"));
        assert!(parsed.inheritsWorkspaceVersion());
        assert_eq!(parsed.line("package", "name"), Some(3));
    }

    #[test]
    fn dependenciesCoverInlineDottedTableAndTargetForms() {
        let found: Vec<(String, DependencyKind, bool, bool)> = CargoManifest::parse(manifest)
            .dependencies()
            .into_iter()
            .map(|dependency| {
                (
                    dependency.packageName,
                    dependency.kind,
                    dependency.hasPath,
                    dependency.isInheritedFromWorkspace,
                )
            })
            .collect();
        let expected = vec![
            (
                "oqs-native-entities".to_string(),
                DependencyKind::normal,
                true,
                false,
            ),
            (
                "oqs-native-other".to_string(),
                DependencyKind::normal,
                true,
                false,
            ),
            (
                "sharedThing".to_string(),
                DependencyKind::normal,
                false,
                true,
            ),
            (
                "registryCrate".to_string(),
                DependencyKind::normal,
                false,
                false,
            ),
            (
                "oqs-native-kat-random".to_string(),
                DependencyKind::development,
                true,
                false,
            ),
            ("builder".to_string(), DependencyKind::build, false, false),
        ];
        assert_eq!(found, expected);
    }

    #[test]
    fn workspaceMembersReadAnArrayThatSpansLines() {
        let parsed = CargoManifest::parse(
            "[workspace]\nmembers = [\n  \"Modules/*\", # crates\n  \"Tools/*\",\n]\n",
        );
        assert_eq!(parsed.workspaceMembers(), vec!["Modules/*", "Tools/*"]);
    }

    #[test]
    fn versionIsNotInheritedWhenThePackageSetsItsOwn() {
        assert!(
            !CargoManifest::parse("[package]\nversion = \"1.0.0\"\n").inheritsWorkspaceVersion()
        );
        assert!(
            CargoManifest::parse("[package]\nversion = { workspace = true }\n")
                .inheritsWorkspaceVersion()
        );
    }

    #[test]
    fn workspacePathDependenciesListOnlyPathEntries() {
        let parsed = CargoManifest::parse(
            "[workspace.dependencies]\nlocal = { path = \"Modules/Local\" }\nremote = \"1\"\nother.path = \"x\"\n",
        );
        assert_eq!(parsed.workspacePathDependencies(), vec!["local", "other"]);
    }

    #[test]
    fn hashInsideAStringIsNotAComment() {
        let parsed = CargoManifest::parse("[package]\nname = \"a#b\"\n");
        assert_eq!(parsed.packageName().as_deref(), Some("a#b"));
    }

    #[test]
    fn dependencyTableWithoutDependenciesIsIgnored() {
        assert!(
            CargoManifest::parse("[features]\ndefault = []\n")
                .dependencies()
                .is_empty()
        );
        assert!(
            CargoManifest::parse("[package.metadata.dependencies]\na = 1\n")
                .dependencies()
                .is_empty()
        );
    }
    #[test]
    fn lineFindsTheKeyInTheRequestedTableOnly() {
        let parsed = CargoManifest::parse(manifest);
        assert_eq!(parsed.line("lib", "name"), Some(10));
        assert_eq!(parsed.line("lib", "ring"), None);
    }

    #[test]
    fn tableDependencyWithSeveralKeysKeepsItsPathAndWorkspaceFlags() {
        let parsed = CargoManifest::parse(
            "[dependencies.local]\npath = \"../Local\"\nversion = \"1\"\n\n[dependencies.shared]\nworkspace = true\nfeatures = [\"a\"]\n\n[dependencies.flagged]\nversion = \"1\"\noptional = true\n\n[dependencies.notInherited]\nworkspace = false\n",
        );
        let found: Vec<(String, bool, bool)> = parsed
            .dependencies()
            .into_iter()
            .map(|dependency| {
                (
                    dependency.packageName,
                    dependency.hasPath,
                    dependency.isInheritedFromWorkspace,
                )
            })
            .collect();
        assert_eq!(
            found,
            vec![
                ("local".to_string(), true, false),
                ("shared".to_string(), false, true),
                ("flagged".to_string(), false, false),
                ("notInherited".to_string(), false, false),
            ]
        );
    }

    #[test]
    fn sameDependencyInTwoSectionsStaysTwoDependencies() {
        let parsed = CargoManifest::parse(
            "[dependencies]\nshared.workspace = true\n\n[dev-dependencies]\nshared.workspace = true\n",
        );
        let kinds: Vec<DependencyKind> = parsed
            .dependencies()
            .into_iter()
            .map(|dependency| dependency.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![DependencyKind::normal, DependencyKind::development]
        );
    }

    #[test]
    fn inlineTableFlagNeedsTheWorkspaceKeyToBeTrue() {
        let parsed = CargoManifest::parse(
            "[dependencies]\nflagged = { version = \"1\", optional = true }\noff = { workspace = false }\n",
        );
        assert!(
            parsed
                .dependencies()
                .iter()
                .all(|dependency| !dependency.isInheritedFromWorkspace)
        );
    }

    #[test]
    fn dependencySectionsUnderOtherTablesAreIgnored() {
        let parsed = CargoManifest::parse(
            "[package.metadata.dev-dependencies]\na = \"1\"\n\n[package.metadata.build-dependencies]\nb = \"1\"\n\n[target.'cfg(unix)'.dev-dependencies]\nc = \"1\"\n",
        );
        let found: Vec<(String, DependencyKind)> = parsed
            .dependencies()
            .into_iter()
            .map(|dependency| (dependency.packageName, dependency.kind))
            .collect();
        assert_eq!(found, vec![("c".to_string(), DependencyKind::development)]);
    }

    #[test]
    fn bracketsInsideAStringDoNotContinueTheValue() {
        let parsed =
            CargoManifest::parse("[package]\ndescription = \"uses [ and { here\"\nname = \"x\"\n");
        assert_eq!(parsed.packageName().as_deref(), Some("x"));
        assert_eq!(
            parsed.value("package", "description").as_deref(),
            Some("uses [ and { here")
        );
    }
    #[test]
    fn closingBracketInsideAStringDoesNotEndAnArray() {
        let parsed =
            CargoManifest::parse("[workspace]\nmembers = [\"odd]name\",\n  \"Tools/*\",\n]\n");
        assert_eq!(parsed.workspaceMembers(), vec!["odd]name", "Tools/*"]);
    }
}
