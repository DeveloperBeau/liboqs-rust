use crate::Declaration;
use crate::DeclarationKind;
use crate::DeclarationScanner;
use crate::FileReading;
use crate::Finding;
use crate::MarkdownTable;
use crate::WorkspaceLayout;
use crate::identifierCasing::{isLowerCamelCase, isUpperCamelCase, titleCaseWords};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Checks Rust names, Rust file paths and library names against the Swift casing rules in
/// `standards.md`.
#[derive(Debug)]
pub struct NamingCheck {
    acronyms: BTreeSet<String>,
    exceptions: BTreeSet<(String, String)>,
}

impl NamingCheck {
    /// The name of the check in each finding.
    pub const name: &'static str = "names";
    /// The register of the acronyms that a name must write as one unit.
    pub const acronymRegisterPath: &'static str = "Documentation/Registers/Acronyms.md";
    /// The register of the names that a language or framework forces into another form.
    pub const exceptionRegisterPath: &'static str = "Documentation/Registers/NamingExceptions.md";

    /// Reads the rules from the two registers.
    pub fn load(files: &dyn FileReading) -> Result<Self, Finding> {
        let acronyms = Self::column(files, Self::acronymRegisterPath, "Acronym")?
            .into_iter()
            .map(|acronym| acronym.trim_matches('`').to_string())
            .collect();
        let exceptionNames = Self::column(files, Self::exceptionRegisterPath, "Name")?;
        let exceptionKinds = Self::column(files, Self::exceptionRegisterPath, "Kind")?;
        let exceptions = exceptionKinds
            .into_iter()
            .zip(exceptionNames)
            .map(|(kind, name)| {
                (
                    kind.trim_matches('`').to_string(),
                    name.trim_matches('`').to_string(),
                )
            })
            .collect();
        Ok(NamingCheck {
            acronyms,
            exceptions,
        })
    }

    /// Returns a finding for each name and path in the repository that breaks a casing rule.
    pub fn findings(&self, files: &dyn FileReading, layout: &WorkspaceLayout) -> Vec<Finding> {
        let mut findings = Vec::new();
        let filePaths = match files.filePaths() {
            Ok(paths) => paths,
            Err(error) => {
                return vec![Finding::new(
                    Self::name,
                    Path::new("."),
                    0,
                    error.to_string(),
                )];
            }
        };
        for path in filePaths
            .iter()
            .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        {
            findings.extend(self.pathFindings(path));
            match files.text(path) {
                Ok(source) => findings.extend(self.sourceFindings(path, &source)),
                Err(error) => findings.push(Finding::new(Self::name, path, 0, error.to_string())),
            }
        }
        for member in &layout.members {
            let folder = member
                .manifestPath
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default();
            let hasLibrary = filePaths.contains(&folder.join("src/lib.rs"));
            match member.manifest.libraryName() {
                Some(libraryName) if !isUpperCamelCase(&libraryName) => {
                    let line = member.manifest.line("lib", "name").unwrap_or(0);
                    findings.push(Finding::new(Self::name, &member.manifestPath, line, format!("library name `{libraryName}` must be UpperCamelCase")));
                }
                None if hasLibrary => findings.push(Finding::new(
                    Self::name,
                    &member.manifestPath,
                    0,
                    "set [lib] name to an UpperCamelCase name, because the default library name is snake_case",
                )),
                _ => {}
            }
        }
        findings
    }

    /// Returns a finding for each declared name in one source file that breaks a casing rule.
    pub fn sourceFindings(&self, path: &Path, source: &str) -> Vec<Finding> {
        DeclarationScanner::declarations(source)
            .into_iter()
            .filter_map(|declaration| {
                self.problem(&declaration)
                    .map(|message| Finding::new(Self::name, path, declaration.line, message))
            })
            .collect()
    }

    /// Returns a finding for each folder or file name in a Rust source path that is not camel case.
    pub fn pathFindings(&self, path: &Path) -> Vec<Finding> {
        let mut parts: Vec<String> = path
            .parent()
            .map(|folder| {
                folder
                    .iter()
                    .map(|part| part.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        if let Some(stem) = path.file_stem() {
            parts.push(stem.to_string_lossy().into_owned());
        }
        parts
            .into_iter()
            .filter(|part| !(isLowerCamelCase(part) || isUpperCamelCase(part)))
            .filter(|part| {
                !self
                    .exceptions
                    .contains(&("path".to_string(), part.clone()))
            })
            .map(|part| {
                Finding::new(
                    Self::name,
                    path,
                    0,
                    format!("path part `{part}` must be lowerCamelCase or UpperCamelCase"),
                )
            })
            .collect()
    }

    fn problem(&self, declaration: &Declaration) -> Option<String> {
        let name = declaration.name.as_str();
        let kindName = format!("{:?}", declaration.kind);
        if self.exceptions.contains(&(kindName, name.to_string())) {
            return None;
        }
        if name.starts_with('_') {
            return Some(format!("`{name}` must not start with an underscore"));
        }
        let casingProblem = match declaration.kind {
            DeclarationKind::r#type
            | DeclarationKind::protocol
            | DeclarationKind::genericParameter => {
                (!isUpperCamelCase(name)).then(|| format!("`{name}` must be UpperCamelCase"))
            }
            DeclarationKind::module => {
                (!isLowerCamelCase(name)).then(|| format!("module `{name}` must be lowerCamelCase"))
            }
            _ => (!isLowerCamelCase(name)).then(|| format!("`{name}` must be lowerCamelCase")),
        };
        if casingProblem.is_some() {
            return casingProblem;
        }
        if matches!(
            declaration.kind,
            DeclarationKind::r#type | DeclarationKind::protocol
        ) && name.ends_with("Impl")
        {
            return Some(format!("`{name}` must not end in `Impl`"));
        }
        if declaration.kind == DeclarationKind::protocol && Self::hasInterfacePrefix(name) {
            return Some(format!(
                "protocol `{name}` must not start with an `I` prefix"
            ));
        }
        titleCaseWords(name)
            .into_iter()
            .find(|word| self.acronyms.contains(&word.to_ascii_uppercase()))
            .map(|word| {
                format!(
                    "write the acronym `{}` as one unit in `{name}`",
                    word.to_ascii_uppercase()
                )
            })
    }

    fn hasInterfacePrefix(name: &str) -> bool {
        let characters: Vec<char> = name.chars().take(3).collect();
        characters.len() == 3
            && characters[0] == 'I'
            && characters[1].is_ascii_uppercase()
            && characters[2].is_ascii_lowercase()
    }

    fn column(files: &dyn FileReading, path: &str, header: &str) -> Result<Vec<String>, Finding> {
        let registerFinding =
            |message: String| Finding::new(Self::name, &PathBuf::from(path), 0, message);
        let text = files
            .text(Path::new(path))
            .map_err(|error| registerFinding(error.to_string()))?;
        let table = MarkdownTable::firstTable(&text)
            .ok_or_else(|| registerFinding("the register has no table".to_string()))?;
        let cells = table
            .column(header)
            .ok_or_else(|| registerFinding(format!("the register has no column {header}")))?;
        Ok(cells.into_iter().map(str::to_string).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::NamingCheck;
    use crate::MemoryFileSystem;
    use crate::SeededGenerator;
    use std::path::Path;

    fn check() -> NamingCheck {
        let files = MemoryFileSystem::withFiles(&[
            (
                NamingCheck::acronymRegisterPath,
                "| Acronym | Meaning |\n|---|---|\n| `KEM` | x |\n| `ID` | x |\n| ML | x |\n",
            ),
            (
                NamingCheck::exceptionRegisterPath,
                "| Kind | Name | Reason |\n|---|---|---|\n| `function` | `from_str` | x |\n| `type` | `forced_type` | x |\n| `path` | `fuzz_targets` | x |\n",
            ),
        ]);
        NamingCheck::load(&files).expect("registers")
    }

    fn messages(source: &str) -> Vec<String> {
        check()
            .sourceFindings(Path::new("a.rs"), source)
            .into_iter()
            .map(|finding| finding.message)
            .collect()
    }

    #[test]
    fn swiftCasingHasNoFinding() {
        let source = "pub struct MLKEM768Parameters { publicKeyLength: usize }\npub trait KeyEncapsulating {}\nenum OQSError { invalidLength }\nconst maximumSize: usize = 1;\nfn generateKeyPair<Random>(userID: u8) { let kemName = 1; }\nmod sharedSecret;";
        assert!(messages(source).is_empty(), "{:?}", messages(source));
    }

    #[test]
    fn snakeCaseAndScreamingCaseAreFindings() {
        assert_eq!(
            messages(
                "fn generate_key_pair(seed_value: u8) { let key_length = 1; }\nconst MAX_SIZE: usize = 1;"
            ),
            vec![
                "`generate_key_pair` must be lowerCamelCase",
                "`seed_value` must be lowerCamelCase",
                "`key_length` must be lowerCamelCase",
                "`MAX_SIZE` must be lowerCamelCase",
            ]
        );
    }

    #[test]
    fn typeKindsMustBeUpperCamelCase() {
        assert_eq!(
            messages(
                "struct publicKey;\ntrait key_reading {}\nfn f<t>() {}\nenum Error { InvalidLength }"
            ),
            vec![
                "`publicKey` must be UpperCamelCase",
                "`key_reading` must be UpperCamelCase",
                "`t` must be UpperCamelCase",
                "`InvalidLength` must be lowerCamelCase",
            ]
        );
    }

    #[test]
    fn moduleMustBeLowerCamelCaseEvenWhenItsFileIsNamedAfterAType() {
        assert_eq!(
            messages(
                "mod SharedSecret;\nmod shared_secret;\n#[path = \"MLKEM768.rs\"]\nmod mlkem768;"
            ),
            vec![
                "module `SharedSecret` must be lowerCamelCase",
                "module `shared_secret` must be lowerCamelCase",
            ]
        );
    }

    #[test]
    fn mixedAcronymIsAFinding() {
        assert_eq!(
            messages("struct MlKem768;\nfn userId() {}"),
            vec![
                "write the acronym `ML` as one unit in `MlKem768`",
                "write the acronym `ID` as one unit in `userId`"
            ]
        );
    }

    #[test]
    fn prefixesAndSuffixesAreFindings() {
        assert_eq!(
            messages("fn f(_unused: u8) {}\nstruct KeyImpl;\ntrait IReader {}"),
            vec![
                "`_unused` must not start with an underscore",
                "`KeyImpl` must not end in `Impl`",
                "protocol `IReader` must not start with an `I` prefix",
            ]
        );
        assert!(messages("trait IDReading {}\nfn g(_: u8) {}").is_empty());
    }

    #[test]
    fn registeredExceptionIsAcceptedOnlyForItsKind() {
        assert!(messages("fn from_str() {}\nstruct forced_type;").is_empty());
        assert_eq!(
            messages("let from_str = 1;"),
            vec!["`from_str` must be lowerCamelCase"]
        );
    }

    #[test]
    fn pathPartsMustBeCamelCaseUnlessRegistered() {
        let naming = check();
        assert!(
            naming
                .pathFindings(Path::new("Modules/MLKEM/src/MLKEM768.rs"))
                .is_empty()
        );
        assert!(
            naming
                .pathFindings(Path::new("Fuzz/fuzz_targets/parseKey.rs"))
                .is_empty()
        );
        let messages: Vec<String> = naming
            .pathFindings(Path::new("modules/ml_kem/src/key_pair.rs"))
            .into_iter()
            .map(|finding| finding.message)
            .collect();
        assert_eq!(
            messages,
            vec![
                "path part `ml_kem` must be lowerCamelCase or UpperCamelCase",
                "path part `key_pair` must be lowerCamelCase or UpperCamelCase"
            ]
        );
    }

    #[test]
    fn libraryNameMustBeUpperCamelCaseAndALibraryMustSetIt() {
        use crate::WorkspaceLayout;
        let mut files = MemoryFileSystem::withFiles(&[
            (
                NamingCheck::acronymRegisterPath,
                "| Acronym |\n|---|\n| KEM |\n",
            ),
            (
                NamingCheck::exceptionRegisterPath,
                "| Kind | Name |\n|---|---|\n",
            ),
            ("Cargo.toml", "[workspace]\nmembers = [\"Modules/*\"]\n"),
            (
                "Modules/Good/Cargo.toml",
                "[package]\nname = \"good\"\n\n[lib]\nname = \"OQSNativeGood\"\n",
            ),
            ("Modules/Good/src/lib.rs", "//! Good.\n"),
            (
                "Modules/Snake/Cargo.toml",
                "[package]\nname = \"snake\"\n\n[lib]\nname = \"oqs_native_snake\"\n",
            ),
            ("Modules/Snake/src/lib.rs", "//! Snake.\n"),
            ("Modules/Unset/Cargo.toml", "[package]\nname = \"unset\"\n"),
            ("Modules/Unset/src/lib.rs", "//! Unset.\n"),
            (
                "Modules/Binary/Cargo.toml",
                "[package]\nname = \"binary\"\n",
            ),
            ("Modules/Binary/src/main.rs", "fn main() {}\n"),
        ]);
        files.add("Modules/Good/src/Extra.rs", "pub struct Extra;\n");
        let naming = NamingCheck::load(&files).expect("registers");
        let layout = WorkspaceLayout::load(&files).expect("layout");
        let found: Vec<String> = naming
            .findings(&files, &layout)
            .into_iter()
            .map(|finding| finding.to_string())
            .collect();
        assert_eq!(
            found,
            vec![
                "Modules/Snake/Cargo.toml:5: [names] library name `oqs_native_snake` must be UpperCamelCase",
                "Modules/Unset/Cargo.toml:0: [names] set [lib] name to an UpperCamelCase name, because the default library name is snake_case",
            ]
        );
    }

    #[test]
    fn loadFailsWhenARegisterIsMissing() {
        let files = MemoryFileSystem::withFiles(&[(
            NamingCheck::acronymRegisterPath,
            "| Acronym |\n|---|\n| KEM |\n",
        )]);
        assert!(NamingCheck::load(&files).is_err());
    }

    /// Random names built from words. A snake_case name must always be a finding (no false
    /// negative) and a camel case name of plain words must never be one (no false positive).
    #[test]
    fn randomNamesAreJudgedByTheirShapeOnly() {
        let words = [
            "key", "pair", "public", "secret", "length", "value", "seed", "shared",
        ];
        let mut generator = SeededGenerator::new(0x4E_41_4D_45);
        for _ in 0..500 {
            let count = 2 + generator.nextIndex(3);
            let chosen: Vec<&str> = (0..count).map(|_| *generator.element(&words)).collect();
            let snakeName = chosen.join("_");
            let camelName: String = chosen
                .iter()
                .enumerate()
                .map(|(index, word)| {
                    if index == 0 {
                        word.to_string()
                    } else {
                        word[..1].to_uppercase() + &word[1..]
                    }
                })
                .collect();
            assert_eq!(
                messages(&format!("fn {snakeName}() {{}}")).len(),
                1,
                "{snakeName}"
            );
            assert!(
                messages(&format!("fn {camelName}() {{}}")).is_empty(),
                "{camelName}"
            );
        }
    }
}
