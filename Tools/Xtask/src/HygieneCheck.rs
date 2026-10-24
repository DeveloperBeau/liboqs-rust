use crate::FileReading;
use crate::Finding;
use std::path::Path;

/// Checks repository text for the hygiene rules in `standards.md`: no em-dash, no absolute path
/// of a computer, no forbidden word, and no semicolon in prose.
pub struct HygieneCheck {
    forbiddenWords: Vec<String>,
}

impl HygieneCheck {
    /// The name of the check in each finding.
    pub const name: &'static str = "hygiene";

    /// Makes a check that also rejects each word of a list. The words come from
    /// `forbiddenWords`, in lower case.
    pub fn new(forbiddenWords: Vec<String>) -> Self {
        HygieneCheck { forbiddenWords }
    }

    /// Returns the forbidden words, in lower case, from the comma-separated value of the
    /// `HYGIENE_WORDS` variable, or else from the lines of the local word file.
    ///
    /// The word list comes from outside the repository, so that the repository never holds the
    /// words that it must not hold. An empty variable counts as no variable, because CI gives
    /// the variable an empty value when the repository has no word list.
    pub fn forbiddenWords(environmentWords: Option<&str>, localWords: Option<&str>) -> Vec<String> {
        let normalized = |words: Vec<&str>| -> Vec<String> {
            words
                .into_iter()
                .map(|word| word.trim().to_lowercase())
                .filter(|word| !word.is_empty())
                .collect()
        };
        let fromEnvironment = normalized(environmentWords.unwrap_or_default().split(',').collect());
        if fromEnvironment.is_empty() {
            normalized(localWords.unwrap_or_default().lines().collect())
        } else {
            fromEnvironment
        }
    }

    /// Returns a finding for each line of each repository file that breaks a hygiene rule.
    pub fn findings(&self, files: &dyn FileReading) -> Vec<Finding> {
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
        let mut findings = Vec::new();
        for path in filePaths {
            let pathText = path.to_string_lossy().to_lowercase();
            if let Some(word) = self
                .forbiddenWords
                .iter()
                .find(|word| pathText.contains(word.as_str()))
            {
                findings.push(Finding::new(
                    Self::name,
                    &path,
                    0,
                    format!("the path holds the forbidden word `{word}`"),
                ));
            }
            // A file that is not UTF-8 text is binary and has no prose to check.
            if let Ok(text) = files.text(&path) {
                findings.extend(self.textFindings(&path, &text));
            }
        }
        findings
    }

    /// Returns a finding for each line of one file that breaks a hygiene rule.
    pub fn textFindings(&self, path: &Path, text: &str) -> Vec<Finding> {
        // The patterns are built from parts, so that this file does not hold the text it rejects.
        let emDash = '\u{2014}';
        let absolutePathMarkers = [
            ["/", "Users", "/"].concat(),
            ["/", "home", "/"].concat(),
            ["C:", "\\", "Users"].concat(),
        ];
        let isProse = Self::isProsePath(path);
        let mut findings = Vec::new();
        let mut isInCodeBlock = false;
        for (index, line) in text.lines().enumerate() {
            let lineNumber = index + 1;
            if line.contains(emDash) {
                findings.push(Finding::new(
                    Self::name,
                    path,
                    lineNumber,
                    "the line holds an em-dash",
                ));
            }
            if absolutePathMarkers
                .iter()
                .any(|marker| line.contains(marker.as_str()))
            {
                findings.push(Finding::new(
                    Self::name,
                    path,
                    lineNumber,
                    "the line holds an absolute path of a computer",
                ));
            }
            let lowercaseLine = line.to_lowercase();
            if let Some(word) = self
                .forbiddenWords
                .iter()
                .find(|word| lowercaseLine.contains(word.as_str()))
            {
                findings.push(Finding::new(
                    Self::name,
                    path,
                    lineNumber,
                    format!("the line holds the forbidden word `{word}`"),
                ));
            }
            if line.trim_start().starts_with("```") {
                isInCodeBlock = !isInCodeBlock;
                continue;
            }
            if isProse && !isInCodeBlock && Self::withoutCodeSpans(line).contains(';') {
                findings.push(Finding::new(
                    Self::name,
                    path,
                    lineNumber,
                    "prose must not use a semicolon",
                ));
            }
        }
        findings
    }

    fn isProsePath(path: &Path) -> bool {
        let isMarkdown = path.extension().is_some_and(|extension| extension == "md");
        isMarkdown && (path.parent() == Some(Path::new("")) || path.starts_with("Documentation"))
    }

    fn withoutCodeSpans(line: &str) -> String {
        line.split('`').step_by(2).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::HygieneCheck;
    use crate::MemoryFileSystem;
    use crate::SeededGenerator;
    use std::path::Path;

    fn messages(check: &HygieneCheck, path: &str, text: &str) -> Vec<String> {
        check
            .textFindings(Path::new(path), text)
            .into_iter()
            .map(|finding| finding.message)
            .collect()
    }

    #[test]
    fn cleanProseHasNoFinding() {
        let check = HygieneCheck::new(vec!["forbidden".to_string()]);
        assert!(
            messages(
                &check,
                "standards.md",
                "Short sentence. Another sentence.\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn emDashIsAFindingInAnyFile() {
        let check = HygieneCheck::new(Vec::new());
        let text = format!("let a = 1{}2\n", '\u{2014}');
        assert_eq!(
            messages(&check, "Modules/A/src/lib.rs", &text),
            vec!["the line holds an em-dash"]
        );
    }

    #[test]
    fn absolutePathIsAFinding() {
        let check = HygieneCheck::new(Vec::new());
        let text = ["see ", "/", "Users", "/", "someone/file\n"].concat();
        assert_eq!(
            messages(&check, "README.md", &text),
            vec!["the line holds an absolute path of a computer"]
        );
    }

    #[test]
    fn forbiddenWordIsAFindingInTextAndInPathsInAnyLetterCase() {
        let check = HygieneCheck::new(HygieneCheck::forbiddenWords(Some("Secretword, "), None));
        assert_eq!(
            messages(&check, "notes.txt", "a SECRETWORD here\n"),
            vec!["the line holds the forbidden word `secretword`"]
        );
        let files = MemoryFileSystem::withFiles(&[("secretWord.local.md", "clean\n")]);
        let pathMessages: Vec<String> = check
            .findings(&files)
            .into_iter()
            .map(|finding| finding.message)
            .collect();
        assert_eq!(
            pathMessages,
            vec!["the path holds the forbidden word `secretword`"]
        );
    }

    #[test]
    fn semicolonIsAFindingInProseOnly() {
        let check = HygieneCheck::new(Vec::new());
        assert_eq!(
            messages(&check, "Documentation/Architecture/Rings.md", "One; two.\n"),
            vec!["prose must not use a semicolon"]
        );
        assert_eq!(
            messages(&check, "standards.md", "One; two.\n"),
            vec!["prose must not use a semicolon"]
        );
        assert!(messages(&check, "Modules/A/src/lib.rs", "let a = 1;\n").is_empty());
        assert!(messages(&check, "Modules/A/Notes.md", "One; two.\n").is_empty());
    }

    #[test]
    fn semicolonInCodeBlockOrCodeSpanIsNotAFinding() {
        let check = HygieneCheck::new(Vec::new());
        let text = "Run `a; b` now.\n```rust\nlet a = 1;\n```\nDone.\n";
        assert!(messages(&check, "README.md", text).is_empty());
    }

    #[test]
    fn forbiddenWordsComeFromTheVariableFirstAndElseFromTheLocalFile() {
        assert_eq!(
            HygieneCheck::forbiddenWords(Some(" One,two ,,"), Some("three")),
            vec!["one", "two"]
        );
        assert_eq!(
            HygieneCheck::forbiddenWords(Some(" , "), Some("Three\n\n four ")),
            vec!["three", "four"]
        );
        assert_eq!(
            HygieneCheck::forbiddenWords(None, Some("five")),
            vec!["five"]
        );
        assert!(HygieneCheck::forbiddenWords(None, None).is_empty());
        assert!(HygieneCheck::forbiddenWords(Some(""), Some("\n")).is_empty());
    }

    /// Random lines from a fixed alphabet. A finding must appear exactly when the line holds a
    /// rejected pattern, which the test decides from the parts it put in, not from the check.
    #[test]
    fn randomLinesReportExactlyTheInsertedProblems() {
        let mut generator = SeededGenerator::new(0x48_59_47);
        let check = HygieneCheck::new(vec!["zorblat".to_string()]);
        let parts = [
            "word ", "text. ", "zorblat ", "; ", "\u{2014}", "`a;b` ", "path ",
        ];
        for _ in 0..500 {
            let chosen: Vec<&str> = (0..1 + generator.nextIndex(6))
                .map(|_| *generator.element(&parts))
                .collect();
            let line = chosen.concat();
            let expected = usize::from(chosen.contains(&"zorblat "))
                + usize::from(chosen.contains(&"; "))
                + usize::from(chosen.contains(&"\u{2014}"));
            assert_eq!(
                check.textFindings(Path::new("README.md"), &line).len(),
                expected,
                "line {line:?}"
            );
        }
    }
}
