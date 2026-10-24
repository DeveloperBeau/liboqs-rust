//! The casing tests for names, after the Swift API Design Guidelines.

/// True when a name starts with a lower-case ASCII letter and holds only ASCII letters and digits.
pub fn isLowerCamelCase(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

/// True when a name starts with an upper-case ASCII letter and holds only ASCII letters and digits.
pub fn isUpperCamelCase(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_uppercase())
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

/// Returns each word of a name that is one upper-case letter followed by lower-case letters.
///
/// `MlKem768Parameters` gives `Ml`, `Kem` and `Parameters`. An acronym written as one unit,
/// such as `MLKEM`, gives no word.
pub fn titleCaseWords(name: &str) -> Vec<String> {
    let characters: Vec<char> = name.chars().collect();
    let mut words = Vec::new();
    for (index, first) in characters.iter().enumerate() {
        let isWordStart = first.is_ascii_uppercase()
            && characters
                .get(index + 1)
                .is_some_and(char::is_ascii_lowercase);
        if isWordStart {
            let rest = characters[index + 1..]
                .iter()
                .take_while(|next| next.is_ascii_lowercase());
            words.push(std::iter::once(first).chain(rest).collect());
        }
    }
    words
}

#[cfg(test)]
mod tests {
    use super::{isLowerCamelCase, isUpperCamelCase, titleCaseWords};

    #[test]
    fn lowerCamelCaseAcceptsSwiftStyleNamesOnly() {
        for name in ["generateKeyPair", "id", "userID", "sha3State", "x"] {
            assert!(isLowerCamelCase(name), "{name}");
        }
        for name in [
            "generate_key_pair",
            "GenerateKeyPair",
            "MAX_SIZE",
            "_hidden",
            "",
            "naïve",
        ] {
            assert!(!isLowerCamelCase(name), "{name}");
        }
    }

    #[test]
    fn upperCamelCaseAcceptsSwiftStyleTypeNamesOnly() {
        for name in ["MLKEM768", "PublicKey", "T", "SHA3State"] {
            assert!(isUpperCamelCase(name), "{name}");
        }
        for name in ["publicKey", "Public_Key", "MAX_SIZE", "", "_Hidden"] {
            assert!(!isUpperCamelCase(name), "{name}");
        }
    }

    #[test]
    fn titleCaseWordsSplitsMixedAcronymsAndSkipsWholeAcronyms() {
        assert_eq!(
            titleCaseWords("MlKem768Parameters"),
            vec!["Ml", "Kem", "Parameters"]
        );
        assert_eq!(titleCaseWords("MLKEM768Parameters"), vec!["Parameters"]);
        assert_eq!(titleCaseWords("userId"), vec!["Id"]);
        assert!(titleCaseWords("userID").is_empty());
        assert!(titleCaseWords("").is_empty());
    }
}
