/// A command of the repository tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Runs every check.
    everyCheck,
    /// Checks the ring of each crate and each dependency edge.
    rings,
    /// Checks names and paths against the Swift casing rules.
    names,
    /// Checks that every copy of the version agrees.
    versions,
    /// Checks the hygiene rules for repository text.
    hygiene,
    /// Checks that `unsafe` code appears only in registered files.
    unsafeCode,
    /// Clones and builds the C library that the parity tests use as the oracle.
    fetchOracle,
}

impl Command {
    /// The help text that lists the commands.
    pub const usage: &'static str = "usage: cargo xtask <command>\n\
\n\
commands:\n  check           run every check\n  check-rings     check rings and dependency edges\n  check-names     check names against the Swift casing rules\n  check-versions  check that every version copy agrees with LIBOQS_VERSION\n  check-hygiene   check repository text for the hygiene rules\n  check-unsafe    check that unsafe code appears only in registered files\n  fetch-oracle    clone and build the C library at the version in LIBOQS_VERSION, for the parity tests";

    /// Reads the command from the command-line arguments, without the program name.
    pub fn parse(arguments: &[String]) -> Result<Self, String> {
        match arguments {
            [command] => match command.as_str() {
                "check" => Ok(Command::everyCheck),
                "check-rings" => Ok(Command::rings),
                "check-names" => Ok(Command::names),
                "check-versions" => Ok(Command::versions),
                "check-hygiene" => Ok(Command::hygiene),
                "check-unsafe" => Ok(Command::unsafeCode),
                "fetch-oracle" => Ok(Command::fetchOracle),
                unknown => Err(format!("unknown command `{unknown}`")),
            },
            [] => Err("no command".to_string()),
            _ => Err("give exactly one command".to_string()),
        }
    }

    /// True when the command runs the check of a kind.
    pub fn includes(&self, check: Command) -> bool {
        (*self == Command::everyCheck && check != Command::fetchOracle) || *self == check
    }
}

#[cfg(test)]
mod tests {
    use super::Command;

    fn parse(arguments: &[&str]) -> Result<Command, String> {
        Command::parse(
            &arguments
                .iter()
                .map(|argument| argument.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn parseReadsEachCommandWord() {
        assert_eq!(parse(&["check"]), Ok(Command::everyCheck));
        assert_eq!(parse(&["check-rings"]), Ok(Command::rings));
        assert_eq!(parse(&["check-names"]), Ok(Command::names));
        assert_eq!(parse(&["check-versions"]), Ok(Command::versions));
        assert_eq!(parse(&["check-hygiene"]), Ok(Command::hygiene));
        assert_eq!(parse(&["check-unsafe"]), Ok(Command::unsafeCode));
        assert_eq!(parse(&["fetch-oracle"]), Ok(Command::fetchOracle));
    }

    #[test]
    fn parseRejectsUnknownMissingAndExtraArguments() {
        assert_eq!(
            parse(&["build"]),
            Err("unknown command `build`".to_string())
        );
        assert_eq!(parse(&[]), Err("no command".to_string()));
        assert_eq!(
            parse(&["check", "check"]),
            Err("give exactly one command".to_string())
        );
    }

    #[test]
    fn checkAllIncludesEveryCheckAndOneCheckIncludesOnlyItself() {
        for check in [
            Command::rings,
            Command::names,
            Command::versions,
            Command::hygiene,
            Command::unsafeCode,
        ] {
            assert!(Command::everyCheck.includes(check));
            assert!(check.includes(check));
        }
        assert!(!Command::rings.includes(Command::names));
        assert!(!Command::everyCheck.includes(Command::fetchOracle));
        assert!(Command::fetchOracle.includes(Command::fetchOracle));
    }
}
