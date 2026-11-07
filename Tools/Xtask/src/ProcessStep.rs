use std::fmt;

/// One program run of a build, with its arguments. The program runs in the repository root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStep {
    /// The program, found on the search path.
    pub program: String,
    /// The arguments, each one word.
    pub arguments: Vec<String>,
}

impl ProcessStep {
    /// Makes a step from a program and its arguments.
    pub fn new(program: &str, arguments: &[&str]) -> Self {
        ProcessStep {
            program: program.to_string(),
            arguments: arguments
                .iter()
                .map(|argument| argument.to_string())
                .collect(),
        }
    }
}

impl fmt::Display for ProcessStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.program)?;
        for argument in &self.arguments {
            write!(formatter, " {argument}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessStep;

    #[test]
    fn displayIsTheCommandLine() {
        assert_eq!(
            ProcessStep::new("cmake", &["--build", "folder"]).to_string(),
            "cmake --build folder"
        );
        assert_eq!(ProcessStep::new("true", &[]).to_string(), "true");
    }
}
