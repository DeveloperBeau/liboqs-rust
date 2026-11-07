/// The text and the exit status of one run of the repository tool.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    /// The text for standard output: one line for each finding, or the pass line.
    pub standardOutput: String,
    /// The text for standard error: notes, the finding count and usage errors.
    pub standardError: String,
    /// The exit status: 0 for no finding, 1 for a finding, 2 for a wrong command.
    pub exitStatus: u8,
}
