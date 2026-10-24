use crate::ProcessStep;

/// A runner of programs, so that the build steps never start a process directly.
pub trait ProcessRunning {
    /// Runs a step in the repository root and waits for it. A step that cannot start or that
    /// ends with a status other than 0 is an error that names the step.
    fn run(&mut self, step: &ProcessStep) -> Result<(), String>;
}
