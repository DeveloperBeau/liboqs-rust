use crate::{ProcessRunning, ProcessStep};

/// A runner that records each step and fails at a chosen step. Tests only.
#[derive(Default)]
pub struct RecordingProcesses {
    /// The steps in the order of their runs.
    pub steps: Vec<ProcessStep>,
    /// The number of the step that fails, from 0, or `None`.
    pub failingStep: Option<usize>,
}

impl ProcessRunning for RecordingProcesses {
    fn run(&mut self, step: &ProcessStep) -> Result<(), String> {
        self.steps.push(step.clone());
        if self.failingStep == Some(self.steps.len() - 1) {
            Err(format!("`{step}` failed with exit status: 1"))
        } else {
            Ok(())
        }
    }
}
