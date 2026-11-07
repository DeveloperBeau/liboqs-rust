use crate::{ProcessRunning, ProcessStep};
use std::path::PathBuf;
use std::process::Command;

/// The programs of the operating system, run in a folder with the output of the tool.
pub struct SystemProcesses {
    folder: PathBuf,
}

impl SystemProcesses {
    /// Makes a runner that runs each program in a folder.
    pub fn new(folder: PathBuf) -> Self {
        SystemProcesses { folder }
    }
}

impl ProcessRunning for SystemProcesses {
    fn run(&mut self, step: &ProcessStep) -> Result<(), String> {
        eprintln!("==> {step}");
        let status = Command::new(&step.program)
            .args(&step.arguments)
            .current_dir(&self.folder)
            .status()
            .map_err(|error| format!("`{step}` did not start: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("`{step}` failed with {status}"))
        }
    }
}
