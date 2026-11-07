/// A thread with a large stack for the work of a parity check.
///
/// Some C algorithms, and their ports, keep arrays of several megabytes on the stack. A spawned
/// thread has 2 MiB, so each check runs on a thread of this size.
pub struct LargeStack;

impl LargeStack {
    /// The stack size of the thread, in bytes.
    pub const size: usize = 256 << 20;

    /// Runs work on a new thread with the large stack and returns its result. A panic of the
    /// work goes on in the calling thread.
    pub fn run<T: Send>(work: impl FnOnce() -> T + Send) -> T {
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .stack_size(Self::size)
                .spawn_scoped(scope, work)
                .expect("start a thread with a large stack");
            match worker.join() {
                Ok(result) => result,
                Err(panic) => std::panic::resume_unwind(panic),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::LargeStack;

    #[test]
    fn workRunsAndGivesItsResult() {
        assert_eq!(LargeStack::run(|| 6 * 7), 42);
    }

    #[test]
    fn workCanUseMoreStackThanASpawnedThreadHas() {
        let total = LargeStack::run(|| {
            let buffer = [1u8; 16 << 20];
            std::hint::black_box(&buffer)
                .iter()
                .map(|byte| u64::from(*byte))
                .sum::<u64>()
        });
        assert_eq!(total, 16 << 20);
    }

    #[test]
    #[should_panic(expected = "the work failed")]
    fn aPanicOfTheWorkGoesOnInTheCaller() {
        LargeStack::run(|| panic!("the work failed"));
    }
}
