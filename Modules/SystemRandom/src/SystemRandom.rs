use OQSNativeDomain::RandomGenerating;
use std::fs::File;
use std::io::{self, Read};

/// The random source of the operating system, read from `/dev/urandom`.
pub struct SystemRandom {
    source: File,
}

impl SystemRandom {
    /// The file that gives the random bytes of the operating system.
    const sourcePath: &'static str = "/dev/urandom";

    /// Opens the random source of the operating system.
    pub fn new() -> io::Result<Self> {
        Ok(SystemRandom {
            source: File::open(Self::sourcePath)?,
        })
    }
}

impl RandomGenerating for SystemRandom {
    /// Fills a buffer with random bytes from the operating system.
    ///
    /// # Panics
    ///
    /// Panics when the operating system gives no random bytes. An algorithm must not go on
    /// without them, and the read of an open `/dev/urandom` does not fail on a working system.
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.source
            .read_exact(bytes)
            .expect("the operating system gives random bytes");
    }
}
