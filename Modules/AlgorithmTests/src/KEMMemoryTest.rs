use OQSNativeDomain::{KeyEncapsulating, RandomGenerating};
use alloc::format;
use alloc::string::String;
use std::path::Path;

/// The memory program of liboqs for KEMs, `tests/test_kem_mem.c`, on a Rust mechanism.
///
/// The C program runs the key pair, the encapsulation and the decapsulation in three
/// processes, with the values in files between them. This test runs the three steps with the
/// values in files of a folder, so each value crosses storage as bytes.
pub struct KEMMemoryTest;

impl KEMMemoryTest {
    /// Runs the three steps with the files in a folder, which must exist.
    pub fn run(
        mechanism: &dyn KeyEncapsulating,
        random: &mut dyn RandomGenerating,
        folder: &Path,
    ) -> Result<(), String> {
        let name = mechanism.description().name;
        let fileName = |part: &str| folder.join(format!("{}-{part}", name.replace('/', "_")));
        let write = |part: &str, bytes: &[u8]| {
            std::fs::write(fileName(part), bytes)
                .map_err(|error| format!("{name}: write {part}: {error}"))
        };
        let read = |part: &str| {
            std::fs::read(fileName(part)).map_err(|error| format!("{name}: read {part}: {error}"))
        };
        let keyPair = mechanism
            .generateKeyPair(random)
            .map_err(|error| format!("{name}: the key pair failed: {error}"))?;
        write("pk", &keyPair.publicKey)?;
        write("sk", keyPair.secretKey.bytes())?;
        drop(keyPair);
        let encapsulation = mechanism
            .encapsulate(&read("pk")?, random)
            .map_err(|error| format!("{name}: the encapsulation failed: {error}"))?;
        write("ct", &encapsulation.ciphertext)?;
        write("ss", encapsulation.sharedSecret.bytes())?;
        drop(encapsulation);
        let recovered = mechanism
            .decapsulate(&read("ct")?, &read("sk")?)
            .map_err(|error| format!("{name}: the decapsulation failed: {error}"))?;
        if recovered.bytes() != read("ss")?.as_slice() {
            return Err(format!("{name}: the shared secrets are not equal"));
        }
        for part in ["pk", "sk", "ct", "ss"] {
            let _ = std::fs::remove_file(fileName(part));
        }
        Ok(())
    }
}
