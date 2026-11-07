use OQSNativeDomain::{RandomGenerating, Signing};
use alloc::format;
use alloc::string::String;
use std::path::Path;

/// The memory program of liboqs for signature schemes, `tests/test_sig_mem.c`, on a Rust
/// scheme.
///
/// The C program runs the key pair, the signature and the verification in three processes,
/// with the values in files between them. This test runs the three steps with the values in
/// files of a folder, so each value crosses storage as bytes.
pub struct SignatureMemoryTest;

impl SignatureMemoryTest {
    /// Runs the three steps with the files in a folder, which must exist.
    pub fn run(
        scheme: &dyn Signing,
        random: &mut dyn RandomGenerating,
        folder: &Path,
    ) -> Result<(), String> {
        let name = scheme.description().name;
        let fileName = |part: &str| folder.join(format!("{}-{part}", name.replace('/', "_")));
        let write = |part: &str, bytes: &[u8]| {
            std::fs::write(fileName(part), bytes)
                .map_err(|error| format!("{name}: write {part}: {error}"))
        };
        let read = |part: &str| {
            std::fs::read(fileName(part)).map_err(|error| format!("{name}: read {part}: {error}"))
        };
        let keyPair = scheme
            .generateKeyPair(random)
            .map_err(|error| format!("{name}: the key pair failed: {error}"))?;
        write("pk", &keyPair.publicKey)?;
        write("sk", keyPair.secretKey.bytes())?;
        drop(keyPair);
        let mut message = [0u8; 100];
        random.fillRandomBytes(&mut message);
        write("msg", &message)?;
        let signature = scheme
            .sign(&read("msg")?, &read("sk")?, random)
            .map_err(|error| format!("{name}: the signature failed: {error}"))?;
        write("sig", &signature)?;
        drop(signature);
        if !scheme.isValidSignature(&read("sig")?, &read("msg")?, &read("pk")?) {
            return Err(format!("{name}: the signature does not verify"));
        }
        for part in ["pk", "sk", "msg", "sig"] {
            let _ = std::fs::remove_file(fileName(part));
        }
        Ok(())
    }
}
