/// A source of random bytes for key generation, encapsulation and signing.
pub trait RandomGenerating {
    /// Fills a buffer with random bytes.
    ///
    /// An algorithm asks for its random bytes in the same order and in the same amounts as the
    /// C code of liboqs, so a deterministic source gives the same output as the C library.
    fn fillRandomBytes(&mut self, bytes: &mut [u8]);
}
