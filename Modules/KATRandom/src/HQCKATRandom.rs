// Translated from the HQC generator of liboqs `tests/test_helpers.c` (MIT).

use OQSNativeDomain::RandomGenerating;
use OQSNativeSHA3::{SHAKE256, SHAKEReader};

/// The SHAKE256 generator that liboqs uses for the known answers of HQC.
///
/// The generator absorbs the 48 bytes of entropy, the optional 48-byte personalization string
/// and the domain byte zero, and then gives the SHAKE256 output stream. A clone is the saved
/// state of `hqc_prng_get_state`.
#[derive(Clone)]
pub struct HQCKATRandom {
    reader: SHAKEReader,
}

impl HQCKATRandom {
    /// The domain byte of the HQC generator.
    const domain: u8 = 0;

    /// Seeds a generator, as `hqc_prng_seed` does.
    pub fn new(entropy: &[u8; 48], personalization: Option<&[u8; 48]>) -> Self {
        let mut function = SHAKE256::new();
        function.absorb(entropy);
        if let Some(personalization) = personalization {
            function.absorb(personalization);
        }
        function.absorb(&[Self::domain]);
        HQCKATRandom {
            reader: function.finalize(),
        }
    }
}

impl RandomGenerating for HQCKATRandom {
    /// Fills a buffer with the next bytes of the stream. Unlike the NIST generator, the output
    /// does not depend on how the requests split the bytes.
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        self.reader.squeeze(bytes);
    }
}
