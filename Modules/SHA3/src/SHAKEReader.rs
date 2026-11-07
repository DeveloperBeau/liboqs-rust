use crate::KeccakSponge;

/// The output stream of a finalized SHAKE function.
///
/// Each call to `squeeze` continues the stream where the last call ended, so the output is
/// the same however the calls split it.
#[derive(Clone)]
pub struct SHAKEReader {
    sponge: KeccakSponge,
}

impl SHAKEReader {
    pub(crate) fn new(sponge: KeccakSponge) -> Self {
        SHAKEReader { sponge }
    }

    /// Fills a buffer with the next bytes of the output stream.
    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.sponge.squeeze(output);
    }
}
