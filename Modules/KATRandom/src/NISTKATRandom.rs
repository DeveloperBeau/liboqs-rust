// Translated from liboqs `src/common/rand/rand_nist.c`, which is NIST-developed software:
// "NIST-developed software is provided by NIST as a public service." See
// `THIRD_PARTY_NOTICES.md`. The port keeps the generator state in a value, not in a global.

use OQSNativeAES::AES256;
use OQSNativeDomain::RandomGenerating;

/// The AES-256 CTR DRBG of the NIST submission package, which the known-answer tests of
/// liboqs use, with its state in a value.
///
/// A clone is the saved state of `OQS_randombytes_nist_kat_get_state`, so a test can save and
/// restore the generator as `tests/kat_kem.c` does.
#[derive(Clone)]
pub struct NISTKATRandom {
    key: [u8; 32],
    counter: [u8; 16],
    reseedCounter: u64,
}

impl NISTKATRandom {
    /// Seeds a generator with 48 bytes of entropy and an optional 48-byte personalization
    /// string, as `OQS_randombytes_nist_kat_init_256bit` does.
    pub fn new(entropy: &[u8; 48], personalization: Option<&[u8; 48]>) -> Self {
        let mut seedMaterial = *entropy;
        if let Some(personalization) = personalization {
            for (byte, mask) in seedMaterial.iter_mut().zip(personalization) {
                *byte ^= mask;
            }
        }
        let mut generator = NISTKATRandom {
            key: [0; 32],
            counter: [0; 16],
            reseedCounter: 1,
        };
        generator.update(Some(&seedMaterial));
        generator
    }

    /// The number of generate calls since seeding, plus one, as the C state counts them.
    pub fn reseedCounter(&self) -> u64 {
        self.reseedCounter
    }

    /// Adds one to the 128-bit big-endian counter block.
    fn incrementCounter(&mut self) {
        for byte in self.counter.iter_mut().rev() {
            let (sum, didCarry) = byte.overflowing_add(1);
            *byte = sum;
            if !didCarry {
                return;
            }
        }
    }

    /// The update function of the DRBG: three counter blocks of keystream, mixed with the
    /// provided data, become the new key and counter.
    fn update(&mut self, providedData: Option<&[u8; 48]>) {
        let cipher = AES256::new(&self.key);
        let mut temporary = [0u8; 48];
        for block in temporary.chunks_exact_mut(16) {
            self.incrementCounter();
            cipher.encryptBlocks(&self.counter, block);
        }
        if let Some(data) = providedData {
            for (byte, mask) in temporary.iter_mut().zip(data) {
                *byte ^= mask;
            }
        }
        self.key.copy_from_slice(&temporary[..32]);
        self.counter.copy_from_slice(&temporary[32..]);
    }
}

impl RandomGenerating for NISTKATRandom {
    /// Fills a buffer as `OQS_randombytes_nist_kat` does: one counter block for each 16
    /// bytes, then one update. The output depends on how the requests split the bytes,
    /// because each request ends with an update.
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        let cipher = AES256::new(&self.key);
        for chunk in bytes.chunks_mut(16) {
            self.incrementCounter();
            let mut block = [0u8; 16];
            cipher.encryptBlocks(&self.counter, &mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        self.update(None);
        self.reseedCounter += 1;
    }
}
