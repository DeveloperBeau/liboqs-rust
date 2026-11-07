use OQSNativeDomain::RandomGenerating;
use alloc::vec::Vec;

/// The random source of the vector programs: the bytes of a test vector, in order.
///
/// `tests/vectors_sig.c` of liboqs replaces `OQS_randombytes` with `MLDSA_randombytes`, which
/// copies the next bytes of the seed or the randomness of a vector. A request for more bytes
/// than the vector holds is a defect of the caller, and the source panics with that reason.
pub struct VectorRandom {
    bytes: Vec<u8>,
    position: usize,
}

impl VectorRandom {
    /// Makes a source that gives the bytes of a vector.
    pub fn new(bytes: &[u8]) -> Self {
        VectorRandom {
            bytes: bytes.to_vec(),
            position: 0,
        }
    }

    /// The number of bytes that the source has not given yet.
    pub fn remainingCount(&self) -> usize {
        self.bytes.len() - self.position
    }
}

impl RandomGenerating for VectorRandom {
    fn fillRandomBytes(&mut self, bytes: &mut [u8]) {
        let end = self.position + bytes.len();
        assert!(
            end <= self.bytes.len(),
            "the request is for {} bytes, and the vector has {} left",
            bytes.len(),
            self.remainingCount()
        );
        bytes.copy_from_slice(&self.bytes[self.position..end]);
        self.position = end;
    }
}

#[cfg(test)]
mod tests {
    use super::VectorRandom;
    use OQSNativeDomain::RandomGenerating;

    #[test]
    fn requestsTakeTheBytesOfTheVectorInOrder() {
        let mut random = VectorRandom::new(&[1, 2, 3, 4, 5]);
        let mut first = [0u8; 2];
        random.fillRandomBytes(&mut first);
        assert_eq!(first, [1, 2]);
        assert_eq!(random.remainingCount(), 3);
        let mut rest = [0u8; 3];
        random.fillRandomBytes(&mut rest);
        assert_eq!(rest, [3, 4, 5]);
        assert_eq!(random.remainingCount(), 0);
        random.fillRandomBytes(&mut []);
    }

    #[test]
    #[should_panic(expected = "the request is for 2 bytes, and the vector has 1 left")]
    fn aRequestPastTheEndOfTheVectorIsADefectOfTheCaller() {
        let mut random = VectorRandom::new(&[9]);
        random.fillRandomBytes(&mut [0u8; 2]);
    }
}
