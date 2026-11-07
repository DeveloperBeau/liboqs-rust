use crate::fieldArithmetic::{loadWord, storeWord};
use alloc::vec;
use alloc::vec::Vec;

/// Entries of a batched matrix in little-endian words, each entry padded with zero bytes to a
/// whole number of words.
///
/// A key pair adds thousands of products to each entry of a row. The words of the row take
/// those sums with no load and no store of the bytes for each product. The padding stays zero,
/// because each lane of a product of a zero lane is zero.
pub(crate) struct PaddedEntries {
    words: Vec<u64>,
    entryLength: usize,
    entryWords: usize,
}

impl PaddedEntries {
    /// The entries of the bytes of a batched matrix, entry after entry.
    pub(crate) fn new(bytes: &[u8], entryLength: usize) -> Self {
        let entryWords = entryLength.div_ceil(8);
        let mut words = Vec::with_capacity(bytes.len() / entryLength * entryWords);
        for entry in bytes.chunks_exact(entryLength) {
            words.extend(entry.chunks(8).map(loadWord));
        }
        PaddedEntries {
            words,
            entryLength,
            entryWords,
        }
    }

    /// A number of zero entries of a length.
    pub(crate) fn zeroed(count: usize, entryLength: usize) -> Self {
        let entryWords = entryLength.div_ceil(8);
        PaddedEntries {
            words: vec![0; count * entryWords],
            entryLength,
            entryWords,
        }
    }

    /// The words of an entry.
    pub(crate) fn entry(&self, index: usize) -> &[u64] {
        &self.words[index * self.entryWords..][..self.entryWords]
    }

    /// The words of an entry, for the sums of a product.
    pub(crate) fn entryMut(&mut self, index: usize) -> &mut [u64] {
        &mut self.words[index * self.entryWords..][..self.entryWords]
    }

    /// Writes the entries over the bytes of a batched matrix of as many entries.
    pub(crate) fn writeBytes(&self, bytes: &mut [u8]) {
        for (entry, words) in bytes
            .chunks_exact_mut(self.entryLength)
            .zip(self.words.chunks_exact(self.entryWords))
        {
            for (chunk, word) in entry.chunks_mut(8).zip(words) {
                storeWord(chunk, *word);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PaddedEntries;
    use crate::testInputs::sequence;

    #[test]
    fn entriesOfAnyLengthComeBackAsTheirBytes() {
        // Two entries of 44 bytes: five whole words and four bytes of a sixth word each.
        let bytes = sequence(88, 3);
        let entries = PaddedEntries::new(&bytes, 44);
        assert_eq!(entries.entry(1).len(), 6);
        assert_eq!(
            entries.entry(0)[0],
            u64::from_le_bytes(bytes[..8].try_into().expect("8"))
        );
        // The padding of an entry is zero.
        assert_eq!(entries.entry(0)[5] >> 32, 0);
        let mut written = vec![0u8; 88];
        entries.writeBytes(&mut written);
        assert_eq!(written, bytes);
        let mut zero = PaddedEntries::zeroed(2, 44);
        zero.entryMut(1)[0] = 0x0807_0605_0403_0201;
        let mut written = vec![0xFFu8; 88];
        zero.writeBytes(&mut written);
        assert_eq!(&written[44..52], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(
            written[..44]
                .iter()
                .chain(&written[52..])
                .all(|byte| *byte == 0)
        );
    }
}
