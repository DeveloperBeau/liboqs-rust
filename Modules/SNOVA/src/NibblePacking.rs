use alloc::vec;
use alloc::vec::Vec;

/// The four packings of GF(16) elements into bytes, the `convert_*` functions of
/// `snova_common.c`.
///
/// The plain packing puts element `2 i` in the low half of byte `i` and element `2 i + 1` in its
/// high half. The packing in halves puts the first half of the elements in the low halves of the
/// bytes and the second half in the high halves. An odd count leaves the high half of the last
/// byte at zero, and the unpacking does not read it.
pub(crate) struct NibblePacking;

impl NibblePacking {
    /// Writes the elements of bytes, `convert_bytes_to_GF16s`.
    pub(crate) fn unpack(bytes: &[u8], elements: &mut [u8]) {
        let count = elements.len();
        for (pair, byte) in elements.chunks_exact_mut(2).zip(bytes) {
            pair[0] = byte & 0x0F;
            pair[1] = (byte >> 4) & 0x0F;
        }
        if count % 2 == 1 {
            elements[count - 1] = bytes[count / 2] & 0x0F;
        }
    }

    /// The first `count` elements of bytes, `convert_bytes_to_GF16s`.
    pub(crate) fn unpacked(bytes: &[u8], count: usize) -> Vec<u8> {
        let mut elements = vec![0u8; count];
        Self::unpack(bytes, &mut elements);
        elements
    }

    /// The bytes of elements, `convert_GF16s_to_bytes`.
    pub(crate) fn packed(elements: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(elements.len().div_ceil(2));
        for pair in elements.chunks(2) {
            // The two halves are disjoint, so `+` joins them.
            let high = pair.get(1).map_or(0, |element| element << 4);
            bytes.push(pair[0] + high);
        }
        bytes
    }

    /// The first `count` elements of bytes packed in halves,
    /// `convert_bytes_to_GF16s_cut_in_half`.
    pub(crate) fn unpackedInHalves(bytes: &[u8], count: usize) -> Vec<u8> {
        let half = count.div_ceil(2);
        let mut elements = vec![0u8; count];
        for (element, byte) in elements[..half].iter_mut().zip(bytes) {
            *element = byte & 0x0F;
        }
        for (element, byte) in elements[half..].iter_mut().zip(bytes) {
            *element = byte >> 4;
        }
        elements
    }

    /// The bytes of elements packed in halves, `convert_GF16s_to_bytes_merger_in_half`.
    pub(crate) fn packedInHalves(elements: &[u8]) -> Vec<u8> {
        let half = elements.len().div_ceil(2);
        let (low, high) = elements.split_at(half);
        let mut bytes: Vec<u8> = low
            .iter()
            .zip(high)
            .map(|(low, high)| low + (high << 4))
            .collect();
        if elements.len() % 2 == 1 {
            bytes.push(low[half - 1]);
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::NibblePacking;

    const exampleBytes: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];

    #[test]
    fn thePlainPackingPutsTheLowHalfFirst() {
        // The example of `convert_bytes_to_GF16s`: each byte gives its low half, then its high
        // half.
        let elements = [2, 1, 4, 3, 6, 5, 8, 7, 0xA, 9, 0xC, 0xB];
        assert_eq!(NibblePacking::unpacked(&exampleBytes, 12), elements);
        assert_eq!(NibblePacking::packed(&elements), exampleBytes);
        // An odd count reads the low half of the last byte only, and packs it alone.
        assert_eq!(NibblePacking::unpacked(&exampleBytes, 5), [2, 1, 4, 3, 6]);
        assert_eq!(
            NibblePacking::unpacked(&[0x12, 0xF4], 3),
            NibblePacking::unpacked(&[0x12, 0x04], 3)
        );
        assert_eq!(NibblePacking::packed(&[2, 1, 4]), [0x12, 0x04]);
        let mut elements = [0xFF; 3];
        NibblePacking::unpack(&[0xAB, 0xCD], &mut elements);
        assert_eq!(elements, [0xB, 0xA, 0xD]);
    }

    #[test]
    fn thePackingInHalvesPutsTheFirstHalfInTheLowHalves() {
        // The example of `convert_bytes_to_GF16s_cut_in_half`.
        let elements = [2, 4, 6, 8, 0xA, 0xC, 1, 3, 5, 7, 9, 0xB];
        assert_eq!(NibblePacking::unpackedInHalves(&exampleBytes, 12), elements);
        assert_eq!(NibblePacking::packedInHalves(&elements), exampleBytes);
        // An odd count: the first half has the extra element, which packs alone.
        assert_eq!(
            NibblePacking::unpackedInHalves(&[0x12, 0x34, 0x56], 5),
            [2, 4, 6, 1, 3]
        );
        assert_eq!(
            NibblePacking::packedInHalves(&[2, 4, 6, 1, 3]),
            [0x12, 0x34, 0x06]
        );
    }
}
