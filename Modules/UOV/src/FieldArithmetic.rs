/// The arithmetic of a field of UOV, GF(16) or GF(256), on single elements and element by
/// element on vectors, as `gf16.h` and `blas_u32.h` of the reference code compute it.
///
/// A vector packs its elements into bytes: two elements in a byte for GF(16), the first in the
/// low half, and one element in a byte for GF(256). The vector operations load eight bytes at a
/// time into a little-endian word and compute on each element of the word as a lane of its
/// own, as the C code does on 32-bit words. No lane reaches another lane, so the width of the
/// word does not change a byte of the result.
pub(crate) trait FieldArithmetic {
    /// The bits of an element: 4 for GF(16) and 8 for GF(256).
    const elementBits: u32;

    /// The top bit of each element of a word.
    const topBits: u64;

    /// The power x to the element bits, reduced by the polynomial of the field: `x + 1` for
    /// GF(16) and `x^4 + x^3 + x + 1` for GF(256).
    const reducedPower: u64;

    /// The elements of a byte.
    const elementsPerByte: usize = (8 / Self::elementBits) as usize;

    /// The bits of one element in a byte.
    const elementMask: u8 = ((1u16 << Self::elementBits) - 1) as u8;

    /// The inverse of an element, and zero for zero.
    fn inverse(element: u8) -> u8;

    /// The bytes of a vector of a number of elements.
    fn byteLength(elementCount: usize) -> usize {
        elementCount / Self::elementsPerByte
    }

    /// The element at an index of a vector, as `gf16v_get_ele` and `gf256v_get_ele` read it.
    fn element(vector: &[u8], index: usize) -> u8 {
        let shift = Self::elementBits as usize * (index % Self::elementsPerByte);
        (vector[index / Self::elementsPerByte] >> shift) & Self::elementMask
    }

    /// Sets the element at an index of a vector to a value of the field, as `gf16v_set_ele`
    /// and `gf256v_set_ele` write it.
    fn setElement(vector: &mut [u8], index: usize, value: u8) {
        let shift = Self::elementBits as usize * (index % Self::elementsPerByte);
        let byte = &mut vector[index / Self::elementsPerByte];
        *byte = (*byte & !(Self::elementMask << shift)) + (value << shift);
    }

    /// 1 when an element is not zero and 0 when it is zero, with no branch, as
    /// `gf16_is_nonzero` and `gf256_is_nonzero` compute it.
    fn isNonzero(element: u8) -> u8 {
        let value = u32::from(element & Self::elementMask);
        ((0u32.wrapping_sub(value) >> Self::elementBits) & 1) as u8
    }

    /// Each element of a word times the generator x.
    #[inline(always)]
    fn timesGenerator(word: u64) -> u64 {
        let top = word & Self::topBits;
        ((word ^ top) << 1) ^ ((top >> (Self::elementBits - 1)) * Self::reducedPower)
    }

    /// The masks of the bits of a scalar: all ones for a set bit and zero for a clear bit, in
    /// place of the multiplications by `(b >> k) & 1` of the C code.
    #[inline(always)]
    fn scalarMasks(scalar: u8) -> [u64; 8] {
        core::array::from_fn(|bit| 0u64.wrapping_sub(u64::from((scalar >> bit) & 1)))
    }

    /// Each element of a word times a scalar, as `gf16v_mul_u32` and `gf256v_mul_u32` compute
    /// it: the sum of the word times each power of x whose bit the scalar sets. The bits of the
    /// scalar above the element bits do not count.
    #[inline(always)]
    fn scaledWord(word: u64, masks: &[u64; 8]) -> u64 {
        let mut power = word;
        let mut product = power & masks[0];
        for mask in &masks[1..Self::elementBits as usize] {
            power = Self::timesGenerator(power);
            product ^= power & mask;
        }
        product
    }

    /// The product of two elements.
    fn product(left: u8, right: u8) -> u8 {
        let word = u64::from(left & Self::elementMask);
        (Self::scaledWord(word, &Self::scalarMasks(right)) as u8) & Self::elementMask
    }

    /// Adds a vector to an accumulator of the same length, as `gf256v_add` does.
    fn add(accumulator: &mut [u8], vector: &[u8]) {
        for (target, source) in accumulator.chunks_mut(8).zip(vector.chunks(8)) {
            storeWord(target, loadWord(target) ^ loadWord(source));
        }
    }

    /// Adds a vector times a scalar to an accumulator of the same length, as `gf16v_madd` and
    /// `gf256v_madd` do.
    fn multiplyAdd(accumulator: &mut [u8], vector: &[u8], scalar: u8) {
        let masks = Self::scalarMasks(scalar);
        for (target, source) in accumulator.chunks_mut(8).zip(vector.chunks(8)) {
            storeWord(
                target,
                loadWord(target) ^ Self::scaledWord(loadWord(source), &masks),
            );
        }
    }

    /// Multiplies each element of a vector by a scalar, as `gf16v_mul_scalar` and
    /// `gf256v_mul_scalar` do.
    fn scale(vector: &mut [u8], scalar: u8) {
        let masks = Self::scalarMasks(scalar);
        for chunk in vector.chunks_mut(8) {
            storeWord(chunk, Self::scaledWord(loadWord(chunk), &masks));
        }
    }
}

/// The little-endian word of up to eight bytes, with zeros after a shorter slice.
#[inline(always)]
pub(crate) fn loadWord(bytes: &[u8]) -> u64 {
    match <[u8; 8]>::try_from(bytes) {
        Ok(whole) => u64::from_le_bytes(whole),
        Err(_) => {
            let mut padded = [0u8; 8];
            padded[..bytes.len()].copy_from_slice(bytes);
            u64::from_le_bytes(padded)
        }
    }
}

/// Writes the low bytes of a little-endian word over a slice of up to eight bytes.
#[inline(always)]
pub(crate) fn storeWord(bytes: &mut [u8], word: u64) {
    let length = bytes.len();
    bytes.copy_from_slice(&word.to_le_bytes()[..length]);
}

#[cfg(test)]
mod tests {
    use super::{FieldArithmetic, loadWord, storeWord};
    use crate::gf16::GF16;
    use crate::gf256::GF256;

    #[test]
    fn wordsLoadAndStoreLittleEndianWithZerosAfterAShortSlice() {
        assert_eq!(loadWord(&[1, 2, 3, 4, 5, 6, 7, 8]), 0x0807_0605_0403_0201);
        assert_eq!(loadWord(&[0xAA, 0xBB]), 0xBBAA);
        let mut bytes = [0u8; 3];
        storeWord(&mut bytes, 0x0102_0304_0506);
        assert_eq!(bytes, [0x06, 0x05, 0x04]);
    }

    #[test]
    fn elementsAreTheHalvesOfABytePackedLowFirstOrWholeBytes() {
        let vector = [0x21u8, 0x43];
        assert_eq!(
            (0..4)
                .map(|index| GF16::element(&vector, index))
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(GF256::element(&vector, 1), 0x43);
        let mut written = [0x21u8, 0x43];
        GF16::setElement(&mut written, 1, 0xF);
        GF16::setElement(&mut written, 2, 0x0);
        assert_eq!(written, [0xF1, 0x40]);
        GF256::setElement(&mut written, 0, 0x9C);
        assert_eq!(written, [0x9C, 0x40]);
        assert_eq!((GF16::byteLength(160), GF256::byteLength(112)), (80, 112));
    }

    #[test]
    fn isNonzeroIsOneExactlyForTheElementsThatAreNotZero() {
        assert_eq!(GF16::isNonzero(0), 0);
        assert!((1..16).all(|element| GF16::isNonzero(element) == 1));
        // Only the low half of a byte is a GF(16) element, as `gf16_is_nonzero` masks it.
        assert_eq!(GF16::isNonzero(0xF0), 0);
        assert_eq!(GF256::isNonzero(0), 0);
        assert!((1..=255).all(|element| GF256::isNonzero(element) == 1));
    }

    #[test]
    fn eachLaneOfAWordIsMultipliedOnItsOwn() {
        // Each element of a word times every scalar equals the products of the elements, so no
        // lane reaches another lane, also for the top bits of each lane.
        let word16 = 0xFEDC_BA98_7654_3210u64;
        for scalar in 0..16u8 {
            let scaled = GF16::scaledWord(word16, &GF16::scalarMasks(scalar));
            for lane in 0..16 {
                let element = ((word16 >> (4 * lane)) & 0xF) as u8;
                assert_eq!(
                    ((scaled >> (4 * lane)) & 0xF) as u8,
                    GF16::product(element, scalar)
                );
            }
        }
        let word256 = 0x80FF_1B53_CA01_7E00u64;
        for scalar in 0..=255u8 {
            let scaled = GF256::scaledWord(word256, &GF256::scalarMasks(scalar));
            for lane in 0..8 {
                let element = ((word256 >> (8 * lane)) & 0xFF) as u8;
                assert_eq!(
                    ((scaled >> (8 * lane)) & 0xFF) as u8,
                    GF256::product(element, scalar)
                );
            }
        }
    }

    #[test]
    fn vectorOperationsActOnEveryElementAndOnAShortTail() {
        // Eleven bytes: one whole word and a tail of three bytes.
        let vector: Vec<u8> = (1..=11).map(|byte| byte * 23).collect();
        let mut accumulator = vec![0x5Au8; 11];
        GF256::multiplyAdd(&mut accumulator, &vector, 0x53);
        for (index, byte) in accumulator.iter().enumerate() {
            assert_eq!(*byte, 0x5A ^ GF256::product(vector[index], 0x53), "{index}");
        }
        let mut scaled = vector.clone();
        GF16::scale(&mut scaled, 0x9);
        for index in 0..22 {
            assert_eq!(
                GF16::element(&scaled, index),
                GF16::product(GF16::element(&vector, index), 9),
                "{index}"
            );
        }
        let mut sum = vector.clone();
        GF256::add(&mut sum, &[0xFF; 11]);
        assert!(sum.iter().zip(&vector).all(|(sum, byte)| *sum == !*byte));
    }
}
