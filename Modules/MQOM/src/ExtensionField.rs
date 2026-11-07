use alloc::vec;
use alloc::vec::Vec;

/// The extension field of the proof of a parameter set: GF(2^8) or GF(2^16).
///
/// GF(2^8) is `F2[x] / (x^8 + x^4 + x^3 + x + 1)`, the field of Rijndael: bit i of a byte is the
/// coefficient of x^i. GF(2^16) is `GF(2^8)[Y] / (Y^2 + Y + 32)`: the low byte of a 16-bit value
/// is the constant coefficient and the high byte is the coefficient of Y, as `fields_ref.h`
/// computes them. An element of either field is a `u16`, and an element of GF(2^8) has a zero
/// high byte. The base field GF(16) lies in both through `lifted`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtensionField {
    /// GF(2^8), the field of the fast sets.
    gf256,
    /// GF(2^16), the field of the short sets.
    gf65536,
}

impl ExtensionField {
    /// The number of bits of an element: 8 or 16.
    pub(crate) const fn bitCount(self) -> usize {
        match self {
            ExtensionField::gf256 => 8,
            ExtensionField::gf65536 => 16,
        }
    }

    /// The number of bytes of an element: 1 or 2.
    pub(crate) const fn byteCount(self) -> usize {
        self.bitCount() / 8
    }

    /// The product of two elements, as `gf256_mult_ref` and `gf256to2_mult_ref` compute it,
    /// with no branch and no table on the values.
    pub(crate) fn product(self, left: u16, right: u16) -> u16 {
        match self {
            ExtensionField::gf256 => u16::from(byteProduct(left as u8, right as u8)),
            ExtensionField::gf65536 => {
                let (left0, left1) = (left as u8, (left >> 8) as u8);
                let (right0, right1) = (right as u8, (right >> 8) as u8);
                let high = byteProduct(left1, right1);
                let low = byteProduct(left0, right0);
                // Y^2 = Y + 32, so the coefficient of Y^2 adds 32 times itself to the constant
                // and itself to the coefficient of Y.
                let constant = low ^ byteProduct(high, 32);
                let linear = low ^ byteProduct(left0 ^ left1, right0 ^ right1);
                (u16::from(linear) << 8) + u16::from(constant)
            }
        }
    }

    /// Reads elements from bytes, one byte or two little-endian bytes each, as
    /// `field_ext_parse` does.
    pub(crate) fn decode(self, bytes: &[u8], elements: &mut [u16]) {
        match self {
            ExtensionField::gf256 => {
                for (element, byte) in elements.iter_mut().zip(bytes) {
                    *element = u16::from(*byte);
                }
            }
            ExtensionField::gf65536 => {
                for (element, pair) in elements.iter_mut().zip(bytes.chunks_exact(2)) {
                    *element = u16::from_le_bytes([pair[0], pair[1]]);
                }
            }
        }
    }

    /// The elements of bytes, as `decode` reads them, one element for each byte or pair.
    pub(crate) fn decoded(self, bytes: &[u8]) -> Vec<u16> {
        let mut elements = vec![0u16; bytes.len() / self.byteCount()];
        self.decode(bytes, &mut elements);
        elements
    }

    /// Writes elements as bytes, as `field_ext_serialize` does.
    pub(crate) fn encode(self, elements: &[u16], bytes: &mut [u8]) {
        match self {
            ExtensionField::gf256 => {
                for (byte, element) in bytes.iter_mut().zip(elements) {
                    *byte = *element as u8;
                }
            }
            ExtensionField::gf65536 => {
                for (pair, element) in bytes.chunks_exact_mut(2).zip(elements) {
                    pair.copy_from_slice(&element.to_le_bytes());
                }
            }
        }
    }

    /// The bytes of elements, as `encode` writes them.
    pub(crate) fn encoded(self, elements: &[u16]) -> Vec<u8> {
        let mut bytes = vec![0u8; elements.len() * self.byteCount()];
        self.encode(elements, &mut bytes);
        bytes
    }
}

/// The product x · value in GF(2^8), as `gf256_lane_xtime_x4` computes it for one byte.
pub(crate) fn doubled(value: u8) -> u8 {
    (value << 1) ^ (0x1B & 0u8.wrapping_sub(value >> 7))
}

/// The product of two elements of GF(2^8), as `gf256_mult4_ref` computes it: the sum of the
/// doublings of the left factor that the bits of the right factor select, with masks in
/// place of branches.
pub(crate) fn byteProduct(left: u8, right: u8) -> u8 {
    let mut product = 0u8;
    let mut shifted = left;
    for bit in 0..8 {
        product ^= shifted & 0u8.wrapping_sub((right >> bit) & 1);
        shifted = doubled(shifted);
    }
    product
}

/// The element of GF(2^8) of an element of GF(16): the bits 0 to 3 map to 0x01, 0xE0, 0x5D
/// and 0xB0, as `gf16_gf256_mult_ref` and `gf256_vect_lift_from_gf16_ref` lift them.
pub(crate) fn lifted(nibble: u8) -> u8 {
    let bit = |index: u32| 0u8.wrapping_sub((nibble >> index) & 1);
    (nibble & 1) ^ (bit(1) & 0xE0) ^ (bit(2) & 0x5D) ^ (bit(3) & 0xB0)
}

/// Element `index` of a vector of GF(16) with two elements to a byte: the low nibble of the
/// byte for an even index, as `field_gf16_vect_unpack` reads it.
pub(crate) fn nibble(bytes: &[u8], index: usize) -> u8 {
    (bytes[index / 2] >> (4 * (index % 2))) & 0x0F
}

#[cfg(test)]
mod tests {
    use super::{ExtensionField, byteProduct, doubled, lifted, nibble};
    use crate::testInputs::{cAnswer, elementsDigest, everySet, sequenceBytes, sequenceElements};

    /// The product in GF(2^8) by its definition: the carry-less product of the bytes, then the
    /// reduction modulo x^8 + x^4 + x^3 + x + 1 from the top bit down.
    fn definedByteProduct(left: u8, right: u8) -> u8 {
        let mut wide = 0u16;
        for bit in 0..8 {
            if (right >> bit) & 1 == 1 {
                wide ^= u16::from(left) << bit;
            }
        }
        for bit in (8..16).rev() {
            if (wide >> bit) & 1 == 1 {
                wide ^= 0x11B << (bit - 8);
            }
        }
        wide as u8
    }

    #[test]
    fn byteProductIsTheProductOfTheRijndaelFieldForEveryPair() {
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                assert_eq!(
                    byteProduct(left, right),
                    definedByteProduct(left, right),
                    "{left:#04x} {right:#04x}"
                );
            }
        }
        // FIPS 197, Section 4.2: {57} {83} = {c1}, and {57} {13} = {fe}.
        assert_eq!(byteProduct(0x57, 0x83), 0xC1);
        assert_eq!(byteProduct(0x57, 0x13), 0xFE);
        assert_eq!(doubled(0x80), 0x1B);
        assert_eq!(doubled(0x57), 0xAE);
    }

    #[test]
    fn theLiftIsAFieldMapFromGF16() {
        // The images of the bits are 0x01, 0xE0, 0x5D and 0xB0, and the map keeps sums and
        // products: the bits are the powers of the element z = 0xE0 of GF(2^8), which is a
        // root of z^4 + z + 1, the polynomial of GF(16) of the MQOM specification.
        assert_eq!(
            [lifted(1), lifted(2), lifted(4), lifted(8)],
            [0x01, 0xE0, 0x5D, 0xB0]
        );
        let z = 0xE0;
        assert_eq!(byteProduct(z, z), 0x5D);
        assert_eq!(byteProduct(0x5D, z), 0xB0);
        assert_eq!(byteProduct(0xB0, z), 0xE0 ^ 0x01);
        // The product of GF(16) modulo z^4 + z + 1, by its definition.
        let gf16Product = |left: u8, right: u8| {
            let mut wide = 0u8;
            for bit in 0..4 {
                if (right >> bit) & 1 == 1 {
                    wide ^= left << bit;
                }
            }
            for bit in (4..7).rev() {
                if (wide >> bit) & 1 == 1 {
                    wide ^= 0b10011 << (bit - 4);
                }
            }
            wide
        };
        for left in 0..16u8 {
            for right in 0..16u8 {
                assert_eq!(lifted(left) ^ lifted(right), lifted(left ^ right));
                assert_eq!(
                    byteProduct(lifted(left), lifted(right)),
                    lifted(gf16Product(left, right)),
                    "{left} {right}"
                );
            }
        }
    }

    #[test]
    fn theWordProductIsTheProductOfTheTowerField() {
        let field = ExtensionField::gf65536;
        let mut state = 0x4D51_4F4Du32;
        let mut next = || {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u16
        };
        for _ in 0..2000 {
            let (left, right, third) = (next(), next(), next());
            // The product is commutative, associative and distributes over the sum.
            assert_eq!(field.product(left, right), field.product(right, left));
            assert_eq!(
                field.product(field.product(left, right), third),
                field.product(left, field.product(right, third))
            );
            assert_eq!(
                field.product(left, right ^ third),
                field.product(left, right) ^ field.product(left, third)
            );
        }
        // Y Y = Y + 32, the reduction polynomial Y^2 + Y + 32 of `gf256to2_mult_ref`, and a
        // constant multiplies each coefficient.
        assert_eq!(field.product(0x0100, 0x0100), 0x0120);
        assert_eq!(field.product(0x0057, 0x8300), 0xC100);
        assert_eq!(field.product(0x0057, 0x0083), 0x00C1);
        // The multiplicative group has 2^16 - 1 elements, so a^(2^16 - 1) = 1, the product of
        // the squares a^(2^k) for k = 0 to 15.
        for start in [0x1234u16, 0x0001, 0xFFFF, 0x0100] {
            let mut element = start;
            let mut product = 1u16;
            for _ in 0..16 {
                product = field.product(product, element);
                element = field.product(element, element);
            }
            assert_eq!(product, 1, "{start:#06x}");
        }
    }

    #[test]
    fn theByteFieldMultipliesTheLowBytes() {
        let field = ExtensionField::gf256;
        assert_eq!(field.product(0x57, 0x83), 0xC1);
        assert_eq!(field.bitCount(), 8);
        assert_eq!(ExtensionField::gf65536.byteCount(), 2);
    }

    #[test]
    fn elementsAreBytesOrLittleEndianPairs() {
        let bytes = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(ExtensionField::gf256.decoded(&bytes), vec![1, 2, 3, 4]);
        assert_eq!(
            ExtensionField::gf65536.decoded(&bytes),
            vec![0x0201, 0x0403]
        );
        assert_eq!(
            ExtensionField::gf65536.encoded(&[0x0201, 0x0403]),
            bytes.to_vec()
        );
        assert_eq!(ExtensionField::gf256.encoded(&[1, 2, 3, 4]), bytes.to_vec());
    }

    #[test]
    fn nibblesAreReadLowFirst() {
        let bytes = [0x21, 0x43];
        let values: Vec<u8> = (0..4).map(|index| nibble(&bytes, index)).collect();
        assert_eq!(values, vec![1, 2, 3, 4]);
    }

    #[test]
    fn productsGiveTheValuesOfTheCFunctionsForEverySet() {
        // `field_ext_mult` of 64 seeded pairs, and `field_ext_base_constant_vect_mult` of a
        // seeded constant and 64 seeded elements of GF(16).
        for parameters in everySet() {
            let name = parameters.description.name;
            let field = parameters.extensionField;
            let left = sequenceElements(parameters, 64, 1);
            let right = sequenceElements(parameters, 64, 2);
            let products: Vec<u16> = left
                .iter()
                .zip(&right)
                .map(|(a, b)| field.product(*a, *b))
                .collect();
            assert_eq!(
                elementsDigest(parameters, &[products]),
                cAnswer(name, "fieldProducts"),
                "{name}"
            );
            let base = sequenceBytes(32, 3);
            let liftedProducts: Vec<u16> = (0..64)
                .map(|index| field.product(left[0], u16::from(lifted(nibble(&base, index)))))
                .collect();
            assert_eq!(
                elementsDigest(parameters, &[liftedProducts]),
                cAnswer(name, "liftedProducts"),
                "{name}"
            );
        }
    }
}
