use crate::modularPolynomial::modulus;
use alloc::vec::Vec;

/// The byte encodings of Falcon, as `codec.c` of the Falcon code of PQClean gives them.
///
/// - The modular encoding writes each value modulo `q` in exactly 14 bits. It is the encoding
///   of the public key.
/// - The trimmed encoding writes each signed integer in a fixed number of bits, with the sign
///   bit, and refuses `-2^(bits - 1)`. It is the encoding of the secret key.
/// - The compressed encoding writes each signed integer as its sign, its low seven bits and a
///   unary count of its high bits. It is the encoding of a signature.
///
/// The bits of each value go from the most significant bit, and the last byte is padded with
/// zero bits, which a decoder checks.
pub(crate) struct Encoding;

/// The bits of each coefficient of `f` and `g` in a secret key, for each `logn` from 1 to 10,
/// `max_fg_bits` of `codec.c`.
pub(crate) const smallPolynomialBits: [u32; 11] = [0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5];

/// The bits of each coefficient of `F` in a secret key, for each `logn` from 1 to 10,
/// `max_FG_bits` of `codec.c`.
pub(crate) const largePolynomialBits: [u32; 11] = [0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];

/// The largest absolute value of a coefficient of a compressed signature.
const compressedLimit: i32 = 2047;

/// The bytes of the bits that an accumulator writes, with the last byte padded with zeros.
struct BitWriter {
    bytes: Vec<u8>,
    accumulator: u32,
    bitCount: u32,
}

impl BitWriter {
    fn new(capacity: usize) -> Self {
        BitWriter {
            bytes: Vec::with_capacity(capacity),
            accumulator: 0,
            bitCount: 0,
        }
    }

    /// Appends the low bits of a value and writes each full byte.
    fn append(&mut self, value: u32, bits: u32) {
        self.accumulator = (self.accumulator << bits) | value;
        self.bitCount += bits;
        while self.bitCount >= 8 {
            self.bitCount -= 8;
            self.bytes.push((self.accumulator >> self.bitCount) as u8);
        }
    }

    /// The bytes, with the remaining bits in a last byte.
    fn finished(mut self) -> Vec<u8> {
        if self.bitCount > 0 {
            self.bytes
                .push((self.accumulator << (8 - self.bitCount)) as u8);
        }
        self.bytes
    }
}

impl Encoding {
    /// The modular encoding of `N` values, as `modq_encode` does, or `None` when a value is
    /// not below `q`.
    pub(crate) fn modularEncoded(values: &[u16], logn: u32) -> Option<Vec<u8>> {
        let n = 1usize << logn;
        if values[..n].iter().any(|value| u32::from(*value) >= modulus) {
            return None;
        }
        let mut writer = BitWriter::new((n * 14).div_ceil(8));
        for value in &values[..n] {
            writer.append(u32::from(*value), 14);
        }
        Some(writer.finished())
    }

    /// The `N` values of a modular encoding at the start of the input, as `modq_decode` does,
    /// or `None` when the input is too short, a value is not below `q` or a padding bit is set.
    pub(crate) fn modularDecoded(input: &[u8], logn: u32) -> Option<Vec<u16>> {
        let n = 1usize << logn;
        let length = (n * 14).div_ceil(8);
        if length > input.len() {
            return None;
        }
        let mut values = Vec::with_capacity(n);
        let mut accumulator = 0u32;
        let mut bitCount = 0u32;
        let mut bytes = input.iter();
        while values.len() < n {
            accumulator = (accumulator << 8) | u32::from(*bytes.next()?);
            bitCount += 8;
            if bitCount >= 14 {
                bitCount -= 14;
                let value = (accumulator >> bitCount) & 0x3FFF;
                if value >= modulus {
                    return None;
                }
                values.push(value as u16);
            }
        }
        if accumulator & ((1u32 << bitCount) - 1) != 0 {
            return None;
        }
        Some(values)
    }

    /// The trimmed encoding of `N` signed integers in `bits` bits each, as `trim_i8_encode`
    /// does, or `None` when a value is outside `-(2^(bits - 1) - 1)..=2^(bits - 1) - 1` or the
    /// encoding is longer than `maximumLength`.
    pub(crate) fn trimmedEncoded(
        values: &[i8],
        logn: u32,
        bits: u32,
        maximumLength: usize,
    ) -> Option<Vec<u8>> {
        let n = 1usize << logn;
        let maximum = (1i32 << (bits - 1)) - 1;
        if values[..n]
            .iter()
            .any(|value| !(-maximum..=maximum).contains(&i32::from(*value)))
        {
            return None;
        }
        let length = (n * bits as usize).div_ceil(8);
        if length > maximumLength {
            return None;
        }
        let mask = (1u32 << bits) - 1;
        let mut writer = BitWriter::new(length);
        for value in &values[..n] {
            writer.append(u32::from(*value as u8) & mask, bits);
        }
        Some(writer.finished())
    }

    /// The `N` signed integers of a trimmed encoding in `bits` bits each at the start of the
    /// input, and the number of bytes that they take, as `trim_i8_decode` does, or `None` when
    /// the input is too short, a value is `-2^(bits - 1)` or a padding bit is set.
    pub(crate) fn trimmedDecoded(input: &[u8], logn: u32, bits: u32) -> Option<(Vec<i8>, usize)> {
        let n = 1usize << logn;
        let length = (n * bits as usize).div_ceil(8);
        if length > input.len() {
            return None;
        }
        let valueMask = (1u32 << bits) - 1;
        let signBit = 1u32 << (bits - 1);
        let mut values = Vec::with_capacity(n);
        let mut accumulator = 0u32;
        let mut bitCount = 0u32;
        let mut bytes = input.iter();
        while values.len() < n {
            accumulator = (accumulator << 8) | u32::from(*bytes.next()?);
            bitCount += 8;
            while bitCount >= bits && values.len() < n {
                bitCount -= bits;
                let mut value = (accumulator >> bitCount) & valueMask;
                // Sign extension, and the value -2^(bits - 1) is refused.
                value |= (value & signBit).wrapping_neg();
                if value == signBit.wrapping_neg() {
                    return None;
                }
                values.push(value as i8);
            }
        }
        if accumulator & ((1u32 << bitCount) - 1) != 0 {
            return None;
        }
        Some((values, length))
    }

    /// The compressed encoding of `N` signed integers, as `comp_encode` does, or `None` when a
    /// value is outside `-2047..=2047` or the encoding is longer than `maximumLength`.
    pub(crate) fn compressedEncoded(
        values: &[i16],
        logn: u32,
        maximumLength: usize,
    ) -> Option<Vec<u8>> {
        let n = 1usize << logn;
        if values[..n]
            .iter()
            .any(|value| !(-compressedLimit..=compressedLimit).contains(&i32::from(*value)))
        {
            return None;
        }
        let mut writer = BitWriter::new(maximumLength);
        for value in &values[..n] {
            let value = i32::from(*value);
            let magnitude = value.unsigned_abs();
            // The sign bit and the low seven bits of the absolute value.
            writer.append((u32::from(value < 0) << 7) | (magnitude & 127), 8);
            // The high bits as that many zeros and a one.
            writer.append(1, (magnitude >> 7) + 1);
            if writer.bytes.len() > maximumLength {
                return None;
            }
        }
        let bytes = writer.finished();
        (bytes.len() <= maximumLength).then_some(bytes)
    }

    /// The `N` signed integers of a compressed encoding at the start of the input, and the
    /// number of bytes that they take, as `comp_decode` does, or `None` when the input ends
    /// first, a value is above 2047 in absolute value, a value is a negative zero or a padding
    /// bit is set.
    pub(crate) fn compressedDecoded(input: &[u8], logn: u32) -> Option<(Vec<i16>, usize)> {
        let n = 1usize << logn;
        let mut values = Vec::with_capacity(n);
        let mut accumulator = 0u32;
        let mut bitCount = 0u32;
        let mut position = 0;
        let mut nextByte = || {
            let byte = *input.get(position)?;
            position += 1;
            Some(u32::from(byte))
        };
        for _ in 0..n {
            // The sign bit and the low seven bits.
            accumulator = (accumulator << 8) | nextByte()?;
            let low = accumulator >> bitCount;
            let isNegative = low & 128 != 0;
            let mut magnitude = low & 127;
            // The unary count of the high bits, which ends with a one.
            loop {
                if bitCount == 0 {
                    accumulator = (accumulator << 8) | nextByte()?;
                    bitCount = 8;
                }
                bitCount -= 1;
                if (accumulator >> bitCount) & 1 != 0 {
                    break;
                }
                magnitude += 128;
                if magnitude > compressedLimit as u32 {
                    return None;
                }
            }
            if isNegative && magnitude == 0 {
                return None;
            }
            let value = magnitude as i16;
            values.push(if isNegative { -value } else { value });
        }
        if accumulator & ((1u32 << bitCount) - 1) != 0 {
            return None;
        }
        Some((values, position))
    }
}

#[cfg(test)]
mod tests {
    use super::Encoding;

    // The known answers come from `codec.c` of the C library at degree 8.

    #[test]
    fn modularEncodingGivesTheBytesOfTheCCodeAndDecodesBack() {
        let mut values: Vec<u16> = (0..8).map(|u| ((u * 4567 + 89) % 12289) as u16).collect();
        values[7] = 12288;
        let expected = [
            0x01, 0x65, 0x23, 0x09, 0x01, 0xC5, 0xDD, 0x5E, 0xD2, 0x98, 0xB2, 0xD8, 0x70, 0x00,
        ];
        assert_eq!(
            Encoding::modularEncoded(&values, 3).as_deref(),
            Some(&expected[..])
        );
        assert_eq!(Encoding::modularDecoded(&expected, 3), Some(values.clone()));
        // Bytes after the encoding are not read.
        let mut longer = expected.to_vec();
        longer.push(0xFF);
        assert_eq!(Encoding::modularDecoded(&longer, 3), Some(values.clone()));
        values[2] = 12289;
        assert_eq!(Encoding::modularEncoded(&values, 3), None);
    }

    #[test]
    fn modularDecodingRefusesALargeValueAPaddingBitAndAShortInput() {
        // 12289 is the first value that is too large, and 12288 the last one that is not.
        assert_eq!(Encoding::modularDecoded(&[0xC0, 0x04, 0x00, 0x00], 1), None);
        assert_eq!(
            Encoding::modularDecoded(&[0xC0, 0x00, 0x00, 0x00], 1),
            Some(vec![12288, 0])
        );
        // Two values take 28 bits, so the low four bits of the fourth byte are padding.
        assert_eq!(
            Encoding::modularDecoded(&[0x00, 0x04, 0x00, 0x20], 1),
            Some(vec![1, 2])
        );
        assert_eq!(Encoding::modularDecoded(&[0x00, 0x04, 0x00, 0x21], 1), None);
        assert_eq!(Encoding::modularDecoded(&[0x00, 0x04, 0x00, 0x28], 1), None);
        assert_eq!(Encoding::modularDecoded(&[0x00, 0x04, 0x00], 1), None);
    }

    #[test]
    fn trimmedEncodingGivesTheBytesOfTheCCodeAndDecodesBack() {
        let mut small: Vec<i8> = (0..8).map(|u| ((u * 5 + 3) % 61) as i8 - 30).collect();
        small[0] = 31;
        small[1] = -31;
        let expected = [0x7E, 0x1B, 0xF4, 0xE7, 0xE0, 0xC8];
        assert_eq!(
            Encoding::trimmedEncoded(&small, 3, 6, 6).as_deref(),
            Some(&expected[..])
        );
        assert_eq!(
            Encoding::trimmedDecoded(&expected, 3, 6),
            Some((small.clone(), 6))
        );
        let large = [127i8, -127, 0, 1, -1, 64, -65, 100];
        let expected = [0x7F, 0x81, 0x00, 0x01, 0xFF, 0x40, 0xBF, 0x64];
        assert_eq!(
            Encoding::trimmedEncoded(&large, 3, 8, 8).as_deref(),
            Some(&expected[..])
        );
        assert_eq!(
            Encoding::trimmedDecoded(&expected, 3, 8),
            Some((large.to_vec(), 8))
        );
        // The output must fit.
        assert_eq!(Encoding::trimmedEncoded(&large, 3, 8, 7), None);
    }

    #[test]
    fn trimmedEncodingRefusesTheValuesOutsideItsRange() {
        // Six bits hold -31..=31: 32 and -32 are refused.
        let mut values = [0i8; 8];
        values[3] = 32;
        assert_eq!(Encoding::trimmedEncoded(&values, 3, 6, 6), None);
        values[3] = -32;
        assert_eq!(Encoding::trimmedEncoded(&values, 3, 6, 6), None);
        values[3] = -128;
        assert_eq!(Encoding::trimmedEncoded(&values, 3, 8, 8), None);
        values[3] = -127;
        assert!(Encoding::trimmedEncoded(&values, 3, 8, 8).is_some());
    }

    #[test]
    fn trimmedDecodingRefusesTheForbiddenValueAPaddingBitAndAShortInput() {
        // 100000 in six bits is -32, the forbidden value.
        assert_eq!(
            Encoding::trimmedDecoded(&[0x80, 0x00, 0x00, 0, 0, 0], 3, 6),
            None
        );
        assert_eq!(Encoding::trimmedDecoded(&[0x80, 0x00], 3, 8), None);
        // 100001 is -31.
        assert_eq!(
            Encoding::trimmedDecoded(&[0x84, 0, 0, 0, 0, 0], 3, 6).map(|(values, _)| values[0]),
            Some(-31)
        );
        // Two values of five bits leave six padding bits.
        assert_eq!(
            Encoding::trimmedDecoded(&[0x08, 0x40], 1, 5),
            Some((vec![1, 1], 2))
        );
        assert_eq!(Encoding::trimmedDecoded(&[0x08, 0x41], 1, 5), None);
        assert_eq!(Encoding::trimmedDecoded(&[0x08], 1, 5), None);
    }

    #[test]
    fn compressedEncodingGivesTheBytesOfTheCCodeAndDecodesBack() {
        let values = [0i16, 1, -1, 127, -128, 128, 2047, -2047];
        let expected = [
            0x00, 0x80, 0xE0, 0x6F, 0xF8, 0x04, 0x01, 0x7F, 0x00, 0x01, 0xFF, 0x00, 0x01,
        ];
        assert_eq!(
            Encoding::compressedEncoded(&values, 3, 64).as_deref(),
            Some(&expected[..])
        );
        assert_eq!(
            Encoding::compressedEncoded(&values, 3, 13).as_deref(),
            Some(&expected[..])
        );
        assert_eq!(Encoding::compressedEncoded(&values, 3, 12), None);
        assert_eq!(
            Encoding::compressedDecoded(&expected, 3),
            Some((values.to_vec(), 13))
        );
        let values = [5i16, -300, 1000, -7, 0, 0, 33, -1];
        let expected = [
            0x05, 0xD6, 0x16, 0x80, 0x18, 0x78, 0x04, 0x02, 0x43, 0x81, 0x80,
        ];
        assert_eq!(
            Encoding::compressedEncoded(&values, 3, 64).as_deref(),
            Some(&expected[..])
        );
        let mut padded = expected.to_vec();
        padded.extend([0, 0, 0]);
        // The decoder reports the length that it read, so the caller can check the padding.
        assert_eq!(
            Encoding::compressedDecoded(&padded, 3),
            Some((values.to_vec(), 11))
        );
    }

    #[test]
    fn compressedEncodingRefusesAValueAbove2047() {
        let mut values = [0i16; 8];
        values[5] = 2048;
        assert_eq!(Encoding::compressedEncoded(&values, 3, 64), None);
        values[5] = -2048;
        assert_eq!(Encoding::compressedEncoded(&values, 3, 64), None);
        values[5] = -2047;
        assert!(Encoding::compressedEncoded(&values, 3, 64).is_some());
    }

    #[test]
    fn compressedDecodingRefusesNegativeZeroALargeValueAPaddingBitAndAShortInput() {
        // Sign 1, low bits 0 and the stop bit: negative zero.
        assert_eq!(Encoding::compressedDecoded(&[0x80, 0x80], 1), None);
        assert_eq!(
            Encoding::compressedDecoded(&[0x00, 0x80, 0x40], 1),
            Some((vec![0, 0], 3))
        );
        // 127 and fifteen zeros is 2047, and a sixteenth zero is too large.
        assert_eq!(
            Encoding::compressedDecoded(&[0x7F, 0x00, 0x01, 0x00, 0x80], 1),
            Some((vec![2047, 0], 5))
        );
        assert_eq!(
            Encoding::compressedDecoded(&[0x7F, 0x00, 0x00, 0x80, 0x00], 1),
            None
        );
        // The padding bits after the last value must be zero.
        assert_eq!(Encoding::compressedDecoded(&[0x00, 0x80, 0x41], 1), None);
        // The input ends inside the second value.
        assert_eq!(Encoding::compressedDecoded(&[0x00, 0x80], 1), None);
        assert_eq!(Encoding::compressedDecoded(&[], 1), None);
    }
}
