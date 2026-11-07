use alloc::vec;
use alloc::vec::Vec;

/// The mixed-radix encoding of `sntrup761.c`, `Encode` and `Decode`: a list of values, each
/// below its own range of at most `2^14`, as few bytes as the ranges allow.
///
/// Each step merges two neighbors into one value of the product of their ranges and writes the
/// low bytes while the range is at least `2^14`. The ranges are public, so the number of bytes
/// does not depend on the values. Decoding reads the same bytes in the same order, and each
/// value it gives is below its range for any input bytes.
pub(crate) struct RadixEncoding;

impl RadixEncoding {
    /// The quotient and the remainder of a 32-bit value by a divisor below `2^14`, with no
    /// division instruction, `uint32_divmod_uint14`.
    pub(crate) fn quotientAndRemainder(value: u32, divisor: u16) -> (u32, u16) {
        let divisor32 = u32::from(divisor);
        let reciprocal = 0x8000_0000 / divisor32;
        let mut value = value;
        let mut part = ((u64::from(value) * u64::from(reciprocal)) >> 31) as u32;
        value = value.wrapping_sub(part.wrapping_mul(divisor32));
        let mut quotient = part;
        part = ((u64::from(value) * u64::from(reciprocal)) >> 31) as u32;
        value = value.wrapping_sub(part.wrapping_mul(divisor32));
        quotient = quotient.wrapping_add(part);
        value = value.wrapping_sub(divisor32);
        quotient = quotient.wrapping_add(1);
        // The last subtraction went below zero exactly when the remainder was already below
        // the divisor, and then the mask adds the divisor back.
        let mask = ((value as i32) >> 31) as u32;
        value = value.wrapping_add(mask & divisor32);
        quotient = quotient.wrapping_add(mask);
        (quotient, value as u16)
    }

    /// The bytes of values below their ranges, `Encode`.
    pub(crate) fn encoded(values: &[u16], ranges: &[u16]) -> Vec<u8> {
        let mut output = Vec::new();
        Self::encode(&mut output, values, ranges);
        output
    }

    fn encode(output: &mut Vec<u8>, values: &[u16], ranges: &[u16]) {
        let length = values.len();
        if length == 1 {
            let mut value = values[0];
            let mut range = ranges[0];
            while range > 1 {
                output.push(value as u8);
                value >>= 8;
                range = ((u32::from(range) + 255) >> 8) as u16;
            }
        }
        if length > 1 {
            let half = length.div_ceil(2);
            let mut mergedValues = vec![0u16; half];
            let mut mergedRanges = vec![0u16; half];
            let mut index = 0;
            while index + 1 < length {
                let firstRange = u32::from(ranges[index]);
                let mut value =
                    u32::from(values[index]) + u32::from(values[index + 1]) * firstRange;
                let mut range = u32::from(ranges[index + 1]) * firstRange;
                while range >= 16384 {
                    output.push(value as u8);
                    value >>= 8;
                    range = (range + 255) >> 8;
                }
                mergedValues[index / 2] = value as u16;
                mergedRanges[index / 2] = range as u16;
                index += 2;
            }
            if index < length {
                mergedValues[index / 2] = values[index];
                mergedRanges[index / 2] = ranges[index];
            }
            Self::encode(output, &mergedValues, &mergedRanges);
        }
    }

    /// The values of the bytes of an encoding with the ranges, `Decode`. The input has the
    /// number of bytes of the ranges.
    pub(crate) fn decoded(input: &[u8], ranges: &[u16]) -> Vec<u16> {
        let mut values = vec![0u16; ranges.len()];
        let mut position = 0;
        Self::decode(&mut values, input, &mut position, ranges);
        values
    }

    fn decode(output: &mut [u16], input: &[u8], position: &mut usize, ranges: &[u16]) {
        let length = ranges.len();
        if length == 1 {
            let range = ranges[0];
            output[0] = if range == 1 {
                0
            } else if range <= 256 {
                Self::quotientAndRemainder(u32::from(input[*position]), range).1
            } else {
                let value = u32::from(input[*position]) + (u32::from(input[*position + 1]) << 8);
                Self::quotientAndRemainder(value, range).1
            };
        }
        if length > 1 {
            let half = length.div_ceil(2);
            let mut mergedRanges = vec![0u16; half];
            let mut bottomValues = vec![0u32; length / 2];
            let mut bottomScales = vec![0u32; length / 2];
            let mut index = 0;
            while index + 1 < length {
                let range = u32::from(ranges[index]) * u32::from(ranges[index + 1]);
                if range > 256 * 16383 {
                    bottomScales[index / 2] = 256 * 256;
                    bottomValues[index / 2] =
                        u32::from(input[*position]) + 256 * u32::from(input[*position + 1]);
                    *position += 2;
                    mergedRanges[index / 2] = ((((range + 255) >> 8) + 255) >> 8) as u16;
                } else if range >= 16384 {
                    bottomScales[index / 2] = 256;
                    bottomValues[index / 2] = u32::from(input[*position]);
                    *position += 1;
                    mergedRanges[index / 2] = ((range + 255) >> 8) as u16;
                } else {
                    bottomScales[index / 2] = 1;
                    bottomValues[index / 2] = 0;
                    mergedRanges[index / 2] = range as u16;
                }
                index += 2;
            }
            if index < length {
                mergedRanges[index / 2] = ranges[index];
            }
            let mut merged = vec![0u16; half];
            Self::decode(&mut merged, input, position, &mergedRanges);
            let mut index = 0;
            while index + 1 < length {
                let value = bottomValues[index / 2]
                    + bottomScales[index / 2] * u32::from(merged[index / 2]);
                let (quotient, remainder) = Self::quotientAndRemainder(value, ranges[index]);
                output[index] = remainder;
                output[index + 1] = Self::quotientAndRemainder(quotient, ranges[index + 1]).1;
                index += 2;
            }
            if index < length {
                output[index] = merged[index / 2];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RadixEncoding;
    use crate::testInputs::sequence;

    #[test]
    fn quotientAndRemainderAreExactForEveryDivisorBelowTwoToTheFourteen() {
        let values = sequence(400, 3);
        for divisor in (1..16384u16).step_by(7).chain([1, 2, 3, 1531, 4591, 16383]) {
            for pair in values.chunks_exact(2) {
                let value = (u32::from(pair[0]) << 16) + u32::from(pair[1]);
                for value in [value, value >> 13, u32::MAX - value] {
                    assert_eq!(
                        RadixEncoding::quotientAndRemainder(value, divisor),
                        (
                            value / u32::from(divisor),
                            (value % u32::from(divisor)) as u16
                        ),
                        "{value} / {divisor}"
                    );
                }
            }
        }
    }

    #[test]
    fn theRangesOfSntrup761GiveTheLengthsOfItsKeysAndCiphertexts() {
        // 761 values below q = 4591 give the 1158 bytes of a public key, and 761 values below
        // (q + 2) / 3 = 1531 the 1007 bytes of a rounded polynomial.
        let zeros = vec![0u16; 761];
        assert_eq!(RadixEncoding::encoded(&zeros, &vec![4591; 761]).len(), 1158);
        assert_eq!(RadixEncoding::encoded(&zeros, &vec![1531; 761]).len(), 1007);
    }

    #[test]
    fn decodingGivesBackTheEncodedValues() {
        for (length, range) in [(761, 4591u16), (761, 1531), (1, 4591), (2, 300), (5, 2)] {
            let ranges = vec![range; length];
            let values: Vec<u16> = sequence(length, length as u32)
                .iter()
                .map(|value| value % range)
                .collect();
            let bytes = RadixEncoding::encoded(&values, &ranges);
            assert_eq!(
                RadixEncoding::decoded(&bytes, &ranges),
                values,
                "{length} values below {range}"
            );
        }
        // The largest values, and mixed ranges with a range of 1.
        let ranges = [4591u16, 1, 256, 257, 16383, 2, 9];
        let largest: Vec<u16> = ranges.iter().map(|range| range - 1).collect();
        let bytes = RadixEncoding::encoded(&largest, &ranges);
        assert_eq!(RadixEncoding::decoded(&bytes, &ranges), largest);
    }

    #[test]
    fn decodingReadsTheBytesOfEncodeAtEachThresholdOfTheRanges() {
        // Encode of sntrup761.c of liboqs 0.16.0. Decode reads one byte for a pair whose ranges
        // multiply to 16384 up to 256 * 16383, and two bytes for a larger product, whose
        // merged range it rounds up twice. The ranges 256 and 16383 give the largest product
        // of one byte, and the pair after them reads from the next byte. The ranges 257 and
        // 16321 give 4194497, whose first rounding is 16385, one more than a multiple of 256,
        // so the merged range is 65, and the largest values give the merged value 64. The
        // ranges of sntrup761 reach neither threshold.
        let cases: [(&[u16], &[u16], &[u8]); 3] = [
            (
                &[256, 16383, 256, 16383],
                &[255, 16382, 17, 9000],
                &[0xFF, 0x11, 0xD6, 0x1C, 0xCA, 0x08],
            ),
            (&[257, 16321], &[256, 16320], &[0xC0, 0x00, 0x40]),
            (
                &[256, 16383, 257, 16321],
                &[255, 16382, 256, 16320],
                &[0xFF, 0xC0, 0x00, 0xBE, 0x3F, 0x10],
            ),
        ];
        for (ranges, values, bytes) in cases {
            assert_eq!(RadixEncoding::encoded(values, ranges), bytes, "{ranges:?}");
            assert_eq!(RadixEncoding::decoded(bytes, ranges), values, "{ranges:?}");
        }
    }

    #[test]
    fn anyBytesDecodeToValuesBelowTheirRanges() {
        for seed in 0..20 {
            let bytes: Vec<u8> = sequence(1158, seed)
                .iter()
                .map(|value| *value as u8)
                .collect();
            let values = RadixEncoding::decoded(&bytes, &vec![4591; 761]);
            assert!(values.iter().all(|value| *value < 4591), "seed {seed}");
        }
        let ones = vec![0xFFu8; 1007];
        let values = RadixEncoding::decoded(&ones, &vec![1531; 761]);
        assert!(values.iter().all(|value| *value < 1531));
    }
}
