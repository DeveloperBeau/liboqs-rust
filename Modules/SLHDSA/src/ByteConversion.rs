/// The conversions between byte strings and integers of FIPS 205, Section 4.4.
pub(crate) struct ByteConversion;

impl ByteConversion {
    /// `toInt(X, n)` of FIPS 205, Algorithm 2: the big-endian integer of at most 8 bytes.
    pub(crate) fn toInteger(bytes: &[u8]) -> u64 {
        debug_assert!(bytes.len() <= 8);
        bytes
            .iter()
            .fold(0u64, |total, byte| (total << 8) + u64::from(*byte))
    }

    /// `toByte(x, n)` of FIPS 205, Algorithm 3: the big-endian bytes of the low bits of an
    /// integer, as many as the output holds.
    pub(crate) fn toBytes(value: u32, output: &mut [u8]) {
        let mut remaining = value;
        for byte in output.iter_mut().rev() {
            *byte = remaining as u8;
            remaining >>= 8;
        }
    }

    /// `base_2b(X, b, out_len)` of FIPS 205, Algorithm 4: the digits of `b` bits of a byte
    /// string, from the high bit of the first byte, one digit for each place of the output.
    pub(crate) fn base2b(input: &[u8], bits: u32, output: &mut [u32]) {
        let mask = (1u32 << bits) - 1;
        let mut position = 0;
        let mut total = 0u32;
        let mut bitCount = 0;
        for digit in output.iter_mut() {
            while bitCount < bits {
                // The high bits leave the 32-bit total, as in the C code. A digit needs at most
                // 14 bits, so they are never read.
                total = (total << 8) + u32::from(input[position]);
                position += 1;
                bitCount += 8;
            }
            bitCount -= bits;
            *digit = (total >> bitCount) & mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ByteConversion;

    #[test]
    fn toIntegerReadsBigEndianBytes() {
        assert_eq!(ByteConversion::toInteger(&[]), 0);
        assert_eq!(ByteConversion::toInteger(&[0x12]), 0x12);
        assert_eq!(ByteConversion::toInteger(&[0x01, 0x02, 0x03]), 0x010203);
        assert_eq!(
            ByteConversion::toInteger(&[0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88]),
            0xFFEE_DDCC_BBAA_9988
        );
    }

    #[test]
    fn toBytesWritesTheLowBytesBigEndian() {
        let mut output = [0xAAu8; 2];
        ByteConversion::toBytes(0x1E00, &mut output);
        assert_eq!(output, [0x1E, 0x00]);
        let mut long = [0u8; 4];
        ByteConversion::toBytes(0x0102_0304, &mut long);
        assert_eq!(long, [1, 2, 3, 4]);
        let mut short = [0u8; 1];
        ByteConversion::toBytes(0x0102, &mut short);
        assert_eq!(short, [2]);
    }

    #[test]
    fn base2bSplitsBitsFromTheHighBitOfTheFirstByte() {
        // Digits of 4 bits, as WOTS+ reads a message.
        let mut nibbles = [0u32; 4];
        ByteConversion::base2b(&[0x12, 0x34], 4, &mut nibbles);
        assert_eq!(nibbles, [1, 2, 3, 4]);
        // Digits of 12 bits, as FORS reads the digest of SLH-DSA-SHA2-128s: 0xABC and 0xDEF,
        // and then 0x123 from the next bytes.
        let mut wide = [0u32; 3];
        ByteConversion::base2b(&[0xAB, 0xCD, 0xEF, 0x12, 0x30], 12, &mut wide);
        assert_eq!(wide, [0xABC, 0xDEF, 0x123]);
        // Digits of 6 bits across bytes: 0b101010 and 0b111100 from 0xAB 0xC0.
        let mut six = [0u32; 2];
        ByteConversion::base2b(&[0xAB, 0xC0], 6, &mut six);
        assert_eq!(six, [0b101010, 0b111100]);
        // Digits of 14 bits, the widest of the sets.
        let mut fourteen = [0u32; 2];
        ByteConversion::base2b(&[0xFF, 0xFC, 0x00, 0x07], 14, &mut fourteen);
        assert_eq!(fourteen, [0x3FFF, 0x0000]);
    }

    #[test]
    fn base2bReadsOnlyTheBytesItNeeds() {
        // Three digits of 9 bits need 27 bits, so 4 bytes, and the fifth byte is not read.
        let mut digits = [0u32; 3];
        ByteConversion::base2b(&[0xFF, 0x80, 0x00, 0x01], 9, &mut digits);
        assert_eq!(digits, [0x1FF, 0x000, 0x000]);
    }
}
