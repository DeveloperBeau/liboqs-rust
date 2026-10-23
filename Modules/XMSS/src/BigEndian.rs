/// The big-endian integers of `utils.c`, `ull_to_bytes` and `bytes_to_ull`.
pub(crate) struct BigEndian;

impl BigEndian {
    /// Writes a value into a buffer, most significant byte first, as `ull_to_bytes` does. A
    /// buffer longer than 8 bytes gets zero bytes in front, and a shorter one keeps the low
    /// bytes of the value.
    pub(crate) fn write(value: u64, output: &mut [u8]) {
        let mut rest = value;
        for byte in output.iter_mut().rev() {
            *byte = rest as u8;
            rest >>= 8;
        }
    }

    /// The value of at most 8 bytes, most significant byte first, as `bytes_to_ull` reads it.
    pub(crate) fn read(input: &[u8]) -> u64 {
        // Each byte goes into the 8 bits that the shift cleared, so `+` joins them.
        input
            .iter()
            .fold(0, |value, byte| (value << 8) + u64::from(*byte))
    }
}

#[cfg(test)]
mod tests {
    use super::BigEndian;

    #[test]
    fn writeGivesTheMostSignificantByteFirstAndZerosInFront() {
        let mut four = [0xAAu8; 4];
        BigEndian::write(0x0102_0304, &mut four);
        assert_eq!(four, [1, 2, 3, 4]);
        // A 32-byte buffer, as the index input of the PRF of a signature.
        let mut long = [0xAAu8; 32];
        BigEndian::write(0x0102_0304_0506_0708, &mut long);
        assert_eq!(&long[..24], &[0u8; 24]);
        assert_eq!(&long[24..], &[1, 2, 3, 4, 5, 6, 7, 8]);
        // A short buffer keeps the low bytes, as a 4-byte counter of a BDS state does.
        let mut short = [0u8; 2];
        BigEndian::write(0x0102_0304, &mut short);
        assert_eq!(short, [3, 4]);
    }

    #[test]
    fn readIsTheInverseOfWriteForEachLength() {
        assert_eq!(BigEndian::read(&[1, 2, 3, 4]), 0x0102_0304);
        assert_eq!(BigEndian::read(&[0xFF; 8]), u64::MAX);
        assert_eq!(BigEndian::read(&[]), 0);
        assert_eq!(BigEndian::read(&[0x80, 0, 0, 0, 0]), 0x80_0000_0000);
        for length in 1..=8 {
            let value = 0x8877_6655_4433_2211u64 >> (64 - 8 * length);
            let mut bytes = [0u8; 8];
            BigEndian::write(value, &mut bytes[..length]);
            assert_eq!(BigEndian::read(&bytes[..length]), value, "{length} bytes");
        }
    }
}
