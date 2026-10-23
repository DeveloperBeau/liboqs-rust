/// The reader of random bits of the samplers of `csprng_hash.h` and of
/// `expand_digest_to_fixed_weight`: a window of 64 bits over a buffer of SHAKE output.
///
/// The window starts with the first 8 bytes of the buffer, the first byte in the low bits. A
/// draw takes the low bits of the window and shifts them out. Before each draw, a window with
/// at most 32 bits left takes up to 4 more bytes of the buffer above its bits. When the buffer
/// is used up, the window runs empty and the draws give zero bits, as in the C code.
pub(crate) struct BitReader<'buffer> {
    buffer: &'buffer [u8],
    window: u64,
    /// The bits left in the window, `bits_in_sub_buf`. It falls below zero when the buffer is
    /// used up and the draws go on.
    windowBits: i32,
    /// The next byte of the buffer, `pos_in_buf`.
    position: usize,
}

impl<'buffer> BitReader<'buffer> {
    /// Makes a reader of a buffer of at least 8 bytes.
    pub(crate) fn new(buffer: &'buffer [u8]) -> Self {
        let first: [u8; 8] = buffer[..8].try_into().expect("8 bytes");
        BitReader {
            buffer,
            window: u64::from_le_bytes(first),
            windowBits: 64,
            position: 8,
        }
    }

    /// The next draw of some bits, at most 32: the refill of the window, the low bits of the
    /// window, and the shift of the window by the bits.
    pub(crate) fn draw(&mut self, bits: u32) -> u64 {
        let remaining = self.buffer.len() - self.position;
        if self.windowBits <= 32 && remaining > 0 {
            let amount = remaining.min(4);
            let refresh = self.buffer[self.position..self.position + amount]
                .iter()
                .rev()
                .fold(0u32, |word, byte| (word << 8) | u32::from(*byte));
            self.position += amount;
            self.window |= u64::from(refresh) << self.windowBits;
            self.windowBits += 8 * amount as i32;
        }
        let value = self.window & ((1 << bits) - 1);
        self.window >>= bits;
        self.windowBits -= bits as i32;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::BitReader;

    #[test]
    fn drawsTakeTheBitsOfTheBufferFromTheLowEnd() {
        let buffer = [0xB4, 0x01, 0, 0, 0, 0, 0, 0x80, 0x0F];
        let mut reader = BitReader::new(&buffer);
        // 0xB4 is 1011 0100: 3 bits give 100, then 110, then 10 with the low bit of 0x01.
        assert_eq!(reader.draw(3), 0b100);
        assert_eq!(reader.draw(3), 0b110);
        assert_eq!(reader.draw(3), 0b110);
        assert_eq!(reader.draw(7), 0);
        // 16 bits are left, with the top bit of byte 7 at the top.
        assert_eq!(reader.draw(32), 0);
        assert_eq!(reader.windowBits, 16);
        // The window held at most 32 bits, so the draw first took the last byte above them.
        assert_eq!(reader.draw(16), 0x8000);
        assert_eq!(reader.draw(4), 0x0F);
    }

    #[test]
    fn theWindowTakesFourBytesWhenAtMost32BitsAreLeft() {
        let buffer: Vec<u8> = (1..=16).collect();
        let mut reader = BitReader::new(&buffer);
        // 33 bits left after the first draw: no refill before the second draw.
        assert_eq!(reader.draw(31), 0x0403_0201 & 0x7FFF_FFFF);
        assert_eq!(reader.windowBits, 33);
        reader.draw(1);
        assert_eq!(reader.position, 8);
        // 32 bits left: the next draw first takes bytes 8 to 11 above them.
        assert_eq!(reader.windowBits, 32);
        assert_eq!(reader.draw(32), 0x0807_0605);
        assert_eq!(reader.position, 12);
        assert_eq!(reader.draw(32), 0x0C0B_0A09);
    }

    #[test]
    fn aShortLastRefillTakesTheRemainingBytes() {
        let buffer: Vec<u8> = (1..=10).collect();
        let mut reader = BitReader::new(&buffer);
        assert_eq!(reader.draw(32), 0x0403_0201);
        // Two bytes remain, and the refill takes both.
        assert_eq!(reader.draw(32), 0x0807_0605);
        assert_eq!(reader.windowBits, 16);
        assert_eq!(reader.draw(16), 0x0A09);
    }

    #[test]
    fn aUsedUpBufferGivesZeroBits() {
        let buffer = [0xFF; 9];
        let mut reader = BitReader::new(&buffer);
        for _ in 0..10 {
            assert_eq!(reader.draw(7), 0x7F);
        }
        // 72 bits were in the buffer, and 70 are drawn. The next draw gives the last two ones.
        assert_eq!(reader.draw(7), 0b11);
        for _ in 0..5 {
            assert_eq!(reader.draw(9), 0);
        }
        assert!(reader.windowBits < 0);
    }
}
