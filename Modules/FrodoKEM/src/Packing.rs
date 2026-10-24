use alloc::vec::Vec;

/// The conversions between bytes and the 16-bit values of FrodoKEM.
///
/// The packing of values of `D` bits is `frodo_pack` and `frodo_unpack` of liboqs `util.c`: the
/// bits form one stream, from the high bit of each value, and fill each byte from its high bit.
/// The secret matrix of a secret key and the hash output of the noise matrices hold each value
/// in two bytes, low byte first.
pub(crate) struct Packing;

impl Packing {
    /// Writes the low `bits` bits of each value into the output, as `frodo_pack` does. The
    /// output has exactly the bytes of the values.
    pub(crate) fn pack(values: &[u16], bits: u32, output: &mut [u8]) {
        debug_assert_eq!(output.len() * 8, values.len() * bits as usize);
        let valueMask = (1u32 << bits) - 1;
        // The bits that wait for a byte, below 8 between two values.
        let mut pending = 0u32;
        let mut pendingCount = 0u32;
        let mut position = 0;
        for value in values {
            pending = (pending << bits) + (u32::from(*value) & valueMask);
            pendingCount += bits;
            while pendingCount >= 8 {
                pendingCount -= 8;
                output[position] = (pending >> pendingCount) as u8;
                position += 1;
                pending &= (1 << pendingCount) - 1;
            }
        }
    }

    /// The values of `bits` bits of a byte stream, as `frodo_unpack` reads them. The stream
    /// holds a whole number of values.
    pub(crate) fn unpacked(input: &[u8], bits: u32) -> Vec<u16> {
        debug_assert_eq!(input.len() * 8 % bits as usize, 0);
        let mut values = Vec::new();
        let mut pending = 0u32;
        let mut pendingCount = 0u32;
        for byte in input {
            pending = (pending << 8) + u32::from(*byte);
            pendingCount += 8;
            while pendingCount >= bits {
                pendingCount -= bits;
                values.push((pending >> pendingCount) as u16);
                pending &= (1 << pendingCount) - 1;
            }
        }
        values
    }

    /// Reads each pair of bytes as one value, low byte first, as `LE_TO_UINT16` of liboqs reads
    /// the output of a hash and the secret matrix of a secret key.
    pub(crate) fn decodeLittleEndian(bytes: &[u8], values: &mut [u16]) {
        debug_assert_eq!(bytes.len(), 2 * values.len());
        for (value, pair) in values.iter_mut().zip(bytes.chunks_exact(2)) {
            *value = u16::from_le_bytes([pair[0], pair[1]]);
        }
    }

    /// The bytes of the values, two for each value, low byte first, as the secret key holds the
    /// secret matrix.
    pub(crate) fn littleEndianBytes(values: &[u16]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Packing;
    use crate::testInputs::{digest, sequence};

    #[test]
    fn packingWritesTheHighBitOfEachValueFirst() {
        // The 15-bit values 0x7FFF, 0, 0x4001 and 1 give the stream of 15 ones, 15 zeros,
        // 100 0000 0000 0001 and 000 0000 0000 0001.
        let values = [0x7FFFu16, 0x0000, 0x4001, 0x0001, 0, 0, 0, 0];
        let mut bytes = [0u8; 15];
        Packing::pack(&values, 15, &mut bytes);
        assert_eq!(
            &bytes[..8],
            &[0xFF, 0xFE, 0x00, 0x02, 0x00, 0x08, 0x00, 0x10]
        );
        assert!(bytes[8..].iter().all(|byte| *byte == 0));
        assert_eq!(Packing::unpacked(&bytes, 15), values.to_vec());
        // 16-bit values are big-endian pairs of bytes.
        let mut bytes = [0u8; 4];
        Packing::pack(&[0x1234, 0xABCD], 16, &mut bytes);
        assert_eq!(bytes, [0x12, 0x34, 0xAB, 0xCD]);
        assert_eq!(Packing::unpacked(&bytes, 16), vec![0x1234, 0xABCD]);
    }

    #[test]
    fn packingKeepsOnlyTheLowBitsOfEachValue() {
        // The top bit of a 16-bit value does not enter a 15-bit packing.
        let mut high = [0u8; 15];
        Packing::pack(&[0xFFFF; 8], 15, &mut high);
        let mut low = [0u8; 15];
        Packing::pack(&[0x7FFF; 8], 15, &mut low);
        assert_eq!(high, low);
        assert_eq!(high, [0xFF; 15]);
    }

    #[test]
    fn packingAndUnpackingGiveTheBytesAndValuesOfTheCCode() {
        // The digests of `frodo_pack` and `frodo_unpack` of liboqs 0.16.0 on the same inputs.
        for (dimension, bits, packDigest, unpackDigest, firstValues) in [
            (
                640usize,
                15u32,
                "b2aaad580fbb51030ffdb39a19bf02e7340bf597de557a59944d6ce56deb2aa9",
                "e86bf7a08eb1896d9f819f430fb111f247b62ee7039cbb4f843e4e70e61ad688",
                [389u16, 1094, 996, 25299],
            ),
            (
                976,
                16,
                "dcaa416086c9a429ad0afb09d1e01dccdf760be751006cf02a27fceae538b0e2",
                "7eaeb579db4bf192cc24a635fed280b0e551b44602d18a460aa3711855becd26",
                [778, 4376, 7974, 11572],
            ),
            (
                1344,
                16,
                "e7c32d1d1a039429a6cb264265e037cb11b92d911c242b607dc800026df98ff0",
                "80a58cf5cfae370c3bc65db4476f3c150d3115fd13766da5a2647d02e61fd713",
                [778, 4376, 7974, 11572],
            ),
        ] {
            let byteCount = bits as usize * dimension;
            let mut packed = vec![0u8; byteCount];
            Packing::pack(&sequence(dimension * 8, 14), bits, &mut packed);
            assert_eq!(digest(&packed), packDigest, "{dimension}");
            let stream: Vec<u8> = (0..byteCount).map(|index| (index * 7 + 3) as u8).collect();
            let values = Packing::unpacked(&stream, bits);
            assert_eq!(values.len(), dimension * 8);
            assert_eq!(&values[..4], &firstValues, "{dimension}");
            assert_eq!(
                digest(&Packing::littleEndianBytes(&values)),
                unpackDigest,
                "{dimension}"
            );
        }
    }

    #[test]
    fn unpackingAndPackingAreInverse() {
        for bits in [15u32, 16] {
            let values: Vec<u16> = sequence(64, bits)
                .iter()
                .map(|value| value & ((1u32 << bits) - 1) as u16)
                .collect();
            let mut bytes = vec![0u8; 8 * bits as usize];
            Packing::pack(&values, bits, &mut bytes);
            assert_eq!(Packing::unpacked(&bytes, bits), values, "{bits}");
        }
    }

    #[test]
    fn littleEndianFormPutsTheLowByteFirst() {
        assert_eq!(
            Packing::littleEndianBytes(&[0x1234, 0xFF01]),
            vec![0x34, 0x12, 0x01, 0xFF]
        );
        let mut values = [0u16; 2];
        Packing::decodeLittleEndian(&[0x34, 0x12, 0x01, 0xFF], &mut values);
        assert_eq!(values, [0x1234, 0xFF01]);
    }
}
