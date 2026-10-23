use alloc::vec::Vec;

/// The bit packing of `pack_unpack.c`: field elements in 7 or 9 bits and exponents in 3 or 7
/// bits, the first value in the low bits of the first byte.
///
/// The packing functions of the C code write each group of 8 values to whole bytes and then
/// the remaining values, which is the plain packing of the bits from the low end. The unpacking
/// functions also check that the bits after the last value are zero, each in its own way.
pub(crate) struct Packing;

impl Packing {
    /// Packs values of some bits into an output of `DENSELY_PACKED` length, as
    /// `generic_pack_3_bit`, `generic_pack_7_bit` and `generic_pack_9_bit` do. Each value must
    /// fit its bits, as every value that the scheme packs does.
    pub(crate) fn pack(values: impl Iterator<Item = u32>, bits: u32, output: &mut [u8]) {
        output.fill(0);
        for (index, value) in values.enumerate() {
            let position = index * bits as usize;
            let mut shifted = value << (position % 8);
            let mut byte = position / 8;
            while shifted != 0 {
                output[byte] |= shifted as u8;
                shifted >>= 8;
                byte += 1;
            }
        }
    }

    /// The value of some bits at an index of a packed input, with the bits above it cleared, as
    /// the unpacking functions read it.
    fn value(input: &[u8], index: usize, bits: u32) -> u32 {
        let position = index * bits as usize;
        let byte = position / 8;
        let mut window = u32::from(input[byte]);
        if let Some(next) = input.get(byte + 1) {
            window |= u32::from(*next) << 8;
        }
        (window >> (position % 8)) & ((1 << bits) - 1)
    }

    /// The padding check at the end of an unpacking function of the C code: the last byte of
    /// the input under a mask of the bits after the last value.
    ///
    /// The mask of `generic_unpack_3_bit` is `0xFF << (n * 3) & 0x7`. The shift binds before the
    /// and, so the mask is zero and the check of the 3-bit vectors of RSDP accepts any padding.
    /// The 7-bit and 9-bit checks refuse a set bit after the last value.
    fn isPaddingAccepted(input: &[u8], count: usize, bits: u32) -> bool {
        let remainder = (count % 8) as u32;
        if remainder == 0 {
            return true;
        }
        let mask: u32 = match bits {
            3 => (0xFF << (remainder * 3)) & 0x7,
            7 => 0xFF << (8 - remainder),
            _ => 0xFF << remainder,
        };
        u32::from(input[input.len() - 1]) & mask == 0
    }

    /// Unpacks a count of values of some bits, as `generic_unpack_3_bit`, `generic_unpack_7_bit`
    /// and `generic_unpack_9_bit` do: the values, and false when the padding check of the C
    /// code refuses the input. The values are not reduced.
    pub(crate) fn unpacked(input: &[u8], count: usize, bits: u32) -> (Vec<u32>, bool) {
        let values = (0..count)
            .map(|index| Self::value(input, index, bits))
            .collect();
        (values, Self::isPaddingAccepted(input, count, bits))
    }
}

#[cfg(test)]
mod tests {
    use super::Packing;
    use crate::parameters::allSets;
    use crate::testInputs::{SeededSequence, shortDigest, wordsDigest};

    /// The known answers of one code: the digests of the three packed vectors, then the digest
    /// and the padding flag of each of the three unpacked vectors.
    type CodeAnswers = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        bool,
        &'static str,
        bool,
        &'static str,
        bool,
    );

    fn packed(values: &[u32], bits: u32, length: usize) -> Vec<u8> {
        let mut output = vec![0xA5; length];
        Packing::pack(values.iter().copied(), bits, &mut output);
        output
    }

    #[test]
    fn packingPlacesEachValueAfterTheBitsOfTheOneBefore() {
        // 3 bits: 1, 2, 3 give 001 010 011 from the low end, 0b011_010_001 in two bytes.
        assert_eq!(packed(&[1, 2, 3], 3, 2), vec![0b1101_0001, 0b0000_0000]);
        assert_eq!(packed(&[1, 2, 3, 7, 7, 7], 3, 3), vec![0xD1, 0xFE, 0x03]);
        // 7 bits: 127 then 1 fill the first byte and start the second.
        assert_eq!(packed(&[127, 1], 7, 2), vec![0xFF, 0x00]);
        assert_eq!(packed(&[127, 3], 7, 2), vec![0xFF, 0x01]);
        // 9 bits: 0x1FF then 0x100.
        assert_eq!(packed(&[0x1FF, 0x100], 9, 3), vec![0xFF, 0x01, 0x02]);
        // The output is cleared before the values, as the C functions clear it.
        assert_eq!(packed(&[0, 0], 9, 3), vec![0, 0, 0]);
    }

    #[test]
    fn packingAndUnpackingGiveTheBytesOfTheCFunctions() {
        // `pack_fp_vec`, `pack_fp_syn`, `pack_fz_vec` or `pack_fz_rsdp_g_vec`, and the unpacking
        // functions of the oracle library, for one set of each code. The packed values follow
        // the sequence of seed 1, and the unpacked bytes the sequence of seed 2. Each row gives
        // the digests of the three packed vectors, then the digests and the padding flags of
        // the three unpacked vectors.
        let expected: [CodeAnswers; 6] = [
            (
                "a2656fc3efb3fc285b9e48c159fd33b0",
                "982a1bf5e092dd2148f77e57f239564e",
                "5c30d43d04b8b312a51cbf3df6590615",
                "07857efb2753dd794800bbe010454c72",
                false,
                "92a8088ee5defb47ed8ef084a295ffa3",
                false,
                "6e1b84e65c4a3fc5d1c7aebec15b42bc",
                true,
            ),
            (
                "e8823556549e02369241640f025dc16e",
                "9ab188a3734862dad599893a9509db69",
                "ac41def69e3c714dfa61d19d43b8b3dc",
                "363301e5424ba811c29124076c7e01f9",
                false,
                "03f7b5f5553fe9061713dc2914694635",
                false,
                "529ed725828a4176c30e0493db20ad1c",
                true,
            ),
            (
                "6ac72945ca069fee9f261f5f576d2103",
                "a5a791540c8af38af20c1ed6fceece67",
                "1546f4826e7466ddbaa6fb7993a6cb45",
                "fb2ac26f54124a33d40b415632fbdaa7",
                false,
                "29f886e229a6184b446fdb68f7f64c67",
                false,
                "6873460c93e880ed8dca05a59212806b",
                true,
            ),
            (
                "ca03f8376b7c22e38479a04d7f9cef60",
                "2f9520ab109b66cfa792e556ec554521",
                "53b07783ec4411e7d922ea16487927d8",
                "a552990829d3686e9edf54725d552417",
                true,
                "e3848926b4a90b643d1e7b9f3b5b92bf",
                false,
                "d50d822b42259f8de5464d8c9d2d0bdc",
                false,
            ),
            (
                "4fd69d8e5aa349dae9a61483f88a6d61",
                "1fe0e1b5fa2890d6d61f3ddbca2c6914",
                "80bb2a5a547c1ae1bd778789e140a47e",
                "1e009f4b47b42213907b9ab241b4760c",
                false,
                "7890198ddcbccd9620e3df76c9f38095",
                false,
                "567ba90407bcbc61d45bd4fc351d27c9",
                true,
            ),
            (
                "e93bcb35a7f561ed7725d7e91261360b",
                "f80c125850b0eb6cd661064870f60208",
                "c64b248fefce1f356d83e216f8492199",
                "e3b80e2ae96a41ec08c4e98a46fae1c3",
                false,
                "632bf5c700f710df0e075159d6c5706a",
                false,
                "4aecc334dc04580a6fff040e431a61c5",
                true,
            ),
        ];
        for (parameters, row) in [0, 3, 6, 9, 12, 15]
            .map(|index| allSets[index])
            .iter()
            .zip(expected)
        {
            let name = parameters.description.name;
            let problem = parameters.problem();
            let fieldBits = problem.fieldBits();
            let restrictedBits = problem.restrictedBits();
            let length = parameters.code.length;
            let syndromeCount = length - parameters.code.dimension;
            let restrictedCount = parameters.restrictedExponentCount();
            let lengths = [
                parameters.fieldVectorLength(),
                parameters.syndromeLength(),
                parameters.restrictedVectorLength(),
            ];
            let mut sequence = SeededSequence::new(1);
            let vector = sequence.values(length, 1 << fieldBits);
            let syndrome = sequence.values(syndromeCount, 1 << fieldBits);
            let restricted = sequence.values(restrictedCount, 1 << restrictedBits);
            assert_eq!(
                shortDigest(&packed(&vector, fieldBits, lengths[0])),
                row.0,
                "{name}"
            );
            assert_eq!(
                shortDigest(&packed(&syndrome, fieldBits, lengths[1])),
                row.1,
                "{name}"
            );
            assert_eq!(
                shortDigest(&packed(&restricted, restrictedBits, lengths[2])),
                row.2,
                "{name}"
            );
            let mut sequence = SeededSequence::new(2);
            let unpackedRows = [
                (lengths[0], length, fieldBits, row.3, row.4),
                (lengths[1], syndromeCount, fieldBits, row.5, row.6),
                (lengths[2], restrictedCount, restrictedBits, row.7, row.8),
            ];
            for (byteCount, count, bits, digest, isAccepted) in unpackedRows {
                let bytes = sequence.bytes(byteCount);
                let (values, flag) = Packing::unpacked(&bytes, count, bits);
                assert_eq!(wordsDigest(values.into_iter()), digest, "{name}");
                assert_eq!(flag, isAccepted, "{name}");
            }
        }
    }

    #[test]
    fn unpackingInvertsPacking() {
        for (count, bits) in [
            (13, 7),
            (11, 3),
            (10, 9),
            (7, 7),
            (19, 9),
            (25, 7),
            (127, 3),
        ] {
            let values = SeededSequence::new(7).values(count, 1 << bits);
            let length = (count * bits as usize).div_ceil(8);
            let bytes = packed(&values, bits, length);
            assert_eq!(Packing::unpacked(&bytes, count, bits), (values, true));
        }
    }

    #[test]
    fn theSevenAndNineBitChecksRefuseEachPaddingBit() {
        for (count, bits) in [(13, 7), (51, 7), (127, 7), (19, 9), (55, 9), (106, 9)] {
            let values = SeededSequence::new(9).values(count, 1 << bits);
            let length = (count * bits as usize).div_ceil(8);
            let bytes = packed(&values, bits, length);
            let usedBits = count * bits as usize - 8 * (length - 1);
            for bit in usedBits..8 {
                let mut changed = bytes.clone();
                changed[length - 1] |= 1 << bit;
                let (unchangedValues, isAccepted) = Packing::unpacked(&changed, count, bits);
                assert!(
                    !isAccepted,
                    "{count} values of {bits} bits, padding bit {bit}"
                );
                // The values stay the same, so only the check refuses the input.
                assert_eq!(unchangedValues, values);
            }
            assert!(Packing::unpacked(&bytes, count, bits).1);
            // A change of the last value bit is no padding.
            let mut lastValueBit = bytes.clone();
            lastValueBit[length - 1] ^= 1 << (usedBits - 1);
            assert!(Packing::unpacked(&lastValueBit, count, bits).1);
        }
    }

    #[test]
    fn theThreeBitCheckAcceptsAnyPaddingAsTheCCodeDoes() {
        // `unpack_fz_vec` of cross-rsdp-128-balanced returns 1 for 48 bytes of 0xFF: the
        // 127 values of 3 bits leave 3 padding bits, and the mask of the C code is zero.
        let bytes = vec![0xFF; 48];
        let (values, isAccepted) = Packing::unpacked(&bytes, 127, 3);
        assert!(isAccepted);
        assert!(values.iter().all(|value| *value == 7));
        // 187 and 251 values leave 7 padding bits.
        for count in [187, 251] {
            let length = (count * 3usize).div_ceil(8);
            assert!(
                Packing::unpacked(&vec![0xFF; length], count, 3).1,
                "{count}"
            );
        }
    }

    #[test]
    fn aWholeNumberOfGroupsHasNoPaddingToCheck() {
        for (count, bits) in [(40, 7), (48, 7), (8, 9), (16, 3)] {
            let length = count * bits as usize / 8;
            assert!(Packing::unpacked(&vec![0xFF; length], count, bits).1);
        }
    }
}
