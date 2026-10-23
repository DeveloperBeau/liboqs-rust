use crate::Variant;

/// The parameters of one XMSS or XMSS^MT parameter set, as `xmss_params` of `params.h` holds
/// them.
///
/// `xmss_parse_oid` and `xmssmt_parse_oid` of `params.c` give them from an object identifier.
/// Every set of `params.c` has the Winternitz parameter w = 16 and the BDS parameter k = 0, so
/// those two are constants here, and the BDS state of a tree keeps no retained nodes. The lengths
/// of the keys leave out the 4 bytes of the object identifier in front.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Parameters {
    /// The length n of a hash output, of a seed and of a tree node in bytes.
    pub(crate) hashLength: usize,
    /// The length of the domain prefix toByte(X) in front of each hash input.
    pub(crate) paddingLength: usize,
    /// The number len_1 of base-w digits of a message digest, one chain for each.
    pub(crate) messageChainCount: usize,
    /// The number len of the chains of a WOTS+ key: the message chains and the checksum chains.
    pub(crate) chainCount: usize,
    /// The length of a WOTS+ signature, len n.
    pub(crate) wotsSignatureLength: usize,
    /// The height h of the whole hypertree.
    pub(crate) fullHeight: u32,
    /// The height h / d of one tree.
    pub(crate) treeHeight: u32,
    /// The number d of layers of trees.
    pub(crate) layerCount: u32,
    /// The length of the leaf index in a secret key and in a signature.
    pub(crate) indexLength: usize,
    /// The length of a signature.
    pub(crate) signatureLength: usize,
    /// The length of a public key, the root and the public seed: 2 n.
    pub(crate) publicKeyLength: usize,
    /// The length of a secret key with the BDS states of `xmss_core_fast.c`.
    pub(crate) secretKeyLength: usize,
}

impl Parameters {
    /// The Winternitz parameter w of every set.
    pub(crate) const winternitzParameter: u32 = 16;

    /// The bits of one base-w digit, log2 w.
    pub(crate) const digitBits: u32 = 4;

    /// The number len_2 of base-w digits of the checksum for w = 16.
    pub(crate) const checksumChainCount: usize = 3;

    /// The length of the object identifier in front of each key.
    pub(crate) const objectIdentifierLength: usize = 4;

    /// The parameters of an object identifier of a variant, or `None` when `params.c` has no
    /// set with that identifier.
    pub(crate) const fn of(variant: Variant, objectIdentifier: u32) -> Option<Parameters> {
        match variant {
            Variant::xmss => Self::xmss(objectIdentifier),
            Variant::xmssmt => Self::xmssmt(objectIdentifier),
        }
    }

    /// The parameters of an XMSS identifier, as `xmss_parse_oid`.
    const fn xmss(objectIdentifier: u32) -> Option<Parameters> {
        // The first table of the C code chooses the hash function, which the core hash of the
        // set overrides. The table of n refuses the same identifiers as that table.
        let hashLength = match objectIdentifier {
            0x0d | 0x0e | 0x0f | 0x13 | 0x14 | 0x15 => 24,
            0x01 | 0x02 | 0x03 | 0x07 | 0x08 | 0x09 | 0x10 | 0x11 | 0x12 => 32,
            0x04 | 0x05 | 0x06 | 0x0a | 0x0b | 0x0c => 64,
            _ => return None,
        };
        let fullHeight = match objectIdentifier {
            0x01 | 0x04 | 0x07 | 0x0a | 0x0d | 0x10 | 0x13 => 10,
            0x02 | 0x05 | 0x08 | 0x0b | 0x0e | 0x11 | 0x14 => 16,
            0x03 | 0x06 | 0x09 | 0x0c | 0x0f | 0x12 | 0x15 => 20,
            _ => return None,
        };
        Some(Self::initialized(hashLength, fullHeight, 1))
    }

    /// The parameters of an XMSS^MT identifier, as `xmssmt_parse_oid`. The table also holds the
    /// sets of 512 bits that liboqs does not offer.
    const fn xmssmt(objectIdentifier: u32) -> Option<Parameters> {
        // As for XMSS, the table of n refuses the identifiers that the table of the hash
        // functions refuses.
        let hashLength = match objectIdentifier {
            0x21..=0x28 | 0x31..=0x38 => 24,
            0x01..=0x08 | 0x11..=0x18 | 0x29..=0x30 => 32,
            0x09..=0x10 | 0x19..=0x20 => 64,
            _ => return None,
        };
        let fullHeight = match objectIdentifier {
            0x01 | 0x02 | 0x09 | 0x0a | 0x11 | 0x12 | 0x19 | 0x1a | 0x21 | 0x22 | 0x29 | 0x2a
            | 0x31 | 0x32 => 20,
            0x03 | 0x04 | 0x05 | 0x0b | 0x0c | 0x0d | 0x13 | 0x14 | 0x15 | 0x1b | 0x1c | 0x1d
            | 0x23 | 0x24 | 0x25 | 0x2b | 0x2c | 0x2d | 0x33 | 0x34 | 0x35 => 40,
            0x06 | 0x07 | 0x08 | 0x0e | 0x0f | 0x10 | 0x16 | 0x17 | 0x18 | 0x1e | 0x1f | 0x20
            | 0x26 | 0x27 | 0x28 | 0x2e | 0x2f | 0x30 | 0x36 | 0x37 | 0x38 => 60,
            _ => return None,
        };
        let layerCount = match objectIdentifier {
            0x01 | 0x03 | 0x09 | 0x0b | 0x11 | 0x13 | 0x19 | 0x1b | 0x21 | 0x23 | 0x29 | 0x2b
            | 0x31 | 0x33 => 2,
            0x02 | 0x04 | 0x0a | 0x0c | 0x12 | 0x14 | 0x1a | 0x1c | 0x22 | 0x24 | 0x2a | 0x2c
            | 0x32 | 0x34 => 4,
            0x05 | 0x0d | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 => 8,
            0x06 | 0x0e | 0x16 | 0x1e | 0x26 | 0x2e | 0x36 => 3,
            0x07 | 0x0f | 0x17 | 0x1f | 0x27 | 0x2f | 0x37 => 6,
            0x08 | 0x10 | 0x18 | 0x20 | 0x28 | 0x30 | 0x38 => 12,
            _ => return None,
        };
        Some(Self::initialized(hashLength, fullHeight, layerCount))
    }

    /// The remaining parameters of a hash length, a height and a layer count, as
    /// `xmss_xmssmt_initialize_params` gives them for w = 16.
    const fn initialized(hashLength: usize, fullHeight: u32, layerCount: u32) -> Parameters {
        let treeHeight = fullHeight / layerCount;
        let messageChainCount = 8 * hashLength / Self::digitBits as usize;
        let chainCount = messageChainCount + Self::checksumChainCount;
        let wotsSignatureLength = chainCount * hashLength;
        // XMSS always has a 4-byte index, and XMSS^MT the bytes of the full height.
        let indexLength = if layerCount == 1 {
            4
        } else {
            (fullHeight as usize).div_ceil(8)
        };
        Parameters {
            hashLength,
            // `params.c` pads the 24-byte sets with 4 bytes and the others with n bytes.
            paddingLength: if hashLength == 24 { 4 } else { hashLength },
            messageChainCount,
            chainCount,
            wotsSignatureLength,
            fullHeight,
            treeHeight,
            layerCount,
            indexLength,
            signatureLength: indexLength
                + hashLength
                + layerCount as usize * wotsSignatureLength
                + fullHeight as usize * hashLength,
            publicKeyLength: 2 * hashLength,
            secretKeyLength: Self::secretKeyLength(
                hashLength,
                treeHeight,
                layerCount,
                indexLength,
                wotsSignatureLength,
            ),
        }
    }

    /// The length of a secret key, as `xmss_xmssmt_core_sk_bytes` of `xmss_core_fast.c`: the
    /// index, the two secret seeds, the root and the public seed, the 2 d - 1 BDS states, and
    /// the d - 1 WOTS+ signatures of the roots of the trees below the top layer.
    const fn secretKeyLength(
        hashLength: usize,
        treeHeight: u32,
        layerCount: u32,
        indexLength: usize,
        wotsSignatureLength: usize,
    ) -> usize {
        let stateCount = 2 * layerCount as usize - 1;
        indexLength
            + 4 * hashLength
            + stateCount * Self::stateLength(hashLength, treeHeight as usize)
            + (layerCount as usize - 1) * wotsSignatureLength
    }

    /// The length of one serialized BDS state: the stack and its offset, the stack levels, the
    /// authentication path, the kept nodes, the treehash instances and the next leaf.
    const fn stateLength(hashLength: usize, treeHeight: usize) -> usize {
        (treeHeight + 1) * hashLength
            + 4
            + treeHeight
            + 1
            + treeHeight * hashLength
            + (treeHeight >> 1) * hashLength
            + treeHeight * (7 + hashLength)
            + 4
    }

    /// The largest leaf index, 2^h - 1, which is also the total signature count of liboqs.
    pub(crate) const fn lastIndex(&self) -> u64 {
        (1u64 << self.fullHeight) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::Parameters;
    use crate::Variant;

    /// The object identifier, the secret key length without the identifier, the public key
    /// length without the identifier and the signature length of each XMSS set, from the table
    /// at the top of `sig_stfl_xmss.h`.
    const xmssLengths: [(u32, usize, usize, usize); 21] = [
        (0x01, 1373, 64, 2500),
        (0x02, 2093, 64, 2692),
        (0x03, 2573, 64, 2820),
        (0x07, 1373, 64, 2500),
        (0x08, 2093, 64, 2692),
        (0x09, 2573, 64, 2820),
        (0x04, 2653, 128, 9092),
        (0x05, 4045, 128, 9476),
        (0x06, 4973, 128, 9732),
        (0x0a, 2653, 128, 9092),
        (0x0b, 4045, 128, 9476),
        (0x0c, 4973, 128, 9732),
        (0x0d, 1053, 48, 1492),
        (0x0e, 1605, 48, 1636),
        (0x0f, 1973, 48, 1732),
        (0x10, 1373, 64, 2500),
        (0x11, 2093, 64, 2692),
        (0x12, 2573, 64, 2820),
        (0x13, 1053, 48, 1492),
        (0x14, 1605, 48, 1636),
        (0x15, 1973, 48, 1732),
    ];

    /// The same facts of each XMSS^MT set of `sig_stfl_xmss.h`.
    const xmssmtLengths: [(u32, usize, usize, usize); 16] = [
        (0x01, 5998, 64, 4963),
        (0x02, 10938, 64, 9251),
        (0x03, 9600, 64, 5605),
        (0x04, 15252, 64, 9893),
        (0x05, 24516, 64, 18469),
        (0x06, 16629, 64, 8392),
        (0x07, 24507, 64, 14824),
        (0x08, 38095, 64, 27688),
        (0x11, 5998, 64, 4963),
        (0x12, 10938, 64, 9251),
        (0x13, 9600, 64, 5605),
        (0x14, 15252, 64, 9893),
        (0x15, 24516, 64, 18469),
        (0x16, 16629, 64, 8392),
        (0x17, 24507, 64, 14824),
        (0x18, 38095, 64, 27688),
    ];

    fn lengths(parameters: &Parameters) -> (usize, usize, usize) {
        (
            parameters.secretKeyLength,
            parameters.publicKeyLength,
            parameters.signatureLength,
        )
    }

    #[test]
    fn eachLiboqsSetHasTheLengthsOfItsHeader() {
        for (variant, table) in [
            (Variant::xmss, &xmssLengths[..]),
            (Variant::xmssmt, &xmssmtLengths[..]),
        ] {
            for &(objectIdentifier, secretKey, publicKey, signature) in table {
                let parameters = Parameters::of(variant, objectIdentifier).expect("a known set");
                assert_eq!(
                    lengths(&parameters),
                    (secretKey, publicKey, signature),
                    "{variant:?} {objectIdentifier:#04x}"
                );
            }
        }
    }

    #[test]
    fn theTablesGiveTheHeightsLayersAndHashLengthsOfParamsC() {
        let shape = |variant, objectIdentifier| {
            let parameters = Parameters::of(variant, objectIdentifier).expect("a known set");
            (
                parameters.hashLength,
                parameters.paddingLength,
                parameters.fullHeight,
                parameters.layerCount,
                parameters.treeHeight,
                parameters.indexLength,
            )
        };
        assert_eq!(shape(Variant::xmss, 0x01), (32, 32, 10, 1, 10, 4));
        assert_eq!(shape(Variant::xmss, 0x0c), (64, 64, 20, 1, 20, 4));
        assert_eq!(shape(Variant::xmss, 0x14), (24, 4, 16, 1, 16, 4));
        assert_eq!(shape(Variant::xmssmt, 0x02), (32, 32, 20, 4, 5, 3));
        assert_eq!(shape(Variant::xmssmt, 0x08), (32, 32, 60, 12, 5, 8));
        assert_eq!(shape(Variant::xmssmt, 0x16), (32, 32, 60, 3, 20, 8));
        // The sets of 512 and 192 bits that liboqs does not offer are still in the table.
        assert_eq!(shape(Variant::xmssmt, 0x09), (64, 64, 20, 2, 10, 3));
        assert_eq!(shape(Variant::xmssmt, 0x1d), (64, 64, 40, 8, 5, 5));
        assert_eq!(shape(Variant::xmssmt, 0x21), (24, 4, 20, 2, 10, 3));
        assert_eq!(shape(Variant::xmssmt, 0x38), (24, 4, 60, 12, 5, 8));
    }

    #[test]
    fn eachIdentifierOutsideTheTablesIsUnknown() {
        for objectIdentifier in [0, 0x16, 0x20, 0xFF, 0x0100_0001, u32::MAX] {
            assert_eq!(Parameters::of(Variant::xmss, objectIdentifier), None);
        }
        for objectIdentifier in [0, 0x39, 0x40, 0x0100_0001, u32::MAX] {
            assert_eq!(Parameters::of(Variant::xmssmt, objectIdentifier), None);
        }
        let known = |variant| {
            (0..=0x40)
                .filter(|objectIdentifier| Parameters::of(variant, *objectIdentifier).is_some())
                .count()
        };
        assert_eq!(known(Variant::xmss), 21);
        assert_eq!(known(Variant::xmssmt), 56);
    }

    #[test]
    fn theChainCountsAreTheCountsOfRFC8391ForW16() {
        let parameters = Parameters::of(Variant::xmss, 0x01).expect("XMSS-SHA2_10_256");
        assert_eq!(
            (parameters.messageChainCount, parameters.chainCount),
            (64, 67)
        );
        let parameters = Parameters::of(Variant::xmss, 0x04).expect("XMSS-SHA2_10_512");
        assert_eq!(
            (parameters.messageChainCount, parameters.chainCount),
            (128, 131)
        );
        let parameters = Parameters::of(Variant::xmss, 0x0d).expect("XMSS-SHA2_10_192");
        assert_eq!(
            (parameters.messageChainCount, parameters.chainCount),
            (48, 51)
        );
        assert_eq!(parameters.lastIndex(), 1023);
        assert_eq!(
            Parameters::of(Variant::xmssmt, 0x08)
                .expect("XMSSMT-SHA2_60/12_256")
                .lastIndex(),
            (1 << 60) - 1
        );
    }
}
