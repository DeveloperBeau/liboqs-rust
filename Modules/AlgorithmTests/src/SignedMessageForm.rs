use alloc::vec::Vec;

/// The layout of the signed message `sm` that `tests/kat_sig.c` prints for a scheme.
///
/// `combine_message_signature` of the C program picks the layout by scheme name. A scheme that
/// it does not list has no known-answer run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedMessageForm {
    /// The signature, then the message.
    signatureThenMessage,
    /// The message, then the signature.
    messageThenSignature,
    /// The form of the Falcon submission: the big-endian length of the signature without its
    /// 40-byte salt, the salt, the message, a header byte and the rest of the signature.
    falcon {
        /// The header byte of the parameter set, `0x29` for Falcon-512 and `0x2A` for
        /// Falcon-1024.
        headerByte: u8,
    },
}

impl SignedMessageForm {
    /// The schemes whose signed message is the signature and then the message.
    pub const signatureThenMessageSchemes: [&'static str; 21] = [
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "Falcon-padded-512",
        "Falcon-padded-1024",
        "MAYO-1",
        "MAYO-2",
        "MAYO-3",
        "MAYO-5",
        "SNOVA_24_5_4",
        "SNOVA_24_5_4_SHAKE",
        "SNOVA_24_5_4_esk",
        "SNOVA_24_5_4_SHAKE_esk",
        "SNOVA_37_17_2",
        "SNOVA_25_8_3",
        "SNOVA_56_25_2",
        "SNOVA_49_11_3",
        "SNOVA_37_8_4",
        "SNOVA_24_5_5",
        "SNOVA_60_10_4",
        "SNOVA_29_6_5",
    ];

    /// The schemes whose signed message is the message and then the signature.
    pub const messageThenSignatureSchemes: [&'static str; 42] = [
        "cross-rsdp-128-balanced",
        "cross-rsdp-128-fast",
        "cross-rsdp-128-small",
        "cross-rsdp-192-balanced",
        "cross-rsdp-192-fast",
        "cross-rsdp-192-small",
        "cross-rsdp-256-balanced",
        "cross-rsdp-256-fast",
        "cross-rsdp-256-small",
        "cross-rsdpg-128-balanced",
        "cross-rsdpg-128-fast",
        "cross-rsdpg-128-small",
        "cross-rsdpg-192-balanced",
        "cross-rsdpg-192-fast",
        "cross-rsdpg-192-small",
        "cross-rsdpg-256-balanced",
        "cross-rsdpg-256-fast",
        "cross-rsdpg-256-small",
        "OV-Is",
        "OV-Ip",
        "OV-III",
        "OV-V",
        "OV-Is-pkc",
        "OV-Ip-pkc",
        "OV-III-pkc",
        "OV-V-pkc",
        "OV-Is-pkc-skc",
        "OV-Ip-pkc-skc",
        "OV-III-pkc-skc",
        "OV-V-pkc-skc",
        "mqom2_cat1_gf16_fast_r3",
        "mqom2_cat1_gf16_fast_r5",
        "mqom2_cat1_gf16_short_r3",
        "mqom2_cat1_gf16_short_r5",
        "mqom2_cat3_gf16_fast_r3",
        "mqom2_cat3_gf16_fast_r5",
        "mqom2_cat3_gf16_short_r3",
        "mqom2_cat3_gf16_short_r5",
        "mqom2_cat5_gf16_fast_r3",
        "mqom2_cat5_gf16_fast_r5",
        "mqom2_cat5_gf16_short_r3",
        "mqom2_cat5_gf16_short_r5",
    ];

    /// The form of a scheme, or `None` when the C program has no known-answer run for it.
    pub fn of(scheme: &str) -> Option<Self> {
        match scheme {
            "Falcon-512" => Some(SignedMessageForm::falcon { headerByte: 0x29 }),
            "Falcon-1024" => Some(SignedMessageForm::falcon { headerByte: 0x2A }),
            _ if Self::signatureThenMessageSchemes.contains(&scheme) => {
                Some(SignedMessageForm::signatureThenMessage)
            }
            _ if Self::messageThenSignatureSchemes.contains(&scheme) => {
                Some(SignedMessageForm::messageThenSignature)
            }
            _ => None,
        }
    }

    /// The signed message of a message and its signature in this form.
    pub fn signedMessage(&self, message: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut signed = Vec::with_capacity(2 + message.len() + signature.len());
        match self {
            SignedMessageForm::signatureThenMessage => {
                signed.extend_from_slice(signature);
                signed.extend_from_slice(message);
            }
            SignedMessageForm::messageThenSignature => {
                signed.extend_from_slice(message);
                signed.extend_from_slice(signature);
            }
            SignedMessageForm::falcon { headerByte } => {
                // The first signature byte is a header and the next 40 bytes are the salt, as in
                // `combine_message_signature`. The length is a 16-bit value, as in the C code.
                let lengthWithoutSalt = (signature.len() as u16).wrapping_sub(40);
                signed.extend_from_slice(&lengthWithoutSalt.to_be_bytes());
                signed.extend_from_slice(&signature[1..41]);
                signed.extend_from_slice(message);
                signed.push(*headerByte);
                signed.extend_from_slice(&signature[41..]);
            }
        }
        signed
    }
}

#[cfg(test)]
mod tests {
    use super::SignedMessageForm;

    #[test]
    fn eachSchemeOfTheCProgramHasItsForm() {
        assert_eq!(
            SignedMessageForm::of("ML-DSA-65"),
            Some(SignedMessageForm::signatureThenMessage)
        );
        assert_eq!(
            SignedMessageForm::of("cross-rsdpg-256-small"),
            Some(SignedMessageForm::messageThenSignature)
        );
        assert_eq!(
            SignedMessageForm::of("Falcon-1024"),
            Some(SignedMessageForm::falcon { headerByte: 0x2A })
        );
        assert_eq!(
            SignedMessageForm::of("Falcon-512"),
            Some(SignedMessageForm::falcon { headerByte: 0x29 })
        );
        assert_eq!(SignedMessageForm::of("SLH_DSA_PURE_SHA2_128S"), None);
        assert_eq!(
            SignedMessageForm::signatureThenMessageSchemes.len()
                + SignedMessageForm::messageThenSignatureSchemes.len()
                + 2,
            65
        );
    }

    #[test]
    fn signedMessagesJoinThePartsInTheOrderOfTheForm() {
        let message = [1u8, 2, 3];
        let signature = [9u8, 8];
        assert_eq!(
            SignedMessageForm::signatureThenMessage.signedMessage(&message, &signature),
            vec![9, 8, 1, 2, 3]
        );
        assert_eq!(
            SignedMessageForm::messageThenSignature.signedMessage(&message, &signature),
            vec![1, 2, 3, 9, 8]
        );
    }

    #[test]
    fn falconFormMovesTheSaltBeforeTheMessageAndTheHeaderAfterIt() {
        // A signature of 45 bytes: header 0x39, salt 1 to 40 and a body of 4 bytes.
        let mut signature = vec![0x39u8];
        signature.extend(1..=40u8);
        signature.extend([0xA1, 0xA2, 0xA3, 0xA4]);
        let signed =
            SignedMessageForm::falcon { headerByte: 0x29 }.signedMessage(&[0xEE, 0xFF], &signature);
        let mut expected = vec![0x00, 0x05];
        expected.extend(1..=40u8);
        expected.extend([0xEE, 0xFF, 0x29, 0xA1, 0xA2, 0xA3, 0xA4]);
        assert_eq!(signed, expected);
    }
}
