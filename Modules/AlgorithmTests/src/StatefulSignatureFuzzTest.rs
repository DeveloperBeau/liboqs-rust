use crate::statefulKnownAnswerTest::VerificationValues;
use crate::statefulSignatureCorrectnessTest::SavedKeys;
use crate::{FuzzRandom, ResponseFile, StatefulKnownAnswerTest};
use OQSNativeDomain::{RandomGenerating, StatefulSigning};
use OQSNativeEntities::SecretBytes;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// The fuzz programs of liboqs for stateful signature schemes, `tests/fuzz_test_sig_stfl_xmss.c`
/// and `tests/fuzz_test_sig_stfl_lms.c`, on a Rust scheme, with seeded cases in place of the
/// inputs of the fuzzer, and with hostile inputs.
///
/// The C programs start from the public key, the message and the signature of the response file
/// of a scheme, write the bytes of a fuzz input over them, and verify the result. A crash is the
/// only failure. The first byte of the input picks one of the two schemes of each program:
/// `XMSS-SHA2_10_256` and `XMSSMT-SHA2_20/2_256` for XMSS, and `LMS_SHA256_H5_W2` and
/// `LMS_SHA256_H5_W8_H5_W8` for LMS. The test takes the scheme as its input, so it has no such
/// byte. The XMSS program writes over the public key, the signature and the message, in that
/// order. The LMS program reads one more byte, which picks the order: the public key, the
/// signature and the message for 0, the signature, the message and the public key for 1, and the
/// message, the public key and the signature for 2, modulo 3.
///
/// The values of the file must verify. In each case a `FuzzRandom` source gives the bytes of the
/// fuzz input: all zeros for case 0, all ones for case 1 and seeded bytes for every other case.
/// The hostile values of the case give the length of the input. The verification must refuse the
/// result when it differs from the values of the file. Each case then gives hostile signatures
/// and public keys, of the right length and of a wrong length, which the verification must
/// refuse, and hostile secret keys of the right length and of a wrong length. The counts and the
/// signature of a hostile secret key give a result or an error, never a panic, and a signature
/// that comes back comes with its saved key.
pub struct StatefulSignatureFuzzTest;

impl StatefulSignatureFuzzTest {
    /// Runs the cases `0..caseCount` from a seed on the values of the response file of the
    /// scheme. Returns the first failure, with the case and the seed.
    pub fn run(
        scheme: &dyn StatefulSigning,
        responseFile: &str,
        seed: u64,
        caseCount: u64,
    ) -> Result<(), String> {
        let description = scheme.description();
        let name = description.name;
        let file = ResponseFile::new(responseFile);
        let VerificationValues {
            message,
            signature,
            publicKey,
        } = StatefulKnownAnswerTest::verificationValues(description, &file)?;
        if !scheme.isValidSignature(&signature, &message, &publicKey) {
            return Err(format!(
                "{name}: the signature of the response file does not verify"
            ));
        }
        let isLMS = name.starts_with("LMS");
        for case in 0..caseCount {
            let failure =
                |text: String| format!("{name}, fuzz case {case} of seed {seed:#x}: {text}");
            let mut input = FuzzRandom::forCase(seed, case);
            let mut bytes = |length: usize| {
                let mut buffer = vec![0u8; length];
                input.fillRandomBytes(&mut buffer);
                buffer
            };
            let order = if isLMS { bytes(1)[0] % 3 } else { 0 };
            let fieldLength = publicKey.len() + signature.len() + message.len();
            let dataLength =
                (FuzzRandom::hostile(seed, case).nextWord() % (fieldLength as u64 + 1)) as usize;
            let data = bytes(dataLength);
            let (fuzzedKey, fuzzedSignature, fuzzedMessage) =
                Self::overwritten(order, &data, &publicKey, &signature, &message);
            // Fuzz bytes that leave the values as they are give the values that the verification
            // accepted before the cases.
            let isChanged = (&fuzzedKey, &fuzzedSignature, &fuzzedMessage)
                != (&publicKey, &signature, &message);
            if isChanged && scheme.isValidSignature(&fuzzedSignature, &fuzzedMessage, &fuzzedKey) {
                return Err(failure(format!(
                    "the verification accepts the values of the file with {dataLength} fuzz bytes written over them in order {order}"
                )));
            }
            let wrongLength = |length: usize| FuzzRandom::wrongLength(case, length);
            for length in [
                description.signatureLength,
                wrongLength(description.signatureLength),
            ] {
                if scheme.isValidSignature(&bytes(length), &message, &publicKey) {
                    return Err(failure(format!(
                        "the verification accepts a hostile signature of {length} bytes"
                    )));
                }
            }
            for length in [
                description.publicKeyLength,
                wrongLength(description.publicKeyLength),
            ] {
                if scheme.isValidSignature(&signature, &message, &bytes(length)) {
                    return Err(failure(format!(
                        "the verification accepts a hostile public key of {length} bytes"
                    )));
                }
            }
            for length in [
                description.secretKeyLength,
                wrongLength(description.secretKeyLength),
            ] {
                let mut secretKey = SecretBytes::new(bytes(length));
                let _ = scheme.remainingSignatureCount(secretKey.bytes());
                let _ = scheme.totalSignatureCount(secretKey.bytes());
                let mut saved = SavedKeys::accepting();
                if scheme.sign(&message, &mut secretKey, &mut saved).is_ok()
                    && saved.keys != [secretKey.bytes()]
                {
                    return Err(failure(format!(
                        "a signature with a hostile secret key of {length} bytes comes back without its saved key"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The public key, the signature and the message of the file with the fuzz bytes written over
    /// them in an order of `fuzz_test_sig_stfl_lms.c`, as far as the bytes reach. Order 0 is the
    /// order of `fuzz_test_sig_stfl_xmss.c`.
    fn overwritten(
        order: u8,
        data: &[u8],
        publicKey: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut fields = [publicKey.to_vec(), signature.to_vec(), message.to_vec()];
        let sequence: [usize; 3] = match order {
            1 => [1, 2, 0],
            2 => [2, 0, 1],
            _ => [0, 1, 2],
        };
        let mut remaining = data;
        for index in sequence {
            let count = remaining.len().min(fields[index].len());
            fields[index][..count].copy_from_slice(&remaining[..count]);
            remaining = &remaining[count..];
        }
        let [publicKey, signature, message] = fields;
        (publicKey, signature, message)
    }
}

#[cfg(test)]
mod tests {
    use super::StatefulSignatureFuzzTest;
    use alloc::vec;

    #[test]
    fn theFuzzBytesFillTheFieldsInTheOrderOfTheCPrograms() {
        let key = [1u8; 2];
        let signature = [2u8; 3];
        let message = [3u8; 2];
        let data = [9u8, 8, 7, 6];
        assert_eq!(
            StatefulSignatureFuzzTest::overwritten(0, &data, &key, &signature, &message),
            (vec![9, 8], vec![7, 6, 2], vec![3, 3])
        );
        assert_eq!(
            StatefulSignatureFuzzTest::overwritten(1, &data, &key, &signature, &message),
            (vec![1, 1], vec![9, 8, 7], vec![6, 3])
        );
        assert_eq!(
            StatefulSignatureFuzzTest::overwritten(2, &data, &key, &signature, &message),
            (vec![7, 6], vec![2, 2, 2], vec![9, 8])
        );
        // The bytes past all three fields are not used, and no bytes leave the fields as they are.
        let long = [5u8; 9];
        assert_eq!(
            StatefulSignatureFuzzTest::overwritten(0, &long, &key, &signature, &message),
            (vec![5, 5], vec![5, 5, 5], vec![5, 5])
        );
        assert_eq!(
            StatefulSignatureFuzzTest::overwritten(2, &[], &key, &signature, &message),
            (key.to_vec(), signature.to_vec(), message.to_vec())
        );
    }
}
