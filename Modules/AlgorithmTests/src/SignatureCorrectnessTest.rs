use OQSNativeDomain::{RandomGenerating, Signing};
use alloc::format;
use alloc::string::String;
use alloc::vec;

/// The correctness test of liboqs for signature schemes, `tests/test_sig.c`, with its extended
/// tests, on a Rust scheme.
///
/// The test signs a random message of 100 bytes and verifies it. Then it flips random bits of
/// the message, and of the signature for a scheme that claims SUF-CMA, and each flip must fail
/// the verification. A scheme with context support signs and verifies under contexts of up to
/// 255 bytes, with the same bit flips, and must refuse a context of 256 bytes. A scheme without
/// it must refuse a context of one byte. Every scheme signs and verifies with the empty
/// context. The guard bytes of the C test have no Rust counterpart.
pub struct SignatureCorrectnessTest;

impl SignatureCorrectnessTest {
    /// The random bit flips of the message and of the signature, as `test_sig` runs them.
    pub const bitFlipCount: usize = 50;

    /// Runs the test with random bytes from a source. Returns the first failure.
    pub fn run(scheme: &dyn Signing, random: &mut dyn RandomGenerating) -> Result<(), String> {
        let description = scheme.description();
        let name = description.name;
        let mut message = vec![0u8; 100];
        random.fillRandomBytes(&mut message);
        let keyPair = scheme
            .generateKeyPair(random)
            .map_err(|error| format!("{name}: the key pair failed: {error}"))?;
        let secretKey = keyPair.secretKey.bytes();
        let publicKey = keyPair.publicKey.as_slice();
        let signature = scheme
            .sign(&message, secretKey, random)
            .map_err(|error| format!("{name}: the signature failed: {error}"))?;
        if !scheme.isValidSignature(&signature, &message, publicKey) {
            return Err(format!("{name}: the signature does not verify"));
        }
        Self::checkBitFlips(scheme, random, &message, &signature, publicKey, None)?;
        let mut context = [0u8; 257];
        random.fillRandomBytes(&mut context);
        if description.supportsContext {
            // SLH-DSA signs slowly, so the test steps through its context lengths by a prime.
            let step = if name.starts_with("SLH_DSA") { 61 } else { 1 };
            for length in (0..256).filter(|length| length % step == 0 || *length == 255) {
                let context = &context[..length];
                let signature = scheme
                    .signWithContext(&message, context, secretKey, random)
                    .map_err(|error| {
                        format!(
                            "{name}: the signature with a {length}-byte context failed: {error}"
                        )
                    })?;
                if !scheme.isValidSignatureWithContext(&signature, &message, context, publicKey) {
                    return Err(format!(
                        "{name}: the signature with a {length}-byte context does not verify"
                    ));
                }
                Self::checkBitFlips(
                    scheme,
                    random,
                    &message,
                    &signature,
                    publicKey,
                    Some(context),
                )?;
            }
            if scheme
                .signWithContext(&message, &context[..256], secretKey, random)
                .is_ok()
            {
                return Err(format!("{name}: a 256-byte context must be refused"));
            }
        } else if scheme
            .signWithContext(&message, &context[..1], secretKey, random)
            .is_ok()
        {
            return Err(format!(
                "{name}: a context must be refused without context support"
            ));
        }
        let signature = scheme
            .signWithContext(&message, &[], secretKey, random)
            .map_err(|error| {
                format!("{name}: the signature with the empty context failed: {error}")
            })?;
        if !scheme.isValidSignatureWithContext(&signature, &message, &[], publicKey) {
            return Err(format!(
                "{name}: the signature with the empty context does not verify"
            ));
        }
        Self::checkBitFlips(scheme, random, &message, &signature, publicKey, Some(&[]))
    }

    /// `test_sig_bitflip` of `tests/test_helpers.c`: each random bit flip of the message, and
    /// of the signature for an SUF-CMA scheme, must fail the verification. The index of a flip
    /// is a little-endian `u64` of 8 random bytes, modulo the number of bits.
    fn checkBitFlips(
        scheme: &dyn Signing,
        random: &mut dyn RandomGenerating,
        message: &[u8],
        signature: &[u8],
        publicKey: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), String> {
        let description = scheme.description();
        let isValid = |message: &[u8], signature: &[u8]| match context {
            Some(context) => {
                scheme.isValidSignatureWithContext(signature, message, context, publicKey)
            }
            None => scheme.isValidSignature(signature, message, publicKey),
        };
        let mut tamperedMessage = message.to_vec();
        let mut tamperedSignature = signature.to_vec();
        let partCount = if description.isSUFCMASecure { 2 } else { 1 };
        for part in 0..partCount {
            let (partName, tampered) = if part == 0 {
                ("message", &mut tamperedMessage)
            } else {
                ("signature", &mut tamperedSignature)
            };
            for _ in 0..Self::bitFlipCount {
                let mut indexBytes = [0u8; 8];
                random.fillRandomBytes(&mut indexBytes);
                let bit = (u64::from_le_bytes(indexBytes) % (8 * tampered.len() as u64)) as usize;
                tampered[bit / 8] ^= 1 << (bit % 8);
                let isAccepted = if part == 0 {
                    isValid(tampered, signature)
                } else {
                    isValid(message, tampered)
                };
                tampered[bit / 8] ^= 1 << (bit % 8);
                if isAccepted {
                    return Err(format!(
                        "{}: the verification accepts the {partName} with bit {bit} flipped",
                        description.name
                    ));
                }
            }
        }
        Ok(())
    }
}
