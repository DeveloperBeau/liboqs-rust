use crate::CoreHash;
use OQSNativeSHA2::{SHA256, SHA512};
use OQSNativeSHA3::{SHAKE128, SHAKE256};

/// A `CoreHash` while it absorbs its input.
///
/// The C code hashes one buffer with each call. The output depends only on the bytes, so the
/// port absorbs the parts of an input in turn, and a clone of a state that has absorbed a common
/// prefix, such as the prefix of each PRF of the public seed, absorbs that prefix once.
#[derive(Clone)]
pub(crate) struct HashState {
    function: CoreHash,
    sponge: Sponge,
}

/// The primitive of a `CoreHash`.
#[derive(Clone)]
enum Sponge {
    sha256(SHA256),
    sha512(SHA512),
    shake128(SHAKE128),
    shake256(SHAKE256),
}

impl HashState {
    /// Makes a state of a function with no input yet.
    pub(crate) fn new(function: CoreHash) -> Self {
        let sponge = match function {
            CoreHash::sha256N24 | CoreHash::sha256N32 => Sponge::sha256(SHA256::new()),
            CoreHash::sha512N64 => Sponge::sha512(SHA512::new()),
            CoreHash::shake128N32 => Sponge::shake128(SHAKE128::new()),
            CoreHash::shake256N24 | CoreHash::shake256N32 | CoreHash::shake256N64 => {
                Sponge::shake256(SHAKE256::new())
            }
        };
        HashState { function, sponge }
    }

    /// Absorbs the next part of the input.
    pub(crate) fn absorb(&mut self, input: &[u8]) {
        match &mut self.sponge {
            Sponge::sha256(hash) => hash.absorb(input),
            Sponge::sha512(hash) => hash.absorb(input),
            Sponge::shake128(function) => function.absorb(input),
            Sponge::shake256(function) => function.absorb(input),
        }
    }

    /// Ends the input and writes the output of the function, `CoreHash::outputLength` bytes, to
    /// the start of a buffer.
    pub(crate) fn finish(self, output: &mut [u8]) {
        let length = self.function.outputLength();
        match self.sponge {
            // `core_hash` keeps the first 24 bytes of the SHA-256 digest for n = 24.
            Sponge::sha256(hash) => output[..length].copy_from_slice(&hash.finalize()[..length]),
            Sponge::sha512(hash) => output[..length].copy_from_slice(&hash.finalize()),
            Sponge::shake128(function) => function.finalize().squeeze(&mut output[..length]),
            Sponge::shake256(function) => function.finalize().squeeze(&mut output[..length]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HashState;
    use crate::CoreHash;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digits"))
            .collect()
    }

    fn output(function: CoreHash, parts: &[&[u8]]) -> Vec<u8> {
        let mut state = HashState::new(function);
        for part in parts {
            state.absorb(part);
        }
        let mut output = vec![0xA5u8; 64];
        state.finish(&mut output);
        output.truncate(function.outputLength());
        output
    }

    #[test]
    fn eachFunctionGivesTheDigestOfItsStandardForTheMessageAbc() {
        // FIPS 180-4 and FIPS 202 examples for the message "abc", cut to the length of n.
        let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let sha512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        let shake128 = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8";
        let shake256 = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4";
        for (function, digest) in [
            (CoreHash::sha256N24, &sha256[..48]),
            (CoreHash::sha256N32, sha256),
            (CoreHash::sha512N64, sha512),
            (CoreHash::shake128N32, shake128),
            (CoreHash::shake256N24, &shake256[..48]),
            (CoreHash::shake256N32, &shake256[..64]),
            (CoreHash::shake256N64, shake256),
        ] {
            assert_eq!(output(function, &[b"abc"]), hex(digest), "{function:?}");
        }
    }

    #[test]
    fn partsAndClonesGiveTheDigestOfTheWholeInput() {
        let input: Vec<u8> = (0..300u32).map(|value| (value * 7) as u8).collect();
        for function in [
            CoreHash::sha256N24,
            CoreHash::shake256N24,
            CoreHash::sha256N32,
            CoreHash::shake128N32,
            CoreHash::shake256N32,
            CoreHash::sha512N64,
            CoreHash::shake256N64,
        ] {
            let whole = output(function, &[&input]);
            assert_eq!(
                output(function, &[&input[..64], &input[64..65], &input[65..]]),
                whole
            );
            let mut prefix = HashState::new(function);
            prefix.absorb(&input[..128]);
            let mut first = prefix.clone();
            first.absorb(&input[128..]);
            let mut firstOutput = [0u8; 64];
            first.finish(&mut firstOutput);
            assert_eq!(&firstOutput[..function.outputLength()], &whole[..]);
            let mut second = prefix;
            second.absorb(&input[128..299]);
            let mut secondOutput = [0u8; 64];
            second.finish(&mut secondOutput);
            assert_eq!(
                &secondOutput[..function.outputLength()],
                &output(function, &[&input[..299]])[..]
            );
        }
    }
}
