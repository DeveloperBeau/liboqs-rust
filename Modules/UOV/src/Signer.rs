use crate::parameters::{Parameters, saltLength, secretSeedLength};
use crate::{BatchedMatrix, FieldArithmetic, LinearSystem, SaltedMessage};
use alloc::vec;
use alloc::vec::Vec;

/// The signature of `ov_sign` with a classic secret key.
///
/// The target y is SHAKE256 of the message and the salt. Each attempt hashes the message, the
/// salt, the secret seed and a counter byte into vinegar values v. With v fixed, the oil
/// variables x meet the linear system `L x = y - P1(v)`, where L is the sum of the rows of the
/// block S times the vinegar values. A nonsingular L gives x, and the point of the signature is
/// `(v + O x, x)`.
pub(crate) struct Signer;

/// The attempts of the loop of `ov_sign`, `MAX_ATTEMPT_VINEGAR`.
pub(crate) const maximumAttemptCount: usize = 256;

impl Signer {
    /// The signature of a message with a classic secret key of the length of the set and a
    /// salt: the point w and the salt. `None` when no attempt finds a nonsingular system, as
    /// `ov_sign` returns -1.
    pub(crate) fn signature<F: FieldArithmetic>(
        parameters: &Parameters,
        secretKey: &[u8],
        message: &[u8],
        salt: &[u8; saltLength],
    ) -> Option<Vec<u8>> {
        let vinegarCount = parameters.vinegarCount();
        let oilCount = parameters.oilCount;
        let entryLength = parameters.oilLength();
        let (secretSeed, rest) = secretKey.split_at(secretSeedLength);
        let (oilMatrix, blocks) = rest.split_at(parameters.oilMatrixLength());
        let (vinegarBlock, linearBlock) = blocks.split_at(parameters.vinegarBlockLength());
        let salted = SaltedMessage::new(message, salt);
        let target = salted.target(entryLength);
        let vinegarHash = salted.withSecretSeed(secretSeed);
        let (mut point, oilValues) = Self::firstSolution(|counter| {
            let mut hash = vinegarHash.clone();
            hash.absorb(&[counter]);
            let mut vinegar = vec![0u8; parameters.vinegarLength()];
            hash.finalize().squeeze(&mut vinegar);
            // The linear system: L is the sum of the rows of S times v, a matrix of o columns
            // of o elements, and the constant is y + P1(v).
            let linearMap = BatchedMatrix::linearCombination::<F>(
                linearBlock,
                oilCount * entryLength,
                &vinegar,
                vinegarCount,
            );
            let mut constant = BatchedMatrix::quadraticForm::<F>(
                vinegarBlock,
                &vinegar,
                vinegarCount,
                entryLength,
            );
            F::add(&mut constant, &target);
            let mut system = LinearSystem::<F>::new(&linearMap, &constant, oilCount);
            if system.eliminate() {
                Some((vinegar, system.solution()))
            } else {
                None
            }
        })?;
        // w = (v + O x, x): the identity part and the oil part of the map T.
        let oilProduct = BatchedMatrix::linearCombination::<F>(
            oilMatrix,
            parameters.vinegarLength(),
            &oilValues,
            oilCount,
        );
        F::add(&mut point, &oilProduct);
        let mut signature = point;
        signature.reserve_exact(oilValues.len() + saltLength);
        signature.extend_from_slice(&oilValues);
        signature.extend_from_slice(salt);
        Some(signature)
    }

    /// The result of the first attempt that succeeds, as the loop of `ov_sign` takes it.
    ///
    /// Attempt n gets the counter byte n. As in the C code, the loop counts an attempt before
    /// it runs it and fails when the count reaches 256 after the attempt that succeeds, so a
    /// success of the last attempt, of the counter 255, is a failure too.
    pub(crate) fn firstSolution<Solution>(
        mut attempt: impl FnMut(u8) -> Option<Solution>,
    ) -> Option<Solution> {
        let mut attemptCount = 0;
        while attemptCount < maximumAttemptCount {
            let counter = (attemptCount & 0xFF) as u8;
            attemptCount += 1;
            if let Some(solution) = attempt(counter) {
                return (attemptCount < maximumAttemptCount).then_some(solution);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Signer, maximumAttemptCount};
    use crate::FieldArithmetic;
    use crate::KeyGenerator;
    use crate::PublicMap;
    use crate::gf16::GF16;
    use crate::gf256::GF256;
    use crate::parameters::{Parameters, ovIII, ovIp, ovIs, ovV, secretSeedLength};
    use crate::testInputs::{hexadecimal, sequence};

    #[test]
    fn theFirstSuccessGivesItsResultExceptAtTheLastAttempt() {
        // Each attempt records its counter, and the attempt of one counter succeeds.
        let run = |succeeding: Option<u8>| {
            let mut counters = Vec::new();
            let result = Signer::firstSolution(|counter| {
                counters.push(counter);
                (Some(counter) == succeeding).then_some(counter)
            });
            (result, counters)
        };
        assert_eq!(run(Some(0)), (Some(0), vec![0]));
        let (result, counters) = run(Some(254));
        assert_eq!(result, Some(254));
        assert_eq!(counters, (0..=254).collect::<Vec<u8>>());
        // The attempt of the counter 255 succeeds, and the C loop still fails.
        let (result, counters) = run(Some(255));
        assert_eq!(result, None);
        assert_eq!(counters.len(), maximumAttemptCount);
        let (result, counters) = run(None);
        assert_eq!(result, None);
        assert_eq!(counters, (0..=255).collect::<Vec<u8>>());
    }

    /// The answers of the C program for a shape: `ov_sign` of the message 38 of 77 bytes with
    /// the salt 37, under the secret key of `expand_sk` of the seed 36, and under the random
    /// secret key 39. With the S of the random key zero, `ov_sign` returns -1 after drawing
    /// the salt, which the test checks for the shapes of `isZeroLinearBlockChecked`.
    fn checkShape<F: FieldArithmetic>(
        parameters: &Parameters,
        signature: &str,
        randomKeySignature: &str,
        isZeroLinearBlockChecked: bool,
    ) {
        let name = parameters.description.name;
        let salt: [u8; 16] = sequence(16, 37).try_into().expect("16 bytes");
        let message = sequence(77, 38);
        let seed = sequence(secretSeedLength, 36);
        let secretKey = KeyGenerator::expandedSecretKey::<F>(parameters, &seed);
        let signed = Signer::signature::<F>(parameters, secretKey.bytes(), &message, &salt)
            .expect("a signature");
        assert_eq!(hexadecimal(&signed), signature, "{name}");
        // `ov_verify` accepts it under the public key of the same seed.
        let seed: [u8; 32] = seed.try_into().expect("32 bytes");
        let (publicKey, _) = KeyGenerator::keyPair::<F>(parameters, &seed);
        assert!(PublicMap::isValidSignature::<F>(
            parameters, &signed, &message, &publicKey
        ));
        // A secret key of random bytes signs as in the C code.
        let randomKey = sequence(parameters.expandedSecretKeyLength(), 39);
        let signed =
            Signer::signature::<F>(parameters, &randomKey, &message, &salt).expect("a signature");
        assert_eq!(hexadecimal(&signed), randomKeySignature, "{name}");
        if !isZeroLinearBlockChecked {
            return;
        }
        // With S zero, each linear system is zero, so every attempt fails, as in the C code.
        let mut zeroKey = randomKey;
        let linearStart = zeroKey.len() - parameters.mixedBlockLength();
        zeroKey[linearStart..].fill(0);
        assert_eq!(
            Signer::signature::<F>(parameters, &zeroKey, &message, &salt),
            None,
            "{name}"
        );
    }

    #[test]
    fn signaturesOfTheShapeOfOVIsAreTheSignaturesOfTheCCode() {
        checkShape::<GF16>(
            &ovIs,
            "0595c2d369d8c8ea131de48d7fa0da1a82cd0891a8224dc9005df28b144f3876c1c360d63f2b9dd116be8ef0d2877cf2630119d84a89258bfe0ad808689fc031c79f71eaedc4a863cf1357f702ab183781f5393d1b60add8feafd15905f29c30",
            "c967efa6e3e688d7d96c9c506412c6417722b3e700c0e68f4cee70bf227bb680beba738b5376dc74bd33b2e23544f3644a85e9a8aef1a79bec1549deee246c1c7b7cfd540d59b6de2737656b70fbce7081f5393d1b60add8feafd15905f29c30",
            true,
        );
    }

    #[test]
    fn signaturesOfTheShapeOfOVIpAreTheSignaturesOfTheCCode() {
        checkShape::<GF256>(
            &ovIp,
            "6aeec948f05856b325e574f127f79ecf106cca0d50d0edb4dabe3819f1653ac5cf2edfbe0e0d68fa7ba0ecfedc3a505960d1efad3aca29d0197916960489b42bde412c201a29a276193a8670f10083e6010556fcfedd07e8d9e1e09f90f72662793b28cfbb2df7252d98c5503d772c6781f5393d1b60add8feafd15905f29c30",
            "f8e7e875bfb9f05fcb60cf2e1bbf72a4b7b7e432e8fd19eef2e3583f25f7b261cc627bb5c70ef4a172147fff6e75a7a0f088f79b4654753e924b1b9fd731e615d579ff15a1738c95037833ec34eac21aaacca9d7f7af0384eb12bc2e98fd1f808e4030dbb0496c6399f5c7c0fc919a6f81f5393d1b60add8feafd15905f29c30",
            true,
        );
    }

    #[test]
    fn signaturesOfTheShapeOfOVIIIAreTheSignaturesOfTheCCode() {
        checkShape::<GF256>(
            &ovIII,
            "e21cac0539016e520650f730db45c624a131fbb94c323411cc3026edaee38a516379dc05177643b237f5fee92eb03ca5058ae42b809cef76388fe7256bea58f6f990622b2a350ad5ce11245ffe84f82cd10a61f7ed5a9746863cd378adf7eb10dff88a0b4dd1147d7d715ba84ce410746fa8d992c816d19ad1bbce006493100a66540a4ee310ac80fd904a7f13ccb5da9d7475bcda9a2afb4cbc5196dd40df88980ef27a6cf02b384a5cfb887f487b7e9146c4816b8f70b181f5393d1b60add8feafd15905f29c30",
            "408e8d37c66e1f9fe167b7a85704dd7be299bf2338c1506990eee6485c4b1a3dc7324c8ac60e628952f35e9fc4d4e833a0875b94c7bcf21c6dd872abc9baa0a87b3ed744e467e8005ebf17d6541dd6cd30a8a1b71a5ef39973b3eeb186866af8dda3f5f2aefb6f67884a0e0d782b8925aee2471186133ce706bf77f4110ace691a3bffb074a9e54e8782b095ca203c40c7a72e39ef0e5993ae2d94cd3a1234bf469a182188173a9777a91efd3641fbcae489fa4a136aecf581f5393d1b60add8feafd15905f29c30",
            false,
        );
    }

    #[test]
    fn signaturesOfTheShapeOfOVVAreTheSignaturesOfTheCCode() {
        checkShape::<GF256>(
            &ovV,
            "c9bc7291cf2798b8e4c6f594622d4aa877773a4e262a74ac2c867231245b43431929cfdcd177e1e116264d7e095f22d37fcd0bc26535ad546dcc8c121007c91d35fc624ca28282bd8d532c2cfce5903a85d60a10da2427f178a24582f427546e9734718ddc8ef8d83c60f68ba334deac15869e74eb5b2dcccbef4dc539cad6618f2fcc6934cf647932978f96131b70e36525a0c6bf9a5d48fb32f6d2b93762b68d3928c4a3cc3d3c8b1c5e1786de84a312593ab9d196e31c07fb8524920d5fa5b76b557ea5589134fe0955ea8f3abfa686e07d8c70381dc128b0c11cf80ff835792482a47f4dda7df03ecc93881be9404304c1c981f5393d1b60add8feafd15905f29c30",
            "2b2206ae045473256b733380c34519a452a0df75890bcbefd6ab0616049e29099435e578de07d407c4f94bdb94b7695f05a0402e34471ac77aa0960dfc9d724a05a4dd70c55c47d70f037a377d81fc9873b1b914de7cc24864bcc5b8966a8d982a70fb468f9a525d21d7e904a4f5e0fa5a22e8427ce67a134e4cd138125a81d8e0697215d81a24726dcd4bfda72ae9c0995b549457704954520cbfa8357c5abbd72e13e73c23d5ae816186428ccf669bb5c037144120f96421fb67db3922c2d00d61acf2a288a498504c8641068144d9778c7eb83d1812634b8ab99357f9b23710fe17417d49a28ba4f4c627be0d711b052e377381f5393d1b60add8feafd15905f29c30",
            false,
        );
    }
}
