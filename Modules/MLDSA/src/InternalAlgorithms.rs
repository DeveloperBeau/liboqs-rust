use crate::Parameters;
use crate::parameters::{packedHighLength, packedLowLength, representativeLength, seedLength};
use crate::polynomial::{Polynomial, droppedBits, isHint};
use OQSNativeSHA3::SHAKE256;
use alloc::vec;
use alloc::vec::Vec;

/// The internal algorithms of FIPS 204, Section 6, of one parameter set, as mldsa-native
/// computes them: the key pair of a seed, the signature of a message representative with given
/// randomness, and the verification of a signature.
pub(crate) struct InternalAlgorithms<'parameters> {
    parameters: &'parameters Parameters,
}

/// The matrix A of ExpandA, FIPS 204, Algorithm 32, as rows of polynomials in the NTT domain.
type Matrix = Vec<Vec<Polynomial>>;

/// The secret key parts that a signature uses, as `mld_unpack_sk` gives them: the seeds and
/// the vectors s1, s2 and t0 in the NTT domain.
struct SigningKey {
    publicSeed: [u8; seedLength],
    signingSeed: [u8; seedLength],
    shortVector: Vec<Polynomial>,
    errorVector: Vec<Polynomial>,
    lowVector: Vec<Polynomial>,
}

impl<'parameters> InternalAlgorithms<'parameters> {
    /// Makes the algorithms of a parameter set.
    pub(crate) fn new(parameters: &'parameters Parameters) -> Self {
        InternalAlgorithms { parameters }
    }

    /// The SHAKE256 of the parts of an input, of a length, as `mld_H` computes it.
    fn hash(parts: &[&[u8]], output: &mut [u8]) {
        let mut sponge = SHAKE256::new();
        for part in parts {
            sponge.absorb(part);
        }
        sponge.finalize().squeeze(output);
    }

    /// The hash tr of a public key: its SHAKE256 of 64 bytes.
    pub(crate) fn publicKeyHash(publicKey: &[u8]) -> [u8; representativeLength] {
        let mut hash = [0u8; representativeLength];
        Self::hash(&[publicKey], &mut hash);
        hash
    }

    /// The message representative mu of FIPS 204, Algorithm 7, line 6: the SHAKE256 of tr, the
    /// prefix and the message, 64 bytes.
    pub(crate) fn messageRepresentative(
        publicKeyHash: &[u8],
        prefix: &[u8],
        message: &[u8],
    ) -> [u8; representativeLength] {
        let mut representative = [0u8; representativeLength];
        Self::hash(&[publicKeyHash, prefix, message], &mut representative);
        representative
    }

    /// The matrix of a public seed: `A[row][column] = RejNTTPoly(rho || column || row)`, as
    /// `mld_polyvec_matrix_expand` samples it.
    fn matrix(&self, publicSeed: &[u8; seedLength]) -> Matrix {
        (0..self.parameters.rowCount)
            .map(|row| {
                (0..self.parameters.columnCount)
                    .map(|column| Polynomial::sampledUniform(publicSeed, column as u8, row as u8))
                    .collect()
            })
            .collect()
    }

    /// Copies of polynomials, each in the NTT domain.
    fn transformed(vector: &[Polynomial]) -> Vec<Polynomial> {
        vector
            .iter()
            .map(|polynomial| {
                let mut transformed = *polynomial;
                transformed.transform();
                transformed
            })
            .collect()
    }

    /// The ML-DSA.KeyGen_internal of FIPS 204, Algorithm 6, as `mld_sign_keypair_internal`:
    /// the public key and the secret key of a 32-byte seed.
    pub(crate) fn keyPair(&self, seed: &[u8; seedLength]) -> (Vec<u8>, Vec<u8>) {
        let parameters = self.parameters;
        let (rowCount, columnCount) = (parameters.rowCount, parameters.columnCount);
        let mut expanded = [0u8; 2 * seedLength + representativeLength];
        Self::hash(&[seed, &[rowCount as u8, columnCount as u8]], &mut expanded);
        let publicSeed: [u8; seedLength] = expanded[..seedLength].try_into().expect("32 bytes");
        let noiseSeed: [u8; representativeLength] = expanded
            [seedLength..seedLength + representativeLength]
            .try_into()
            .expect("64 bytes");
        let signingSeed = &expanded[seedLength + representativeLength..];
        let eta = parameters.eta;
        let shortVector: Vec<Polynomial> = (0..columnCount)
            .map(|index| Polynomial::sampledShort(eta, &noiseSeed, index as u8))
            .collect();
        let errorVector: Vec<Polynomial> = (0..rowCount)
            .map(|index| Polynomial::sampledShort(eta, &noiseSeed, (columnCount + index) as u8))
            .collect();
        let shortTransformed = Self::transformed(&shortVector);
        let matrix = self.matrix(&publicSeed);
        let mut publicKey = vec![0u8; parameters.description.publicKeyLength];
        publicKey[..seedLength].copy_from_slice(&publicSeed);
        let mut lowPacked = vec![0u8; packedLowLength * rowCount];
        let highChunks = publicKey[seedLength..].chunks_exact_mut(packedHighLength);
        let lowChunks = lowPacked.chunks_exact_mut(packedLowLength);
        for (((matrixRow, error), highChunk), lowChunk) in matrix
            .iter()
            .zip(&errorVector)
            .zip(highChunks)
            .zip(lowChunks)
        {
            // t = A s1 + s2, row by row, as `mld_compute_pack_t0_t1` computes it.
            let mut product = Polynomial::innerProduct(matrixRow, &shortTransformed);
            product.inverseTransform();
            let (high, low) = product.plus(error).reduced().nonNegative().power2Rounded();
            high.simplePacked(10, highChunk);
            low.boundPacked(1 << (droppedBits - 1), droppedBits, lowChunk);
        }
        let publicKeyHash = Self::publicKeyHash(&publicKey);
        let shortLength = parameters.packedShortLength();
        let shortBits = Parameters::etaBits(eta);
        let mut secretKey = Vec::with_capacity(parameters.description.secretKeyLength);
        secretKey.extend_from_slice(&publicSeed);
        secretKey.extend_from_slice(signingSeed);
        secretKey.extend_from_slice(&publicKeyHash);
        let mut packed = vec![0u8; shortLength];
        for polynomial in shortVector.iter().chain(&errorVector) {
            polynomial.boundPacked(eta, shortBits, &mut packed);
            secretKey.extend_from_slice(&packed);
        }
        secretKey.extend_from_slice(&lowPacked);
        (publicKey, secretKey)
    }

    /// The parts of a secret key of the right length, as `mld_unpack_sk` reads them. The
    /// decoding checks no range, as in the C code.
    fn signingKey(&self, secretKey: &[u8]) -> SigningKey {
        let parameters = self.parameters;
        let (rowCount, columnCount) = (parameters.rowCount, parameters.columnCount);
        let eta = parameters.eta;
        let shortLength = parameters.packedShortLength();
        let shortBits = Parameters::etaBits(eta);
        let shortStart = 2 * seedLength + representativeLength;
        let errorStart = shortStart + columnCount * shortLength;
        let lowStart = errorStart + rowCount * shortLength;
        let decoded = |bytes: &[u8], chunkLength: usize, bound: i32, bits: u32| {
            bytes
                .chunks_exact(chunkLength)
                .map(|chunk| {
                    let mut polynomial = Polynomial::boundUnpacked(bound, bits, chunk);
                    polynomial.transform();
                    polynomial
                })
                .collect::<Vec<_>>()
        };
        SigningKey {
            publicSeed: secretKey[..seedLength].try_into().expect("32 bytes"),
            signingSeed: secretKey[seedLength..2 * seedLength]
                .try_into()
                .expect("32 bytes"),
            shortVector: decoded(
                &secretKey[shortStart..errorStart],
                shortLength,
                eta,
                shortBits,
            ),
            errorVector: decoded(
                &secretKey[errorStart..lowStart],
                shortLength,
                eta,
                shortBits,
            ),
            lowVector: decoded(
                &secretKey[lowStart..],
                packedLowLength,
                1 << (droppedBits - 1),
                droppedBits,
            ),
        }
    }

    /// The ML-DSA.Sign_internal of FIPS 204, Algorithm 7, as `mld_sign_signature_internal`:
    /// the signature of a message representative mu under a secret key of the right length,
    /// with 32 bytes of randomness.
    ///
    /// Returns `None` when every attempt of the rejection loop fails, the
    /// `MLD_ERR_SIGN_ATTEMPTS_EXHAUSTED` of the C code.
    pub(crate) fn signature(
        &self,
        secretKey: &[u8],
        representative: &[u8; representativeLength],
        randomness: &[u8; seedLength],
    ) -> Option<Vec<u8>> {
        let columnCount = self.parameters.columnCount;
        let key = self.signingKey(secretKey);
        let mut maskSeed = [0u8; representativeLength];
        Self::hash(
            &[&key.signingSeed, randomness, representative],
            &mut maskSeed,
        );
        let matrix = self.matrix(&key.publicSeed);
        // `MLD_NONCE_UB`: the masks of the last attempt use nonces below 2^16.
        let attemptCount = (usize::from(u16::MAX) - columnCount) / columnCount;
        (0..attemptCount).find_map(|attempt| {
            self.attemptedSignature(representative, &maskSeed, attempt as u16, &matrix, &key)
        })
    }

    /// One attempt of the rejection loop, as `mld_attempt_signature_generation`: the signature
    /// of the mask of a nonce, or `None` when a norm check or the hint count rejects it.
    fn attemptedSignature(
        &self,
        representative: &[u8; representativeLength],
        maskSeed: &[u8; representativeLength],
        attempt: u16,
        matrix: &Matrix,
        key: &SigningKey,
    ) -> Option<Vec<u8>> {
        let parameters = self.parameters;
        let columnCount = parameters.columnCount;
        let gamma1 = 1 << parameters.gamma1Bits;
        let gamma2 = parameters.gamma2;
        let beta = parameters.beta;
        let firstNonce = columnCount as u16 * attempt;
        let mask: Vec<Polynomial> = (0..columnCount)
            .map(|index| {
                Polynomial::sampledMask(parameters.gamma1Bits, maskSeed, firstNonce + index as u16)
            })
            .collect();
        let maskTransformed = Self::transformed(&mask);
        let (high, mut low): (Vec<Polynomial>, Vec<Polynomial>) = matrix
            .iter()
            .map(|matrixRow| {
                let mut commitment = Polynomial::innerProduct(matrixRow, &maskTransformed);
                commitment.inverseTransform();
                commitment.nonNegative().decomposed(gamma2)
            })
            .unzip();
        let commitmentLength = parameters.packedCommitmentLength();
        let mut highPacked = vec![0u8; commitmentLength * parameters.rowCount];
        for (polynomial, chunk) in high
            .iter()
            .zip(highPacked.chunks_exact_mut(commitmentLength))
        {
            polynomial.simplePacked(parameters.commitmentBits(), chunk);
        }
        let hashLength = parameters.commitmentHashLength;
        let mut signature = vec![0u8; parameters.description.signatureLength];
        Self::hash(&[representative, &highPacked], &mut signature[..hashLength]);
        let mut challenge = Polynomial::sampledInBall(parameters.tau, &signature[..hashLength]);
        challenge.transform();
        // z = y + c s1, as `mld_compute_pack_z` computes and packs it.
        let maskLength = parameters.packedMaskLength();
        let responseChunks = signature[hashLength..hashLength + columnCount * maskLength]
            .chunks_exact_mut(maskLength);
        for ((secret, maskPolynomial), chunk) in
            key.shortVector.iter().zip(&mask).zip(responseChunks)
        {
            let mut product = secret.transformedProduct(&challenge);
            product.inverseTransform();
            let response = product.plus(maskPolynomial).reduced();
            if !response.isNormBelow(gamma1 - beta) {
                return None;
            }
            response.boundPacked(gamma1, parameters.maskBits(), chunk);
        }
        // w0 - c s2 + c t0, row by row, with the norm checks of each row.
        for ((lowRow, error), lowPart) in low.iter_mut().zip(&key.errorVector).zip(&key.lowVector) {
            let mut product = error.transformedProduct(&challenge);
            product.inverseTransform();
            *lowRow = lowRow.minus(&product).reduced();
            if !lowRow.isNormBelow(gamma2 - beta) {
                return None;
            }
            let mut product = lowPart.transformedProduct(&challenge);
            product.inverseTransform();
            let product = product.reduced();
            if !product.isNormBelow(gamma2) {
                return None;
            }
            *lowRow = lowRow.plus(&product);
        }
        let hintStart = hashLength + columnCount * maskLength;
        self.packedHints(&low, &high, &mut signature[hintStart..])
            .then_some(signature)
    }

    /// The HintBitPack of FIPS 204, Algorithm 20, as `mld_pack_sig_h` computes it: the places
    /// of the hint bits of each row and the running count after each row. False when there are
    /// more than omega hint bits.
    fn packedHints(&self, low: &[Polynomial], high: &[Polynomial], output: &mut [u8]) -> bool {
        let omega = self.parameters.omega;
        let gamma2 = self.parameters.gamma2;
        output.fill(0);
        let mut count = 0;
        for (row, (lowRow, highRow)) in low.iter().zip(high).enumerate() {
            for (place, (lowValue, highValue)) in lowRow
                .coefficients
                .iter()
                .zip(highRow.coefficients)
                .enumerate()
            {
                if isHint(*lowValue, highValue, gamma2) {
                    if count == omega {
                        return false;
                    }
                    output[count] = place as u8;
                    count += 1;
                }
            }
            output[omega + row] = count as u8;
        }
        true
    }

    /// The HintBitUnpack of FIPS 204, Algorithm 21, with the checks of `mld_sig_unpack_hints`:
    /// the hint polynomials, or `None` when a count falls or passes omega, when the places of a
    /// row do not rise, or when a byte after the last place is not zero.
    fn unpackedHints(&self, packed: &[u8]) -> Option<Vec<Polynomial>> {
        let omega = self.parameters.omega;
        let mut hints = vec![Polynomial::zero; self.parameters.rowCount];
        let mut previousCount = 0;
        for (row, hint) in hints.iter_mut().enumerate() {
            let count = usize::from(packed[omega + row]);
            if count < previousCount || count > omega {
                return None;
            }
            for index in previousCount..count {
                if index > previousCount && packed[index] <= packed[index - 1] {
                    return None;
                }
                hint.coefficients[usize::from(packed[index])] = 1;
            }
            previousCount = count;
        }
        packed[previousCount..omega]
            .iter()
            .all(|byte| *byte == 0)
            .then_some(hints)
    }

    /// The ML-DSA.Verify_internal of FIPS 204, Algorithm 8, as `mld_sign_verify_internal`:
    /// true when a signature of a message representative mu is valid for a public key. A
    /// signature or a public key of a wrong length is not valid.
    pub(crate) fn isValidSignature(
        &self,
        signature: &[u8],
        publicKey: &[u8],
        representative: &[u8; representativeLength],
    ) -> bool {
        let parameters = self.parameters;
        let description = &parameters.description;
        if signature.len() != description.signatureLength
            || publicKey.len() != description.publicKeyLength
        {
            return false;
        }
        let columnCount = parameters.columnCount;
        let gamma1 = 1 << parameters.gamma1Bits;
        let hashLength = parameters.commitmentHashLength;
        let maskLength = parameters.packedMaskLength();
        let hintStart = hashLength + columnCount * maskLength;
        let mut response: Vec<Polynomial> = signature[hashLength..hintStart]
            .chunks_exact(maskLength)
            .map(|chunk| Polynomial::boundUnpacked(gamma1, parameters.maskBits(), chunk))
            .collect();
        // The check of every polynomial, with no early exit, as `mld_polyvecl_chknorm`.
        let isResponseShort = response.iter().fold(true, |isShort, polynomial| {
            isShort & polynomial.isNormBelow(gamma1 - parameters.beta)
        });
        if !isResponseShort {
            return false;
        }
        let Some(hints) = self.unpackedHints(&signature[hintStart..]) else {
            return false;
        };
        for polynomial in response.iter_mut() {
            polynomial.transform();
        }
        let publicSeed: [u8; seedLength] = publicKey[..seedLength].try_into().expect("32 bytes");
        let matrix = self.matrix(&publicSeed);
        let mut challenge = Polynomial::sampledInBall(parameters.tau, &signature[..hashLength]);
        challenge.transform();
        let commitmentLength = parameters.packedCommitmentLength();
        let mut highPacked = vec![0u8; commitmentLength * parameters.rowCount];
        let highChunks = publicKey[seedLength..].chunks_exact(packedHighLength);
        for (((matrixRow, highChunk), hint), chunk) in matrix
            .iter()
            .zip(highChunks)
            .zip(&hints)
            .zip(highPacked.chunks_exact_mut(commitmentLength))
        {
            // w' = A z - c t1 2^d, row by row, as the loop of `mld_sign_verify_internal`.
            let product = Polynomial::innerProduct(matrixRow, &response);
            let mut scaledHigh = Polynomial::simpleUnpacked(10, highChunk).shiftedLeft();
            scaledHigh.transform();
            let mut approximation = product
                .minus(&scaledHigh.transformedProduct(&challenge))
                .reduced();
            approximation.inverseTransform();
            approximation
                .nonNegative()
                .hintedHigh(hint, parameters.gamma2)
                .simplePacked(parameters.commitmentBits(), chunk);
        }
        let mut commitmentHash = [0u8; 64];
        let commitmentHash = &mut commitmentHash[..hashLength];
        Self::hash(&[representative, &highPacked], commitmentHash);
        // The comparison has no branch on the bytes, as `mld_ct_memcmp`.
        let differences = commitmentHash
            .iter()
            .zip(&signature[..hashLength])
            .fold(0u8, |accumulated, (left, right)| {
                accumulated | (left ^ right)
            });
        differences == 0
    }
}

#[cfg(test)]
mod tests {
    use super::InternalAlgorithms;
    use crate::parameters::{mldsa44, mldsa65, mldsa87};
    use crate::polynomial::{Polynomial, coefficientCount};

    #[test]
    fn hintsPackAndUnpackAsTheirPlacesAndRunningCounts() {
        let algorithms = InternalAlgorithms::new(&mldsa44);
        let gamma2 = mldsa44.gamma2;
        let mut low = vec![Polynomial::zero; 4];
        let high = vec![Polynomial::zero; 4];
        // A low value above gamma2 is a hint, gamma2 itself is not.
        low[0].coefficients[3] = gamma2 + 1;
        low[0].coefficients[4] = gamma2;
        low[2].coefficients[0] = -gamma2 - 1;
        low[2].coefficients[255] = gamma2 + 5;
        let mut packed = vec![0u8; 84];
        assert!(algorithms.packedHints(&low, &high, &mut packed));
        assert_eq!(&packed[..4], &[3, 0, 255, 0]);
        assert!(packed[4..80].iter().all(|byte| *byte == 0));
        assert_eq!(&packed[80..], &[1, 1, 3, 3]);
        let hints = algorithms.unpackedHints(&packed).expect("valid hints");
        let ones: Vec<(usize, usize)> = hints
            .iter()
            .enumerate()
            .flat_map(|(row, hint)| {
                (0..coefficientCount)
                    .filter(move |place| hint.coefficients[*place] == 1)
                    .map(move |place| (row, place))
            })
            .collect();
        assert_eq!(ones, vec![(0, 3), (2, 0), (2, 255)]);
    }

    #[test]
    fn hintPackingRefusesMoreThanOmegaHints() {
        let algorithms = InternalAlgorithms::new(&mldsa44);
        let mut low = vec![Polynomial::zero; 4];
        let high = vec![Polynomial::zero; 4];
        for place in 0..80 {
            low[1].coefficients[place] = mldsa44.gamma2 + 1;
        }
        let mut packed = vec![0u8; 84];
        assert!(algorithms.packedHints(&low, &high, &mut packed));
        low[3].coefficients[0] = mldsa44.gamma2 + 1;
        assert!(!algorithms.packedHints(&low, &high, &mut packed));
    }

    #[test]
    fn hintUnpackingRefusesEachMalformedEncodingOfMLDSANative() {
        let algorithms = InternalAlgorithms::new(&mldsa65);
        let omega = mldsa65.omega;
        let valid = |places: &[u8], counts: [u8; 6]| {
            let mut packed = vec![0u8; omega + 6];
            packed[..places.len()].copy_from_slice(places);
            packed[omega..].copy_from_slice(&counts);
            packed
        };
        let good = valid(&[2, 9, 4], [2, 2, 3, 3, 3, 3]);
        assert!(algorithms.unpackedHints(&good).is_some());
        // A count that falls, also when the places of the next row still rise.
        assert!(
            algorithms
                .unpackedHints(&valid(&[2, 9, 4], [2, 1, 3, 3, 3, 3]))
                .is_none()
        );
        assert!(
            algorithms
                .unpackedHints(&valid(&[2, 9, 12], [2, 1, 3, 3, 3, 3]))
                .is_none()
        );
        assert!(
            algorithms
                .unpackedHints(&valid(&[2, 9, 12], [2, 2, 3, 3, 3, 3]))
                .is_some()
        );
        // A count above omega.
        let mut tooMany = good.clone();
        tooMany[omega + 5] = omega as u8 + 1;
        assert!(algorithms.unpackedHints(&tooMany).is_none());
        // A count of exactly omega is allowed.
        let mut full = vec![0u8; omega + 6];
        for (index, byte) in full[..omega].iter_mut().enumerate() {
            *byte = index as u8;
        }
        full[omega..].copy_from_slice(&[omega as u8; 6]);
        assert!(algorithms.unpackedHints(&full).is_some());
        // A count of omega + 1 is refused, also when the places would still rise into the
        // first count byte.
        full[omega..].copy_from_slice(&[omega as u8 + 1; 6]);
        assert!(algorithms.unpackedHints(&full).is_none());
        // Places of a row that repeat or fall.
        assert!(
            algorithms
                .unpackedHints(&valid(&[9, 9, 4], [2, 2, 3, 3, 3, 3]))
                .is_none()
        );
        assert!(
            algorithms
                .unpackedHints(&valid(&[9, 2, 4], [2, 2, 3, 3, 3, 3]))
                .is_none()
        );
        // A place may fall from one row to the next.
        assert!(
            algorithms
                .unpackedHints(&valid(&[2, 9, 1], [2, 2, 3, 3, 3, 3]))
                .is_some()
        );
        // A byte after the last place that is not zero.
        let mut padded = good.clone();
        padded[omega - 1] = 1;
        assert!(algorithms.unpackedHints(&padded).is_none());
    }

    #[test]
    fn keyPairsHaveTheLayoutOfFIPS204() {
        for parameters in [&mldsa44, &mldsa65, &mldsa87] {
            let algorithms = InternalAlgorithms::new(parameters);
            let (publicKey, secretKey) = algorithms.keyPair(&[7u8; 32]);
            assert_eq!(publicKey.len(), parameters.description.publicKeyLength);
            assert_eq!(secretKey.len(), parameters.description.secretKeyLength);
            // The secret key starts with rho, as the public key, and holds tr = H(pk).
            assert_eq!(&secretKey[..32], &publicKey[..32]);
            assert_eq!(
                &secretKey[64..128],
                InternalAlgorithms::publicKeyHash(&publicKey).as_slice()
            );
            assert_ne!(algorithms.keyPair(&[8u8; 32]).0, publicKey);
        }
    }
}
