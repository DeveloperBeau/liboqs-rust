use crate::chaChaRandom::ChaChaRandom;
use crate::floatingPoint::FloatingPoint;
use crate::fourierTransform::FourierTransform;
use crate::gaussianSampler::GaussianSampler;
use crate::secretBasis::SecretBasis;
use crate::signatureNorm::SignatureNorm;
use OQSNativeSHA3::SHAKEReader;
use alloc::vec;
use alloc::vec::Vec;

/// The computation of the short vector of a signature, `sign_dyn` of `sign.c` of the Falcon
/// code of PQClean, which builds the Gram matrix and the LDL tree of the secret basis on the fly.
///
/// The target vector `(c0 / q) [F, -f]` of the hashed message `c0` goes through fast Fourier
/// sampling over the basis `B = [[g, -f], [G, -F]]`, which gives a lattice point close to it.
/// The difference `(s1, s2)` is short, and the signature keeps `s2`. A vector above the norm
/// bound starts again with a new sampler seeded from the same SHAKE256 stream, as in the C code.
pub(crate) struct Signer;

/// `1 / q`.
const inverseOfModulus: FloatingPoint = FloatingPoint::fromBits(4_545_632_735_260_551_042);

/// `1 / sigma` for each `logn` from 1 to 10, `fpr_inv_sigma` of `fpr.h`.
const inverseSigmas: [FloatingPoint; 11] = [
    FloatingPoint::fromBits(0),
    FloatingPoint::fromBits(4_574_611_497_772_390_042),
    FloatingPoint::fromBits(4_574_501_679_055_810_265),
    FloatingPoint::fromBits(4_574_396_282_908_341_804),
    FloatingPoint::fromBits(4_574_245_855_758_572_086),
    FloatingPoint::fromBits(4_574_103_865_040_221_165),
    FloatingPoint::fromBits(4_573_969_550_563_515_544),
    FloatingPoint::fromBits(4_573_842_244_705_920_822),
    FloatingPoint::fromBits(4_573_721_358_406_441_454),
    FloatingPoint::fromBits(4_573_606_369_665_796_042),
    FloatingPoint::fromBits(4_573_496_814_039_276_259),
];

/// The minimum standard deviation `sigma_min` for each `logn` from 1 to 10, `fpr_sigma_min` of
/// `fpr.h`.
const sigmaMinimums: [FloatingPoint; 11] = [
    FloatingPoint::fromBits(0),
    FloatingPoint::fromBits(4_607_707_126_469_777_035),
    FloatingPoint::fromBits(4_607_777_455_861_499_430),
    FloatingPoint::fromBits(4_607_846_828_256_951_418),
    FloatingPoint::fromBits(4_607_949_175_006_100_261),
    FloatingPoint::fromBits(4_608_049_571_757_433_526),
    FloatingPoint::fromBits(4_608_148_125_896_792_003),
    FloatingPoint::fromBits(4_608_244_935_301_382_692),
    FloatingPoint::fromBits(4_608_340_089_478_362_016),
    FloatingPoint::fromBits(4_608_433_670_533_905_013),
    FloatingPoint::fromBits(4_608_525_754_002_622_308),
];

/// The first slots of `N` values of a workspace, as separate polynomials.
fn slots<const Count: usize>(
    workspace: &mut [FloatingPoint],
    n: usize,
) -> [&mut [FloatingPoint]; Count] {
    let mut chunks = workspace.chunks_exact_mut(n);
    core::array::from_fn(|_| chunks.next().expect("a slot of the workspace"))
}

/// Writes the values of small integers into a polynomial, as `smallints_to_fpr` does.
fn loadSmall(values: &mut [FloatingPoint], integers: &[i8]) {
    for (value, integer) in values.iter_mut().zip(integers) {
        *value = FloatingPoint::of(i64::from(*integer));
    }
}

impl Signer {
    /// The vector `s2` of a signature of a hashed message, as `sign_dyn` does. Each attempt
    /// seeds a new sampler with the next 56 bytes of the stream.
    pub(crate) fn signatureVector(
        reader: &mut SHAKEReader,
        basis: &SecretBasis<'_>,
        hashedMessage: &[u16],
        logn: u32,
    ) -> Vec<i16> {
        let mut workspace = vec![FloatingPoint::zero; 9 << logn];
        loop {
            let mut sampler =
                GaussianSampler::new(ChaChaRandom::seeded(reader), sigmaMinimums[logn as usize]);
            if let Some(vector) =
                Self::shortVector(&mut sampler, basis, hashedMessage, logn, &mut workspace)
            {
                return vector;
            }
        }
    }

    /// Loads the basis `[[g, -f], [G, -F]]` into the first four polynomials of the workspace,
    /// in the transform: `b00 = g`, `b01 = -f`, `b10 = G` and `b11 = -F`.
    fn loadBasis(workspace: &mut [FloatingPoint], basis: &SecretBasis<'_>, logn: u32) {
        let n = 1usize << logn;
        loadSmall(&mut workspace[n..2 * n], basis.f);
        loadSmall(&mut workspace[..n], basis.g);
        loadSmall(&mut workspace[3 * n..4 * n], basis.bigF);
        loadSmall(&mut workspace[2 * n..3 * n], basis.bigG);
        for start in [n, 0, 3 * n, 2 * n] {
            FourierTransform::transform(&mut workspace[start..start + n], logn);
        }
        FourierTransform::negate(&mut workspace[n..2 * n], logn);
        FourierTransform::negate(&mut workspace[3 * n..4 * n], logn);
    }

    /// One attempt of `do_sign_dyn`: the vector `s2` when `(s1, s2)` is short, and else `None`.
    /// The workspace holds nine polynomials, in the layout of the C code.
    fn shortVector(
        sampler: &mut GaussianSampler,
        basis: &SecretBasis<'_>,
        hashedMessage: &[u16],
        logn: u32,
        workspace: &mut [FloatingPoint],
    ) -> Option<Vec<i16>> {
        let n = 1usize << logn;
        Self::loadBasis(workspace, basis, logn);
        // The Gram matrix G = B B*: g00, g01 and g11 replace b00, b01 and b10, and slot 4
        // keeps a copy of b01.
        {
            let [b00, b01, b10, b11, t0, t1, ..] = slots::<9>(workspace, n);
            t0.copy_from_slice(b01);
            FourierTransform::multiplyBySelfAdjoint(t0, logn);
            t1.copy_from_slice(b00);
            FourierTransform::multiplyByAdjoint(t1, b10, logn);
            FourierTransform::multiplyBySelfAdjoint(b00, logn);
            FourierTransform::add(b00, t0, logn);
            t0.copy_from_slice(b01);
            FourierTransform::multiplyByAdjoint(b01, b11, logn);
            FourierTransform::add(b01, t1, logn);
            FourierTransform::multiplyBySelfAdjoint(b10, logn);
            t1.copy_from_slice(b11);
            FourierTransform::multiplyBySelfAdjoint(t1, logn);
            FourierTransform::add(b10, t1, logn);
        }
        // The target vector [hm, 0] B^-1 = (hm / q) [-F, f], from b11 at slot 3 and the copy of
        // b01 at slot 4, into slots 5 and 6, which then move to slots 3 and 4.
        {
            let [_, _, _, b11, b01, t0, t1, ..] = slots::<9>(workspace, n);
            for (value, hashed) in t0.iter_mut().zip(hashedMessage) {
                *value = FloatingPoint::of(i64::from(*hashed));
            }
            FourierTransform::transform(t0, logn);
            t1.copy_from_slice(t0);
            FourierTransform::multiply(t1, b01, logn);
            FourierTransform::multiplyByConstant(t1, -inverseOfModulus, logn);
            FourierTransform::multiply(t0, b11, logn);
            FourierTransform::multiplyByConstant(t0, inverseOfModulus, logn);
        }
        workspace.copy_within(5 * n..7 * n, 3 * n);
        // Fast Fourier sampling of the target over the Gram matrix, with the four last slots as
        // scratch space.
        {
            let (front, scratch) = workspace.split_at_mut(5 * n);
            let [g00, g01, g11, t0, t1] = slots::<5>(front, n);
            Self::sampleTree(sampler, t0, t1, g00, g01, g11, logn, logn, scratch);
        }
        // The lattice point of the sampled vector, with the basis loaded again: the sampled
        // vector moves to slots 4 and 5.
        workspace.copy_within(3 * n..5 * n, 4 * n);
        Self::loadBasis(workspace, basis, logn);
        {
            let [b00, b01, b10, b11, t0, t1, tx, ty, _] = slots::<9>(workspace, n);
            tx.copy_from_slice(t0);
            ty.copy_from_slice(t1);
            FourierTransform::multiply(tx, b00, logn);
            FourierTransform::multiply(ty, b10, logn);
            FourierTransform::add(tx, ty, logn);
            ty.copy_from_slice(t0);
            FourierTransform::multiply(ty, b01, logn);
            t0.copy_from_slice(tx);
            FourierTransform::multiply(t1, b11, logn);
            FourierTransform::add(t1, ty, logn);
            FourierTransform::inverseTransform(t0, logn);
            FourierTransform::inverseTransform(t1, logn);
        }
        // s1 = hm - t0 with its saturated squared norm, and s2 = -t1.
        let [_, _, _, _, t0, t1, ..] = slots::<9>(workspace, n);
        let mut squaredNorm = 0u32;
        let mut overflow = 0u32;
        for (hashed, value) in hashedMessage.iter().zip(t0.iter()) {
            let z = i32::from(*hashed).wrapping_sub(value.roundedToNearest() as i32);
            squaredNorm = squaredNorm.wrapping_add(z.wrapping_mul(z) as u32);
            overflow |= squaredNorm;
        }
        squaredNorm |= (overflow >> 31).wrapping_neg();
        let second: Vec<i16> = t1
            .iter()
            .map(|value| value.roundedToNearest().wrapping_neg() as i16)
            .collect();
        SignatureNorm::isShortHalf(squaredNorm, &second, logn).then_some(second)
    }

    /// Fast Fourier sampling of a target `(t0, t1)` over the Gram matrix
    /// `[[g00, g01], [adj(g01), g11]]`, with the LDL tree computed at each level, as
    /// `ffSampling_fft_dyntree` does. The sampled vector replaces the target, and the matrix is
    /// changed. The scratch space holds at least `4 N - 2` values.
    #[allow(clippy::too_many_arguments)]
    fn sampleTree(
        sampler: &mut GaussianSampler,
        t0: &mut [FloatingPoint],
        t1: &mut [FloatingPoint],
        g00: &mut [FloatingPoint],
        g01: &mut [FloatingPoint],
        g11: &mut [FloatingPoint],
        originalLogn: u32,
        logn: u32,
        scratch: &mut [FloatingPoint],
    ) {
        if logn == 0 {
            // The leaf of the tree is g00, normalized by sigma.
            let leaf = g00[0].squareRoot() * inverseSigmas[originalLogn as usize];
            t0[0] = FloatingPoint::of(i64::from(sampler.sample(t0[0], leaf)));
            t1[0] = FloatingPoint::of(i64::from(sampler.sample(t1[0], leaf)));
            return;
        }
        let n = 1usize << logn;
        let hn = n >> 1;
        // The LDL decomposition in place: g00 = d00, g01 = l10 and g11 = d11. Then d00 and d11
        // split into the half-size Gram matrices of the two subtrees, and l10 goes to the
        // scratch space.
        FourierTransform::decomposeLDL(g00, g01, g11, logn);
        let (l10, rest) = scratch.split_at_mut(n);
        {
            let (low, high) = l10.split_at_mut(hn);
            FourierTransform::split(low, high, g00, logn);
        }
        g00[..n].copy_from_slice(l10);
        {
            let (low, high) = l10.split_at_mut(hn);
            FourierTransform::split(low, high, g11, logn);
        }
        g11[..n].copy_from_slice(l10);
        l10.copy_from_slice(&g01[..n]);
        g01[..hn].copy_from_slice(&g00[..hn]);
        g01[hn..n].copy_from_slice(&g11[..hn]);
        // The right subtree samples the split t1, and the result merges at offset 2 N.
        let (z1, rest) = rest.split_at_mut(n);
        {
            let (z1Low, z1High) = z1.split_at_mut(hn);
            FourierTransform::split(z1Low, z1High, t1, logn);
            let (g11Low, g11High) = g11.split_at_mut(hn);
            Self::sampleTree(
                sampler,
                z1Low,
                z1High,
                g11Low,
                g11High,
                &mut g01[hn..n],
                originalLogn,
                logn - 1,
                rest,
            );
        }
        let merged = &mut rest[..n];
        FourierTransform::merge(merged, &z1[..hn], &z1[hn..], logn);
        // tb0 = t0 + (t1 - z1) l10, and z1 replaces t1.
        z1.copy_from_slice(&t1[..n]);
        FourierTransform::subtract(z1, merged, logn);
        t1[..n].copy_from_slice(merged);
        FourierTransform::multiply(l10, z1, logn);
        FourierTransform::add(t0, l10, logn);
        // The left subtree samples the split tb0.
        let (z0, rest) = scratch.split_at_mut(n);
        {
            let (z0Low, z0High) = z0.split_at_mut(hn);
            FourierTransform::split(z0Low, z0High, t0, logn);
            let (g00Low, g00High) = g00.split_at_mut(hn);
            Self::sampleTree(
                sampler,
                z0Low,
                z0High,
                g00Low,
                g00High,
                &mut g01[..hn],
                originalLogn,
                logn - 1,
                rest,
            );
        }
        FourierTransform::merge(t0, &z0[..hn], &z0[hn..], logn);
    }
}

#[cfg(test)]
mod tests {
    use super::{Signer, sigmaMinimums};
    use crate::chaChaRandom::ChaChaRandom;
    use crate::floatingPoint::FloatingPoint;
    use crate::gaussianSampler::GaussianSampler;
    use crate::keyGenerator::KeyGenerator;
    use crate::modularPolynomial::ModularPolynomial;
    use crate::secretBasis::SecretBasis;
    use OQSNativeSHA3::SHAKE256;

    /// The FNV-1a hash of bytes, the digest that the C program of the known answers prints.
    fn digest(bytes: impl IntoIterator<Item = u8>) -> u64 {
        bytes
            .into_iter()
            .fold(0xCBF2_9CE4_8422_2325u64, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01B3)
            })
    }

    #[test]
    fn signatureVectorsOfEveryDegreeAreTheVectorsOfTheCCode() {
        // Known answers of `sign_dyn` of the C library: the keys of the stream
        // SHAKE256("K" || logn), the point (7919 u + 13) mod q and the sampler stream
        // SHAKE256("S" || logn).
        let expected: [(u32, u64); 10] = [
            (1, 0x8A97_A420_7303_C005),
            (2, 0x4D5C_3D99_2F7E_4B2C),
            (3, 0xA98F_9806_6727_A745),
            (4, 0xE606_EF40_375F_54F4),
            (5, 0x33B3_7D1F_5F47_FB6C),
            (6, 0xAACE_2E16_673F_8210),
            (7, 0xFC9E_E091_5D39_BB00),
            (8, 0x2EB2_BE49_9CD9_5C14),
            (9, 0xB748_E721_725C_4009),
            (10, 0x9B97_88FD_54D3_AA1B),
        ];
        for (logn, vectorDigest) in expected {
            let (f, g, bigF, publicKey) =
                KeyGenerator::generatedKey(&mut SHAKE256::absorbOnce(&[b'K', logn as u8]), logn);
            let bigG = ModularPolynomial::completedSecretPolynomial(&f, &g, &bigF, logn)
                .expect("G of a generated key");
            let basis = SecretBasis {
                f: &f,
                g: &g,
                bigF: &bigF,
                bigG: &bigG,
            };
            let point: Vec<u16> = (0..1u32 << logn)
                .map(|u| ((u * 7919 + 13) % 12289) as u16)
                .collect();
            let mut reader = SHAKE256::absorbOnce(&[b'S', logn as u8]);
            let vector = Signer::signatureVector(&mut reader, &basis, &point, logn);
            assert_eq!(
                digest(vector.iter().flat_map(|value| value.to_le_bytes())),
                vectorDigest,
                "logn {logn}"
            );
            // The vector is a signature of the point for the public key.
            let mut transformed = publicKey.clone();
            ModularPolynomial::toMontgomeryTransform(&mut transformed, logn);
            assert!(ModularPolynomial::isValidSignatureVector(
                &point,
                &vector,
                &transformed,
                logn
            ));
        }
    }

    #[test]
    fn anAttemptGivesAVectorOnlyWhenItIsShort() {
        // The stream of the known answer of degree 32 gives a vector above the bound in its
        // first attempt and a short vector in its second. The second vector is the known answer
        // of the C code, so the C code refuses the first attempt too.
        let logn = 5;
        let (f, g, bigF, _) =
            KeyGenerator::generatedKey(&mut SHAKE256::absorbOnce(&[b'K', logn as u8]), logn);
        let bigG = ModularPolynomial::completedSecretPolynomial(&f, &g, &bigF, logn)
            .expect("G of a generated key");
        let basis = SecretBasis {
            f: &f,
            g: &g,
            bigF: &bigF,
            bigG: &bigG,
        };
        let point: Vec<u16> = (0..1u32 << logn)
            .map(|u| ((u * 7919 + 13) % 12289) as u16)
            .collect();
        let mut reader = SHAKE256::absorbOnce(&[b'S', logn as u8]);
        let mut workspace = vec![FloatingPoint::zero; 9 << logn];
        let mut attempt = || {
            let mut sampler = GaussianSampler::new(
                ChaChaRandom::seeded(&mut reader),
                sigmaMinimums[logn as usize],
            );
            Signer::shortVector(&mut sampler, &basis, &point, logn, &mut workspace)
        };
        assert_eq!(attempt(), None);
        let vector = attempt().expect("a short vector in the second attempt");
        assert_eq!(
            digest(vector.iter().flat_map(|value| value.to_le_bytes())),
            0x33B3_7D1F_5F47_FB6C
        );
    }
}
