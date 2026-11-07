use OQSNativeSortingNetwork::SortingNetwork;
use alloc::vec;
use alloc::vec::Vec;

/// The control bits of a Benes network for a permutation, `controlbitsfrompermutation` of
/// `controlbits.c`: the algorithm of Nassimi and Sahni in the form of Bernstein, with sorting
/// networks in place of branches.
///
/// The C code checks the bits by sending the identity through the network, and computes them
/// again on a mismatch. The recursion is exact for every permutation, so the check passes at
/// once and the port has no loop. The unit tests send each test permutation through the
/// network.
pub(crate) struct ControlBits;

impl ControlBits {
    /// The `(2 w - 1) 2^(w - 1)` control bits of a permutation of `2^w` elements, with `w`
    /// from 1 to 14, packed from the low bit of each byte.
    pub(crate) fn ofPermutation(permutation: &[i16], logarithm: u32) -> Vec<u8> {
        let count = 1usize << logarithm;
        debug_assert_eq!(permutation.len(), count);
        let bitCount = (2 * logarithm as usize - 1) * count / 2;
        let mut bits = vec![0u8; bitCount.div_ceil(8)];
        let mut scratch = vec![0i32; 2 * count];
        Self::recursion(&mut bits, 0, 1, permutation, logarithm, &mut scratch);
        bits
    }

    /// The smaller of two signed values, `crypto_int32_min`.
    fn minimum(left: i32, right: i32) -> i32 {
        let differentBits = right ^ left;
        let mut difference = right.wrapping_sub(left);
        difference ^= differentBits & (difference ^ right);
        left ^ ((difference >> 31) & differentBits)
    }

    /// Adds a bit at a position of the output, as `out[pos >> 3] ^= bit << (pos & 7)`.
    fn addBit(bits: &mut [u8], position: usize, bit: i32) {
        bits[position >> 3] ^= (bit << (position & 7)) as u8;
    }

    /// `cbrecursion`: the bits of the outer layers of the network of a permutation at the
    /// positions `position`, `position + step` and so on, and the two halves in the middle.
    /// The scratch space holds the two arrays `A` and `B` of the C code.
    fn recursion(
        bits: &mut [u8],
        mut position: usize,
        step: usize,
        permutation: &[i16],
        logarithm: u32,
        scratch: &mut [i32],
    ) {
        let count = permutation.len();
        if logarithm == 1 {
            Self::addBit(bits, position, i32::from(permutation[0]));
            return;
        }
        let (a, rest) = scratch.split_at_mut(count);
        let b = &mut rest[..count];
        for (x, entry) in a.iter_mut().enumerate() {
            *entry = (i32::from(permutation[x] ^ 1) << 16) + i32::from(permutation[x ^ 1]);
        }
        SortingNetwork::sort(a);
        for (x, entry) in b.iter_mut().enumerate() {
            let px = a[x] & 0xFFFF;
            *entry = (px << 16) + Self::minimum(px, x as i32);
        }
        for (x, entry) in a.iter_mut().enumerate() {
            *entry = (((*entry as u32) << 16) + x as u32) as i32;
        }
        SortingNetwork::sort(a);
        for (entry, bEntry) in a.iter_mut().zip(b.iter()) {
            *entry = ((*entry as u32) << 16).wrapping_add((*bEntry >> 16) as u32) as i32;
        }
        SortingNetwork::sort(a);
        if logarithm <= 10 {
            for (bEntry, aEntry) in b.iter_mut().zip(a.iter()) {
                *bEntry = ((*aEntry & 0xFFFF) << 10) + (*bEntry & 0x3FF);
            }
            for _ in 1..logarithm - 1 {
                for (x, entry) in a.iter_mut().enumerate() {
                    *entry = ((b[x] & !0x3FF) << 6) + x as i32;
                }
                SortingNetwork::sort(a);
                for (entry, bEntry) in a.iter_mut().zip(b.iter()) {
                    *entry = (((*entry as u32) << 20) + *bEntry as u32) as i32;
                }
                SortingNetwork::sort(a);
                for (bEntry, aEntry) in b.iter_mut().zip(a.iter()) {
                    let ppcpx = *aEntry & 0xF_FFFF;
                    let ppcx = (*aEntry & 0xF_FC00) + (*bEntry & 0x3FF);
                    *bEntry = Self::minimum(ppcx, ppcpx);
                }
            }
            for entry in b.iter_mut() {
                *entry &= 0x3FF;
            }
        } else {
            for (bEntry, aEntry) in b.iter_mut().zip(a.iter()) {
                *bEntry = (((*aEntry as u32) << 16) + (*bEntry & 0xFFFF) as u32) as i32;
            }
            for round in 1..logarithm - 1 {
                for (x, entry) in a.iter_mut().enumerate() {
                    *entry = (b[x] & !0xFFFF) + x as i32;
                }
                SortingNetwork::sort(a);
                for (entry, bEntry) in a.iter_mut().zip(b.iter()) {
                    *entry = (((*entry as u32) << 16) + (*bEntry & 0xFFFF) as u32) as i32;
                }
                if round < logarithm - 2 {
                    for (bEntry, aEntry) in b.iter_mut().zip(a.iter()) {
                        *bEntry = (*aEntry & !0xFFFF) + (*bEntry >> 16);
                    }
                    SortingNetwork::sort(b);
                    for (bEntry, aEntry) in b.iter_mut().zip(a.iter()) {
                        *bEntry = (((*bEntry as u32) << 16) + (*aEntry & 0xFFFF) as u32) as i32;
                    }
                }
                SortingNetwork::sort(a);
                for (bEntry, aEntry) in b.iter_mut().zip(a.iter()) {
                    let cpx = (*bEntry & !0xFFFF) + (*aEntry & 0xFFFF);
                    *bEntry = Self::minimum(*bEntry, cpx);
                }
            }
            for entry in b.iter_mut() {
                *entry &= 0xFFFF;
            }
        }
        for (x, entry) in a.iter_mut().enumerate() {
            *entry = (i32::from(permutation[x]) << 16) + x as i32;
        }
        SortingNetwork::sort(a);
        let half = count / 2;
        for j in 0..half {
            let x = 2 * j;
            let fj = b[x] & 1;
            let fx = x as i32 + fj;
            Self::addBit(bits, position, fj);
            position += step;
            b[x] = (((a[x] as u32) << 16) + fx as u32) as i32;
            b[x + 1] = (((a[x + 1] as u32) << 16) + (fx ^ 1) as u32) as i32;
        }
        SortingNetwork::sort(b);
        position += (2 * logarithm as usize - 3) * step * half;
        for k in 0..half {
            let y = 2 * k;
            let lk = b[y] & 1;
            let ly = y as i32 + lk;
            Self::addBit(bits, position, lk);
            position += step;
            a[y] = (ly << 16) + (b[y] & 0xFFFF);
            a[y + 1] = ((ly ^ 1) << 16) + (b[y + 1] & 0xFFFF);
        }
        SortingNetwork::sort(a);
        position -= (2 * logarithm as usize - 2) * step * half;
        let mut halves = vec![0i16; count];
        for j in 0..half {
            halves[j] = ((a[2 * j] & 0xFFFF) >> 1) as i16;
            halves[j + half] = ((a[2 * j + 1] & 0xFFFF) >> 1) as i16;
        }
        let (first, second) = halves.split_at(half);
        Self::recursion(bits, position, step * 2, first, logarithm - 1, scratch);
        Self::recursion(
            bits,
            position + step,
            step * 2,
            second,
            logarithm - 1,
            scratch,
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::ControlBits;
    use OQSNativeAlgorithmTests::{FuzzRandom, OutputDigest};

    /// The permutation of `2^w` elements of a seed, by the method of Fisher and Yates.
    pub(crate) fn seededPermutation(seed: u64, logarithm: u32) -> Vec<i16> {
        let count = 1usize << logarithm;
        let mut permutation: Vec<i16> = (0..count).map(|value| value as i16).collect();
        let mut words = FuzzRandom::seeded(seed);
        for index in (1..count).rev() {
            let other = (words.nextWord() % (index as u64 + 1)) as usize;
            permutation.swap(index, other);
        }
        permutation
    }

    /// The identity sent through the layers of the network, as the check of
    /// `controlbitsfrompermutation` does: strides 1, 2 and so on to `2^(w - 1)`, and back to 1.
    pub(crate) fn routedIdentity(bits: &[u8], logarithm: u32) -> Vec<i16> {
        let count = 1usize << logarithm;
        let mut values: Vec<i16> = (0..count).map(|value| value as i16).collect();
        let strides = (0..logarithm).chain((0..logarithm - 1).rev());
        for (layer, strideLogarithm) in strides.enumerate() {
            let stride = 1usize << strideLogarithm;
            let mut index = layer * count / 2;
            for start in (0..count).step_by(2 * stride) {
                for offset in start..start + stride {
                    if (bits[index >> 3] >> (index & 7)) & 1 == 1 {
                        values.swap(offset, offset + stride);
                    }
                    index += 1;
                }
            }
        }
        values
    }

    #[test]
    fn theBitsRouteTheIdentityToThePermutation() {
        for logarithm in 1..=13 {
            for seed in 0..3 {
                let permutation = seededPermutation(seed, logarithm);
                let bits = ControlBits::ofPermutation(&permutation, logarithm);
                assert_eq!(
                    bits.len(),
                    ((2 * logarithm as usize - 1) << (logarithm - 1)).div_ceil(8)
                );
                assert_eq!(
                    routedIdentity(&bits, logarithm),
                    permutation,
                    "w {logarithm}, seed {seed}"
                );
            }
        }
    }

    #[test]
    fn theIdentityAndTheSwapOfTwoElementsHaveTheirOwnBits() {
        // A network of one switch: the identity of two elements opens it, the swap closes it.
        assert_eq!(ControlBits::ofPermutation(&[0, 1], 1), vec![0]);
        assert_eq!(ControlBits::ofPermutation(&[1, 0], 1), vec![1]);
        let identity: Vec<i16> = (0..16).collect();
        let bits = ControlBits::ofPermutation(&identity, 4);
        assert_eq!(routedIdentity(&bits, 4), identity);
    }

    #[test]
    fn theMinimumIsTheSmallerValueForAnyTwoValuesAsCryptoInt32Min() {
        // The recursion gives `minimum` only values from 0 up, and the correction of the sign of
        // the difference matters only for two values of opposite signs, whose difference can
        // overflow. `crypto_int32_min` of `pqclean_mceliece348864_clean` in liboqs 0.16.0 takes
        // every ordered pair of the edge values, then 20000 pairs of SplitMix64 of the seed 71,
        // the low half of each word as the left value. The digest is the `OutputDigest` of the
        // minimums as little-endian 32-bit values. About half of the pairs have opposite signs,
        // and about half of those overflow.
        let edges = [
            i32::MIN,
            i32::MIN + 1,
            -65536,
            -1,
            0,
            1,
            65535,
            i32::MAX - 1,
            i32::MAX,
        ];
        let mut pairs: Vec<(i32, i32)> = edges
            .iter()
            .flat_map(|left| edges.iter().map(|right| (*left, *right)))
            .collect();
        let mut words = FuzzRandom::seeded(71);
        pairs.extend((0..20_000).map(|_| {
            let word = words.nextWord();
            (word as i32, (word >> 32) as i32)
        }));
        let mut output = Vec::new();
        for (left, right) in pairs {
            let minimum = ControlBits::minimum(left, right);
            assert_eq!(minimum, left.min(right), "{left} and {right}");
            output.extend(minimum.to_le_bytes());
        }
        assert_eq!(
            OutputDigest::of(&output),
            "7798e98bf6d0db0a3faac72af3c09595dcb4b187a138e3c3a4a49f8950eebb9a"
        );
    }

    #[test]
    fn theBitsAreTheKnownAnswersOfTheCFunction() {
        // The `OutputDigest` of the control bits of `controlbitsfrompermutation` of
        // `pqclean_mceliece348864_clean` in liboqs 0.16.0 for the permutations of the seeds 0
        // and 1, for each w from 4 to 13, in that order. The check of the C function moves by
        // `n >> 4` bytes for each layer, which is zero below 16 elements, so the C function
        // runs only from w = 4.
        let expected = "13d5f94ac58e4c13ddefa47e6b5eb5b1edeb21adaa74db0368302e7cd75c4787";
        let mut output = Vec::new();
        for logarithm in 4..=13 {
            for seed in 0..2 {
                output.extend(ControlBits::ofPermutation(
                    &seededPermutation(seed, logarithm),
                    logarithm,
                ));
            }
        }
        assert_eq!(OutputDigest::of(&output), expected);
    }
}
