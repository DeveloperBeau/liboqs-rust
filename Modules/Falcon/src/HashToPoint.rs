use OQSNativeSHA3::SHAKEReader;
use alloc::vec;
use alloc::vec::Vec;

/// HashToPoint of the Falcon specification: the polynomial modulo `q` of a SHAKE256 stream, in
/// the constant-time form `hash_to_point_ct` of `common.c` of the Falcon code of PQClean.
///
/// Each 16-bit big-endian sample below `61445 = 5 q` gives one coefficient, `sample mod q`,
/// and a larger sample is refused. The C code reads a fixed number of samples, more than the
/// degree, and moves the accepted values to the front with no branch on their positions.
pub(crate) struct HashToPoint;

/// The extra samples for each `logn` from 1 to 10, enough for `N` accepted values with a
/// probability of at least `1 - 2^-256`.
const oversampling: [usize; 11] = [0, 65, 67, 71, 77, 86, 100, 122, 154, 205, 287];

/// The marker of a refused sample.
const refused: u16 = 0xFFFF;

impl HashToPoint {
    /// The `N` coefficients of the point of a finalized SHAKE256 stream.
    pub(crate) fn point(reader: &mut SHAKEReader, logn: u32) -> Vec<u16> {
        let n = 1usize << logn;
        let extra = oversampling[logn as usize];
        let count = n + extra;
        let mut values = vec![0u16; count];
        for value in values.iter_mut() {
            let mut bytes = [0u8; 2];
            reader.squeeze(&mut bytes);
            let sample = (u32::from(bytes[0]) << 8) | u32::from(bytes[1]);
            // The reduction modulo q: up to two subtractions of 2 q and one of q.
            let isAtLeast =
                |value: u32, bound: u32| (value.wrapping_sub(bound) >> 31).wrapping_sub(1);
            let mut reduced = sample.wrapping_sub(24578 & isAtLeast(sample, 24578));
            reduced = reduced.wrapping_sub(24578 & isAtLeast(reduced, 24578));
            reduced = reduced.wrapping_sub(12289 & isAtLeast(reduced, 12289));
            // A sample of 61445 or more becomes the refused marker.
            reduced |= isAtLeast(sample, 61445);
            *value = reduced as u16;
        }
        // Passes with shifts of 1, 2, 4 and so on move each accepted value down to its final
        // slot. Whenever a pass moves a value by its shift, the target slot holds a refused
        // value.
        let mut shift = 1usize;
        while shift <= extra {
            let mut destination = 0u32;
            for source in 0..count {
                let sourceValue = u32::from(values[source]);
                let jump = (source as u32).wrapping_sub(destination);
                // All ones for an accepted value, and zero for a refused one.
                let mut mask = (sourceValue >> 15).wrapping_sub(1);
                destination = destination.wrapping_sub(mask);
                if source < shift {
                    continue;
                }
                let targetValue = u32::from(values[source - shift]);
                // The swap happens when the value is accepted and its jump has the bit of the
                // shift.
                mask &= (((jump & shift as u32) + 0x1FF) >> 9).wrapping_neg();
                let swapped = mask & (sourceValue ^ targetValue);
                values[source] = (sourceValue ^ swapped) as u16;
                values[source - shift] = (targetValue ^ swapped) as u16;
            }
            shift <<= 1;
        }
        values.truncate(n);
        debug_assert!(values.iter().all(|value| *value != refused));
        values
    }
}

#[cfg(test)]
mod tests {
    use super::HashToPoint;
    use OQSNativeSHA3::SHAKE256;

    /// The variable-time form of the specification, `hash_to_point_vartime`: read samples until
    /// `N` are accepted.
    fn specificationPoint(input: &[u8], logn: u32) -> Vec<u16> {
        let mut reader = SHAKE256::absorbOnce(input);
        let mut point = Vec::new();
        while point.len() < 1 << logn {
            let mut bytes = [0u8; 2];
            reader.squeeze(&mut bytes);
            let sample = (u16::from(bytes[0]) << 8) | u16::from(bytes[1]);
            if sample < 61445 {
                point.push(sample % 12289);
            }
        }
        point
    }

    #[test]
    fn pointIsThePointOfTheSpecification() {
        for logn in 1..=10 {
            for seed in 0u8..20 {
                let input = [seed, 0x46, logn as u8];
                let point = HashToPoint::point(&mut SHAKE256::absorbOnce(&input), logn);
                assert_eq!(
                    point,
                    specificationPoint(&input, logn),
                    "logn {logn}, {seed}"
                );
            }
        }
    }

    #[test]
    fn pointOfTheCCodeForAKnownStream() {
        // Known answers of `hash_to_point_ct` of the C library for SHAKE256("Falcon"): the
        // first coefficients and the sum of all of them.
        for (logn, first, total) in [
            (9u32, [2897u16, 11131, 6179, 4168], 3215693u64),
            (10, [2897, 11131, 6179, 4168], 6259158),
        ] {
            let point = HashToPoint::point(&mut SHAKE256::absorbOnce(b"Falcon"), logn);
            assert_eq!(&point[..4], &first, "logn {logn}");
            assert_eq!(
                point.iter().map(|value| u64::from(*value)).sum::<u64>(),
                total
            );
        }
    }
}
