/// The error distribution of a parameter set, given by the table of its cumulative
/// distribution.
///
/// The table `T_chi` of the specification holds the cumulative distribution of the absolute
/// value, scaled to 15 bits. liboqs calls it `CDF_TABLE` in the parameter header of each set.
pub(crate) struct ErrorDistribution {
    table: &'static [u16],
}

impl ErrorDistribution {
    /// Makes the distribution of a table.
    pub(crate) const fn new(table: &'static [u16]) -> Self {
        ErrorDistribution { table }
    }

    /// Replaces each 16-bit random value with a sample of the distribution, as
    /// `frodo_sample_n` of liboqs `noise.c` does.
    ///
    /// The high 15 bits of a value give the absolute value of the sample: the number of table
    /// entries below them, counted with no branch. The low bit gives the sign. A negative sample
    /// is its two's complement modulo `2^16`.
    pub(crate) fn sample(&self, values: &mut [u16]) {
        for value in values.iter_mut() {
            let randomBits = *value >> 1;
            let sign = *value & 1;
            let mut magnitude = 0u16;
            // The C code skips the last entry, which is 32767 in every table. No 15-bit value
            // exceeds it, so its comparison adds zero.
            for bound in self.table {
                // Both values fit in 15 bits, so the top bit of the difference is one exactly
                // when the bound is below the random bits.
                magnitude += bound.wrapping_sub(randomBits) >> 15;
            }
            *value = (0u16.wrapping_sub(sign) ^ magnitude).wrapping_add(sign);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorDistribution;
    use crate::parameters::{frodoKEM640AES, frodoKEM976AES, frodoKEM1344AES};
    use crate::testInputs::valuesDigest;

    /// The sample of each 16-bit value, in order.
    fn samplesOfEveryValue(distribution: &ErrorDistribution) -> Vec<u16> {
        let mut values: Vec<u16> = (0..=u16::MAX).collect();
        distribution.sample(&mut values);
        values
    }

    #[test]
    fn samplesOfEveryValueEqualTheSamplesOfTheCCode() {
        // The digests of `frodo_sample_n` of liboqs 0.16.0 on the values 0 to 65535.
        for (parameters, expected) in [
            (
                &frodoKEM640AES,
                "f99d2239d6365ec267ecd7e1e8a7dbc47b7d19e1dfd90fbc82bdfa03934a1dfb",
            ),
            (
                &frodoKEM976AES,
                "808fc3ba293553da64afa5240d99a9265f343f16a4ffbb900d86c8ad0b4dda9a",
            ),
            (
                &frodoKEM1344AES,
                "e82f4f5d440a1663def2accbfed1dac53e12fa3f85f4d0322e5d1c8df5d7c530",
            ),
        ] {
            assert_eq!(
                valuesDigest(&samplesOfEveryValue(&parameters.errorDistribution)),
                expected,
                "{}",
                parameters.description.name
            );
        }
    }

    #[test]
    fn eachAbsoluteValueHasTheProbabilityOfTheTable() {
        // The specification gives Pr[|e| = 0] = (T(0) + 1) / 2^15 and
        // Pr[|e| = z] = (T(z) - T(z - 1)) / 2^15 for each sign, so each count of the 2^15
        // random values with one sign is a difference of the table.
        for (table, parameters) in [
            (
                &[
                    4643u16, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762,
                    32766, 32767,
                ][..],
                &frodoKEM640AES,
            ),
            (
                &[
                    5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767,
                ][..],
                &frodoKEM976AES,
            ),
            (
                &[9142, 23462, 30338, 32361, 32725, 32765, 32767][..],
                &frodoKEM1344AES,
            ),
        ] {
            let samples = samplesOfEveryValue(&parameters.errorDistribution);
            for (magnitude, entry) in table.iter().enumerate() {
                let expected = if magnitude == 0 {
                    usize::from(*entry) + 1
                } else {
                    usize::from(entry - table[magnitude - 1])
                };
                let positive = samples
                    .iter()
                    .step_by(2)
                    .filter(|sample| usize::from(**sample) == magnitude)
                    .count();
                let negative = samples
                    .iter()
                    .skip(1)
                    .step_by(2)
                    .filter(|sample| **sample == 0u16.wrapping_sub(magnitude as u16))
                    .count();
                assert_eq!(positive, expected, "+{magnitude}");
                assert_eq!(negative, expected, "-{magnitude}");
            }
        }
    }

    #[test]
    fn theHighBitsGiveTheMagnitudeAndTheLowBitTheSign() {
        let distribution = &frodoKEM640AES.errorDistribution;
        let sampled = |value: u16| {
            let mut values = [value];
            distribution.sample(&mut values);
            values[0]
        };
        // 4643 is the first entry: random bits up to it give zero, and one more gives one.
        assert_eq!(sampled(2 * 4643), 0);
        assert_eq!(sampled(2 * 4643 + 1), 0);
        assert_eq!(sampled(2 * 4644), 1);
        assert_eq!(sampled(2 * 4644 + 1), 0xFFFF);
        // The largest random bits pass every bound but the last: 12 and -12.
        assert_eq!(sampled(0xFFFE), 12);
        assert_eq!(sampled(0xFFFF), 0u16.wrapping_sub(12));
        assert_eq!(sampled(0), 0);
        assert_eq!(sampled(1), 0);
    }
}
