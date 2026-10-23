use crate::parameters::{Parameters, saltLength};
use crate::{FieldArithmetic, SaltedMessage};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;

/// The public map P of a classic public key, as `ov_publicmap` evaluates it, and the
/// verification of `ov_verify`.
///
/// The public key holds the entries of the upper triangular matrix of the n variables, block
/// after block: P1 for the pairs of vinegar variables, P2 for a vinegar and an oil variable and
/// P3 for the pairs of oil variables. Each entry has one element for each equation, and the
/// value at a point w is the sum over i <= j of `w_i w_j P(i, j)`.
pub(crate) struct PublicMap;

impl PublicMap {
    /// The value of the public map of a classic public key at a point of n elements, one
    /// element for each equation.
    ///
    /// As in the C code, the map adds each entry to the sum of the entries whose factor
    /// `w_i w_j` has the same low half, and for GF(256) also to the sum for the same high half.
    /// Then it multiplies each sum by its half. The point is public, so the sums may depend on
    /// it.
    pub(crate) fn evaluated<F: FieldArithmetic>(
        parameters: &Parameters,
        publicKey: &[u8],
        point: &[u8],
    ) -> Vec<u8> {
        let variableCount = parameters.variableCount;
        let vinegarCount = parameters.vinegarCount();
        let entryLength = parameters.oilLength();
        let isWide = F::elementBits > 4;
        let values: Vec<u8> = (0..variableCount)
            .map(|index| F::element(point, index))
            .collect();
        let mut lowSums = vec![0u8; 16 * entryLength];
        let mut highSums = vec![0u8; 16 * entryLength];
        let mut factors = vec![0u8; variableCount];
        let mut entries = publicKey.chunks_exact(entryLength);
        let mut addRow = |row: usize, columns: Range<usize>| {
            // `_xixj`: one element in each byte, so a scale of the bytes multiplies each one.
            factors[columns.clone()].copy_from_slice(&values[columns.clone()]);
            F::scale(&mut factors[columns.clone()], values[row]);
            for (column, entry) in columns.zip(&mut entries) {
                let factor = usize::from(factors[column]);
                F::add(
                    &mut lowSums[(factor & 0xF) * entryLength..][..entryLength],
                    entry,
                );
                if isWide {
                    F::add(
                        &mut highSums[(factor >> 4) * entryLength..][..entryLength],
                        entry,
                    );
                }
            }
        };
        for row in 0..vinegarCount {
            addRow(row, row..vinegarCount);
        }
        for row in 0..vinegarCount {
            addRow(row, vinegarCount..variableCount);
        }
        for row in vinegarCount..variableCount {
            addRow(row, row..variableCount);
        }
        let mut value = vec![0u8; entryLength];
        for half in 1..16u8 {
            let index = usize::from(half) * entryLength;
            F::multiplyAdd(&mut value, &lowSums[index..][..entryLength], half);
            if isWide {
                F::multiplyAdd(&mut value, &highSums[index..][..entryLength], half << 4);
            }
        }
        value
    }

    /// True when a signature of the length of the set is valid for a classic public key of the
    /// length of the set, as `ov_verify` decides: the public map at the point of the signature
    /// equals SHAKE256 of the message and the salt. The comparison folds the differences of
    /// the bytes with an or, with no branch on a byte.
    pub(crate) fn isValidSignature<F: FieldArithmetic>(
        parameters: &Parameters,
        signature: &[u8],
        message: &[u8],
        publicKey: &[u8],
    ) -> bool {
        let pointLength = parameters.pointLength();
        assert_eq!(
            signature.len(),
            pointLength + saltLength,
            "the caller checks the signature length"
        );
        let (point, salt) = signature.split_at(pointLength);
        let value = Self::evaluated::<F>(parameters, publicKey, point);
        let target = SaltedMessage::new(message, salt).target(parameters.oilLength());
        let difference = value
            .iter()
            .zip(&target)
            .fold(0u8, |difference, (value, target)| {
                difference | (value ^ target)
            });
        difference == 0
    }
}

#[cfg(test)]
mod tests {
    use super::PublicMap;
    use crate::gf16::GF16;
    use crate::gf256::GF256;
    use crate::parameters::{Parameters, ovIII, ovIp, ovIs, ovV, triangleSize};
    use crate::testInputs::{digest, sequence};
    use crate::{Field, FieldArithmetic};

    /// The value of the map by its definition: the sum over i <= j of `w_i w_j P(i, j)`, with
    /// the entries in the order of the upper triangular matrix of the n variables.
    fn definedValue<F: FieldArithmetic>(
        parameters: &Parameters,
        publicKey: &[u8],
        point: &[u8],
    ) -> Vec<u8> {
        let (variableCount, vinegarCount) = (parameters.variableCount, parameters.vinegarCount());
        let entryLength = parameters.oilLength();
        let mut order = Vec::new();
        for row in 0..vinegarCount {
            order.extend((row..vinegarCount).map(|column| (row, column)));
        }
        for row in 0..vinegarCount {
            order.extend((vinegarCount..variableCount).map(|column| (row, column)));
        }
        for row in vinegarCount..variableCount {
            order.extend((row..variableCount).map(|column| (row, column)));
        }
        assert_eq!(order.len(), triangleSize(variableCount));
        let mut value = vec![0u8; entryLength];
        for ((row, column), entry) in order.into_iter().zip(publicKey.chunks_exact(entryLength)) {
            let factor = F::product(F::element(point, row), F::element(point, column));
            F::multiplyAdd(&mut value, entry, factor);
        }
        value
    }

    fn checkSet<F: FieldArithmetic>(parameters: &Parameters, expected: &str) {
        let publicKey = sequence(parameters.expandedPublicKeyLength(), 30);
        let point = sequence(parameters.pointLength(), 31);
        let value = PublicMap::evaluated::<F>(parameters, &publicKey, &point);
        // `ov_publicmap` with the public key 30 at the point 31, from liboqs 0.16.0.
        assert_eq!(digest(&value), expected, "{}", parameters.description.name);
        assert_eq!(value, definedValue::<F>(parameters, &publicKey, &point));
    }

    #[test]
    fn theMapOfEachShapeGivesTheBytesOfTheCCode() {
        assert_eq!(ovIs.field, Field::gf16);
        checkSet::<GF16>(
            &ovIs,
            "efa29a32bd0787815df84848f522ee4541863ce6e8fc1598b299a6458884e6a1",
        );
        checkSet::<GF256>(
            &ovIp,
            "2220f8dc0df9753cf3fb45201cc2385226f2179d35faf164d0cc33c893d5b796",
        );
        checkSet::<GF256>(
            &ovIII,
            "c9e1801c84694b2468b5a8a7f8932fd4be0ce6255ccb6b7f0d1970eacf8aa253",
        );
        checkSet::<GF256>(
            &ovV,
            "a5151caf9c08b78f731c134d32c96e48e48f7cc13e2daec39d8ab91f154fa31a",
        );
    }

    #[test]
    fn theMapAtZeroIsZeroAndOneEntryGivesItsOwnTerm() {
        let entryLength = ovIp.oilLength();
        let mut publicKey = vec![0u8; ovIp.expandedPublicKeyLength()];
        let point = vec![0u8; ovIp.pointLength()];
        publicKey.fill(0x5A);
        assert_eq!(
            PublicMap::evaluated::<GF256>(&ovIp, &publicKey, &point),
            vec![0u8; entryLength]
        );
        // Only the last entry of P3, for the last oil variable squared, is not zero, and only
        // that variable is not zero.
        publicKey.fill(0);
        let last = publicKey.len() - entryLength;
        publicKey[last..].copy_from_slice(&sequence(entryLength, 5));
        let mut point = point;
        let lastVariable = point.len() - 1;
        point[lastVariable] = 0x03;
        let mut expected = vec![0u8; entryLength];
        GF256::multiplyAdd(
            &mut expected,
            &sequence(entryLength, 5),
            GF256::product(3, 3),
        );
        assert_eq!(
            PublicMap::evaluated::<GF256>(&ovIp, &publicKey, &point),
            expected
        );
    }
}
