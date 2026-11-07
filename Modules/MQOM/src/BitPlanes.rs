/// Up to 64 elements of an extension field in bit planes: bit `lane` of plane `b` is bit `b`
/// of the element in that lane.
///
/// One operation on the planes is the field operation in every lane, as the bitsliced fields
/// of `fields_bitsliced_branchconst.h` compute the τ repetitions of the proof at once.
/// `BitCount` is 8 for GF(2^8) and 16 for GF(2^16). The planes of GF(2^16) are the eight
/// planes of the constant coefficient and then the eight planes of the coefficient of Y, as
/// the C code packs them. The operations have no branch and no table on the values of the
/// lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BitPlanes<const BitCount: usize> {
    planes: [u64; BitCount],
}

/// The product of eight planes of GF(2^8) with x: the planes move up by one, and the top plane
/// adds x^8 = x^4 + x^3 + x + 1.
fn doubledPlanes(planes: &[u64; 8]) -> [u64; 8] {
    let top = planes[7];
    [
        top,
        planes[0] ^ top,
        planes[1],
        planes[2] ^ top,
        planes[3] ^ top,
        planes[4],
        planes[5],
        planes[6],
    ]
}

/// The lane-wise product of eight planes of GF(2^8) with eight others: the carry-less product
/// of the planes, then the reduction of the planes 14 down to 8.
fn bytePlanesProduct(left: &[u64; 8], right: &[u64; 8]) -> [u64; 8] {
    let mut wide = [0u64; 15];
    for (leftIndex, leftPlane) in left.iter().enumerate() {
        for (rightIndex, rightPlane) in right.iter().enumerate() {
            wide[leftIndex + rightIndex] ^= leftPlane & rightPlane;
        }
    }
    for degree in (8..15).rev() {
        let carry = wide[degree];
        wide[degree - 4] ^= carry;
        wide[degree - 5] ^= carry;
        wide[degree - 7] ^= carry;
        wide[degree - 8] ^= carry;
    }
    core::array::from_fn(|index| wide[index])
}

/// The product of eight planes of GF(2^8) with the constant 32 = x^5.
fn planesTimes32(planes: &[u64; 8]) -> [u64; 8] {
    let mut result = *planes;
    for _ in 0..5 {
        result = doubledPlanes(&result);
    }
    result
}

/// The exclusive or of eight planes with eight others.
fn sumOfPlanes(left: &[u64; 8], right: &[u64; 8]) -> [u64; 8] {
    core::array::from_fn(|index| left[index] ^ right[index])
}

impl<const BitCount: usize> BitPlanes<BitCount> {
    /// The planes with zero in every lane.
    pub(crate) const zero: Self = BitPlanes {
        planes: [0; BitCount],
    };

    /// The planes of elements, one in each lane from lane 0.
    pub(crate) fn fromLanes(elements: impl IntoIterator<Item = u16>) -> Self {
        let mut planes = Self::zero;
        for (lane, element) in elements.into_iter().enumerate() {
            planes.insert(lane, element);
        }
        planes
    }

    /// Writes an element into a lane that holds zero, as `field_ext_bitslice_vect_pack` does.
    pub(crate) fn insert(&mut self, lane: usize, element: u16) {
        for (bit, plane) in self.planes.iter_mut().enumerate() {
            *plane |= u64::from((element >> bit) & 1) << lane;
        }
    }

    /// The element of a lane, as `field_ext_bitslice_vect_unpack` reads it.
    pub(crate) fn lane(&self, lane: usize) -> u16 {
        self.planes
            .iter()
            .enumerate()
            .fold(0u16, |element, (bit, plane)| {
                element + (((plane >> lane) & 1) as u16) * (1 << bit)
            })
    }

    /// Adds other planes, lane by lane.
    pub(crate) fn add(&mut self, other: &Self) {
        for (plane, otherPlane) in self.planes.iter_mut().zip(&other.planes) {
            *plane ^= otherPlane;
        }
    }

    /// The low eight planes, of GF(2^8) or of the constant coefficient of GF(2^16).
    fn lowPlanes(&self) -> [u64; 8] {
        core::array::from_fn(|index| self.planes[index])
    }

    /// The planes 8 to 15, of the coefficient of Y of GF(2^16).
    fn highPlanes(&self) -> [u64; 8] {
        core::array::from_fn(|index| self.planes[8 + index])
    }

    /// The planes of the low and the high eight planes.
    fn joined(low: &[u64; 8], high: &[u64; 8]) -> Self {
        BitPlanes {
            planes: core::array::from_fn(|index| {
                if index < 8 {
                    low[index]
                } else {
                    high[index - 8]
                }
            }),
        }
    }

    /// The lane-wise product with other planes, as `gf256_bitslice32_mult_default` and
    /// `gf256to2_bitslice32_mult_default` compute it.
    pub(crate) fn times(&self, other: &Self) -> Self {
        let low = bytePlanesProduct(&self.lowPlanes(), &other.lowPlanes());
        if BitCount == 8 {
            return Self::joined(&low, &[0; 8]);
        }
        let high = bytePlanesProduct(&self.highPlanes(), &other.highPlanes());
        let constant = sumOfPlanes(&low, &planesTimes32(&high));
        let linear = sumOfPlanes(
            &low,
            &bytePlanesProduct(
                &sumOfPlanes(&self.lowPlanes(), &self.highPlanes()),
                &sumOfPlanes(&other.lowPlanes(), &other.highPlanes()),
            ),
        );
        Self::joined(&constant, &linear)
    }

    /// The products of the planes with the elements of the basis: entry `b` is the product
    /// with the element whose bit `b` alone is set. A product with a scalar is the sum of the
    /// entries of its bits.
    pub(crate) fn basisMultiples(&self) -> [Self; BitCount] {
        let mut multiples = [Self::zero; BitCount];
        let mut low = self.lowPlanes();
        let mut high = if BitCount == 8 {
            [0; 8]
        } else {
            self.highPlanes()
        };
        for multiple in multiples.iter_mut().take(8) {
            *multiple = Self::joined(&low, &high);
            low = doubledPlanes(&low);
            high = doubledPlanes(&high);
        }
        if BitCount == 16 {
            // The product with Y: (a + b Y) Y = 32 b + (a + b) Y.
            let mut low = planesTimes32(&self.highPlanes());
            let mut high = sumOfPlanes(&self.lowPlanes(), &self.highPlanes());
            for multiple in multiples.iter_mut().skip(8) {
                *multiple = Self::joined(&low, &high);
                low = doubledPlanes(&low);
                high = doubledPlanes(&high);
            }
        }
        multiples
    }

    /// Adds the product of a scalar and the planes whose basis multiples are `multiples`, with
    /// masks in place of branches on the bits of the scalar, as
    /// `field_ext_bitslice_vect_mult_hybrid` and its kin multiply.
    pub(crate) fn addProduct(&mut self, scalar: u16, multiples: &[Self; BitCount]) {
        for (bit, multiple) in multiples.iter().enumerate() {
            let mask = 0u64.wrapping_sub(u64::from((scalar >> bit) & 1));
            for (plane, multiplePlane) in self.planes.iter_mut().zip(&multiple.planes) {
                *plane ^= multiplePlane & mask;
            }
        }
    }

    /// Adds the product of a public scalar and the planes whose basis multiples are
    /// `multiples`, with a branch on each bit of the scalar, as the public multiplication of
    /// `field_ext_bitslice_vect_mult_hybrid_public` may. The scalar must be public, such as an
    /// element of the equations of a public key.
    pub(crate) fn addPublicProduct(&mut self, publicScalar: u16, multiples: &[Self; BitCount]) {
        for (bit, multiple) in multiples.iter().enumerate() {
            if (publicScalar >> bit) & 1 == 1 {
                self.add(multiple);
            }
        }
    }

    /// The product of a scalar and the planes whose basis multiples are `multiples`.
    pub(crate) fn product(scalar: u16, multiples: &[Self; BitCount]) -> Self {
        let mut planes = Self::zero;
        planes.addProduct(scalar, multiples);
        planes
    }
}

#[cfg(test)]
mod tests {
    use super::BitPlanes;
    use crate::ExtensionField;

    /// Seeded elements of a field, from a linear congruential sequence.
    fn elements(seed: u32, count: usize, field: ExtensionField) -> Vec<u16> {
        let mut state = seed;
        let mask = if field == ExtensionField::gf256 {
            0x00FF
        } else {
            0xFFFF
        };
        (0..count)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                ((state >> 8) as u16) & mask
            })
            .collect()
    }

    fn checkLaneOperations<const BitCount: usize>(field: ExtensionField) {
        for seed in 0..20u32 {
            let left = elements(seed, 64, field);
            let right = elements(seed + 100, 64, field);
            let scalar = elements(seed + 200, 1, field)[0];
            let leftPlanes = BitPlanes::<BitCount>::fromLanes(left.iter().copied());
            let rightPlanes = BitPlanes::<BitCount>::fromLanes(right.iter().copied());
            let product = leftPlanes.times(&rightPlanes);
            let scaled = BitPlanes::product(scalar, &leftPlanes.basisMultiples());
            let mut sum = leftPlanes;
            sum.add(&rightPlanes);
            for lane in 0..64 {
                assert_eq!(
                    leftPlanes.lane(lane),
                    left[lane],
                    "seed {seed}, lane {lane}"
                );
                assert_eq!(
                    product.lane(lane),
                    field.product(left[lane], right[lane]),
                    "seed {seed}, lane {lane}"
                );
                assert_eq!(
                    scaled.lane(lane),
                    field.product(scalar, left[lane]),
                    "seed {seed}, lane {lane}"
                );
                assert_eq!(sum.lane(lane), left[lane] ^ right[lane]);
            }
        }
    }

    #[test]
    fn eachLaneOfGF256PlanesComputesTheFieldOperation() {
        checkLaneOperations::<8>(ExtensionField::gf256);
    }

    #[test]
    fn eachLaneOfGF65536PlanesComputesTheFieldOperation() {
        checkLaneOperations::<16>(ExtensionField::gf65536);
    }

    #[test]
    fn eachBasisMultipleIsTheProductWithOneBit() {
        let field = ExtensionField::gf65536;
        let values = elements(7, 37, field);
        let planes = BitPlanes::<16>::fromLanes(values.iter().copied());
        for (bit, multiple) in planes.basisMultiples().iter().enumerate() {
            for (lane, value) in values.iter().enumerate() {
                assert_eq!(multiple.lane(lane), field.product(1 << bit, *value));
            }
        }
        let mut accumulated = BitPlanes::<16>::zero;
        accumulated.addProduct(0x8001, &planes.basisMultiples());
        accumulated.addProduct(0x8001, &planes.basisMultiples());
        assert_eq!(accumulated, BitPlanes::zero);
        // The public form gives the same sums.
        let multiples = planes.basisMultiples();
        for scalar in [0u16, 1, 0x8000, 0x1234, 0xFFFF] {
            let mut masked = planes;
            masked.addProduct(scalar, &multiples);
            let mut branched = planes;
            branched.addPublicProduct(scalar, &multiples);
            assert_eq!(masked, branched, "{scalar:#06x}");
        }
    }
}
