use crate::Parameters;
use crate::fieldArithmetic::FieldArithmetic;
use crate::publicMap::PublicMap;
use alloc::vec;
use alloc::vec::Vec;

/// The central map of the secret key, `map_group2` of `snova.h`: the blocks F11, F12 and F21
/// of each equation, in the layouts of P11, P12 and P21.
pub(crate) struct CentralMap {
    /// The blocks F11, which equal P11.
    pub(crate) f11: Vec<u8>,
    /// The blocks F12, `P12 + P11 T12`.
    pub(crate) f12: Vec<u8>,
    /// The blocks F21, `P21 + T12' P11`, where `T12'` takes the blocks of T12 in transposed
    /// places.
    pub(crate) f21: Vec<u8>,
}

impl CentralMap {
    /// The central map of a public map and the secret matrices T12, `gen_F_opt` of
    /// `snova_opt.h`, with the spread arithmetic and the loop order of the C code.
    pub(crate) fn generated(
        parameters: &Parameters,
        publicMap: &PublicMap,
        t12: &[u8],
    ) -> CentralMap {
        let (vinegarCount, oilCount, rank) = (
            parameters.vinegarCount,
            parameters.oilCount,
            parameters.rank,
        );
        let equationCount = oilCount;
        let squaredRank = parameters.squaredRank();
        let p11 = &publicMap.p11;
        let mut f12 = publicMap.p12.clone();
        let mut f21 = publicMap.p21.clone();
        // The spread elements in 16 bits, see `FieldArithmetic::narrowed`.
        let mut spreadT12 = vec![0u16; vinegarCount * oilCount * squaredRank];
        let mut spreadP11 = vec![0u16; equationCount * squaredRank];
        let spread = |element: u8| FieldArithmetic::narrowed(FieldArithmetic::spread(element));
        let mut sums = vec![0u32; equationCount * oilCount * squaredRank];
        let rowLength = equationCount * rank;
        let columnLength = oilCount * rank;

        // F12 = P12 + P11 T12. `spreadT12` holds T12 by block row, row, block column and
        // column, so that one row of the product is one stretch of it.
        for blockRow in 0..vinegarCount {
            for blockColumn in 0..oilCount {
                for row in 0..rank {
                    for column in 0..rank {
                        spreadT12
                            [((blockRow * rank + row) * oilCount + blockColumn) * rank + column] =
                            spread(
                                t12[(blockRow * oilCount + blockColumn) * squaredRank
                                    + row * rank
                                    + column],
                            );
                    }
                }
            }
        }
        for vinegarRow in 0..vinegarCount {
            sums.fill(0);
            for inner in 0..vinegarCount {
                for equation in 0..equationCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            spreadP11[column * rowLength + equation * rank + row] = spread(
                                p11[((equation * vinegarCount + vinegarRow) * vinegarCount
                                    + inner)
                                    * squaredRank
                                    + row * rank
                                    + column],
                            );
                        }
                    }
                }
                // Each sum of an equation and a row adds the products of one row of P11.
                for oilColumn in 0..oilCount {
                    for column in 0..rank {
                        let target =
                            &mut sums[(oilColumn * rank + column) * rowLength..][..rowLength];
                        for innerIndex in 0..rank {
                            let factor = spreadT12[(inner * rank + innerIndex) * columnLength
                                + oilColumn * rank
                                + column];
                            let source = &spreadP11[innerIndex * rowLength..][..rowLength];
                            for (sum, element) in target.iter_mut().zip(source) {
                                *sum ^= FieldArithmetic::spreadProduct(*element, factor);
                            }
                        }
                    }
                }
            }
            for equation in 0..equationCount {
                for oilColumn in 0..oilCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            f12[((equation * vinegarCount + vinegarRow) * oilCount + oilColumn)
                                * squaredRank
                                + row * rank
                                + column] ^= FieldArithmetic::element(
                                sums[(oilColumn * rank + column) * rowLength
                                    + equation * rank
                                    + row],
                            );
                        }
                    }
                }
            }
        }

        // F21 = P21 + T12' P11, with T12 in the transposed layout and P11 by its rows.
        for blockRow in 0..vinegarCount {
            for blockColumn in 0..oilCount {
                for row in 0..rank {
                    for column in 0..rank {
                        spreadT12
                            [((blockRow * rank + column) * oilCount + blockColumn) * rank + row] =
                            spread(
                                t12[(blockRow * oilCount + blockColumn) * squaredRank
                                    + row * rank
                                    + column],
                            );
                    }
                }
            }
        }
        for vinegarColumn in 0..vinegarCount {
            sums.fill(0);
            for inner in 0..vinegarCount {
                for equation in 0..equationCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            spreadP11[row * rowLength + equation * rank + column] = spread(
                                p11[((equation * vinegarCount + inner) * vinegarCount
                                    + vinegarColumn)
                                    * squaredRank
                                    + row * rank
                                    + column],
                            );
                        }
                    }
                }
                for oilRow in 0..oilCount {
                    for row in 0..rank {
                        let target = &mut sums[(oilRow * rank + row) * rowLength..][..rowLength];
                        for innerIndex in 0..rank {
                            let factor = spreadT12
                                [(inner * rank + innerIndex) * columnLength + oilRow * rank + row];
                            let source = &spreadP11[innerIndex * rowLength..][..rowLength];
                            for (sum, element) in target.iter_mut().zip(source) {
                                *sum ^= FieldArithmetic::spreadProduct(*element, factor);
                            }
                        }
                    }
                }
            }
            for equation in 0..equationCount {
                for oilRow in 0..oilCount {
                    for row in 0..rank {
                        for column in 0..rank {
                            f21[((equation * oilCount + oilRow) * vinegarCount + vinegarColumn)
                                * squaredRank
                                + row * rank
                                + column] ^= FieldArithmetic::element(
                                sums[(oilRow * rank + row) * rowLength + equation * rank + column],
                            );
                        }
                    }
                }
            }
        }

        CentralMap {
            f11: p11.clone(),
            f12,
            f21,
        }
    }
}
