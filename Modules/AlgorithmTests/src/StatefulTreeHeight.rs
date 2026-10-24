use alloc::vec::Vec;

/// The height of the largest Merkle tree of a stateful set of liboqs, read from its name.
///
/// A key generation builds the largest tree of a set, so the height sets the time of a key
/// pair: about two seconds in the C library for a tree of height 10, two minutes for 16, from
/// four minutes to an hour for 20, and up to a day for 25, see
/// `Documentation/Learnings/COracle.md`. `XMSS-SHA2_20_256` has one tree of height 20.
/// `XMSSMT-SHA2_60/3_256` has three layers of trees of height 20, the total height divided by
/// the layers. `LMS_SHA256_H10_W4_H5_W8` has a top tree of height 10 and bottom trees of
/// height 5.
pub struct StatefulTreeHeight;

impl StatefulTreeHeight {
    /// The height of the largest tree of the set of a name, or `None` for a name that is not
    /// an XMSS, XMSS^MT or LMS name of liboqs.
    pub fn largest(name: &str) -> Option<u32> {
        if let Some(parameters) = name.strip_prefix("XMSSMT-") {
            // The hash, the total height and the layers, and the length of a hash.
            let (_, rest) = parameters.split_once('_')?;
            let (heights, _) = rest.split_once('_')?;
            let (total, layers) = heights.split_once('/')?;
            let total: u32 = total.parse().ok()?;
            let layers: u32 = layers.parse().ok()?;
            return (layers > 0 && total.is_multiple_of(layers)).then(|| total / layers);
        }
        if let Some(parameters) = name.strip_prefix("XMSS-") {
            // The hash, the height and the length of a hash.
            let fields: Vec<&str> = parameters.split('_').collect();
            return match fields[..] {
                [_, height, _] => height.parse().ok(),
                _ => None,
            };
        }
        // The height and the Winternitz parameter of each level, from the top.
        let levels: Vec<&str> = name.strip_prefix("LMS_SHA256_")?.split('_').collect();
        if !levels.len().is_multiple_of(2) {
            return None;
        }
        let heights: Option<Vec<u32>> = levels
            .chunks(2)
            .map(|level| {
                level[1].strip_prefix('W')?.parse::<u32>().ok()?;
                level[0].strip_prefix('H')?.parse::<u32>().ok()
            })
            .collect();
        heights?.into_iter().max()
    }
}

#[cfg(test)]
mod tests {
    use super::StatefulTreeHeight;

    #[test]
    fn theNameGivesTheHeightOfTheLargestTree() {
        for (name, height) in [
            ("XMSS-SHA2_10_256", 10),
            ("XMSS-SHAKE256_20_192", 20),
            ("XMSSMT-SHA2_20/2_256", 10),
            ("XMSSMT-SHAKE_60/12_256", 5),
            ("XMSSMT-SHA2_60/3_256", 20),
            ("LMS_SHA256_H5_W1", 5),
            ("LMS_SHA256_H10_W4_H5_W8", 10),
            ("LMS_SHA256_H20_W8_H15_W8", 20),
            ("LMS_SHA256_H25_W8", 25),
        ] {
            assert_eq!(StatefulTreeHeight::largest(name), Some(height), "{name}");
        }
        for name in [
            "ML-DSA-44",
            "SLH_DSA_PURE_SHA2_128S",
            "XMSS-SHA2_10",
            "XMSS-SHA2_10_256_1",
            "XMSSMT-SHA2_20_256",
            "XMSSMT-SHA2_20/3_256",
            // No layers. A total of 0 is a multiple of 0, so only the check of the layers
            // keeps the division away.
            "XMSSMT-SHA2_20/0_256",
            "XMSSMT-SHA2_0/0_256",
            "LMS_SHA256_H5",
            "LMS_SHA256_X5_W1",
            "LMS_SHA256_H5_X1",
            "",
        ] {
            assert_eq!(StatefulTreeHeight::largest(name), None, "{name}");
        }
    }
}
