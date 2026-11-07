/// The trade-off of a CROSS parameter set between the length of a signature and its speed.
///
/// The balanced and the small sets reveal the seeds and the commitments of the rounds through a
/// seed tree and a Merkle tree. The fast sets have no trees, `NO_TREES` of their `set.h`: a
/// signature lists each seed and each commitment that it reveals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tradeoff {
    /// `BALANCED`: the trees, with a middle number of rounds.
    balanced,
    /// `SPEED`: no trees, with the fewest rounds.
    fast,
    /// `SIG_SIZE`: the trees, with the most rounds and the shortest signatures.
    small,
}

impl Tradeoff {
    /// True when the set builds the seed tree and the Merkle tree.
    pub(crate) const fn usesTrees(self) -> bool {
        !matches!(self, Tradeoff::fast)
    }
}

#[cfg(test)]
mod tests {
    use super::Tradeoff;

    #[test]
    fn onlyTheFastSetsHaveNoTrees() {
        assert!(Tradeoff::balanced.usesTrees());
        assert!(Tradeoff::small.usesTrees());
        assert!(!Tradeoff::fast.usesTrees());
    }
}
