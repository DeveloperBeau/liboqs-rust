/// The settings of a parity run: how many variations each algorithm runs, the seed of the
/// variations, and the part of the algorithms that this process checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParitySettings {
    /// The number of variations of each algorithm, after its base case.
    pub caseCount: u64,
    /// The seed of every variation input. A failure prints it, so a run can repeat the case.
    pub seed: u64,
    /// The shard of this process, from 0.
    pub shardIndex: u64,
    /// The number of shards. Algorithm `n` of the registry belongs to shard `n % shardCount`.
    pub shardCount: u64,
}

impl ParitySettings {
    /// The number of variations of the full parity gate.
    pub const fullCaseCount: u64 = 1000;
    /// The seed of a run that gives no seed.
    pub const defaultSeed: u64 = 0x0016_0000_4F51_5300;

    /// Settings with a case count, the default seed and one shard.
    pub fn new(caseCount: u64) -> Self {
        ParitySettings {
            caseCount,
            seed: Self::defaultSeed,
            shardIndex: 0,
            shardCount: 1,
        }
    }

    /// Reads the settings of a test run from the values of `PARITY_CASES` and `PARITY_SEED`.
    /// A missing value takes the default case count or the default seed.
    pub fn fromVariables(
        cases: Option<&str>,
        seed: Option<&str>,
        defaultCaseCount: u64,
    ) -> Result<Self, String> {
        let mut settings = ParitySettings::new(defaultCaseCount);
        if let Some(cases) = cases {
            settings.caseCount = Self::number(cases)
                .ok_or_else(|| format!("PARITY_CASES `{cases}` is not a number"))?;
        }
        if let Some(seed) = seed {
            settings.seed = Self::number(seed)
                .ok_or_else(|| format!("PARITY_SEED `{seed}` is not a number"))?;
        }
        Ok(settings)
    }

    /// Reads the settings of a test run from the environment, with a default case count.
    pub fn fromEnvironment(defaultCaseCount: u64) -> Self {
        let cases = std::env::var("PARITY_CASES").ok();
        let seed = std::env::var("PARITY_SEED").ok();
        Self::fromVariables(cases.as_deref(), seed.as_deref(), defaultCaseCount)
            .unwrap_or_else(|message| panic!("{message}"))
    }

    /// Reads a shard as `index/count`, such as `2/8`.
    pub fn withShard(mut self, shard: &str) -> Result<Self, String> {
        let invalid = || format!("the shard `{shard}` is not of the form index/count");
        let (index, count) = shard.split_once('/').ok_or_else(invalid)?;
        let index = Self::number(index).ok_or_else(invalid)?;
        let count = Self::number(count).ok_or_else(invalid)?;
        if count == 0 || index >= count {
            return Err(format!(
                "the shard `{shard}` needs an index below a count above zero"
            ));
        }
        self.shardIndex = index;
        self.shardCount = count;
        Ok(self)
    }

    /// True when the algorithm at a position of the registry belongs to this shard.
    pub fn includes(&self, position: usize) -> bool {
        position as u64 % self.shardCount == self.shardIndex
    }

    /// A decimal number, or a hexadecimal number after `0x`.
    fn number(text: &str) -> Option<u64> {
        let text = text.trim();
        match text.strip_prefix("0x") {
            Some(hexadecimal) => u64::from_str_radix(hexadecimal, 16).ok(),
            None => text.parse().ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ParitySettings;

    #[test]
    fn missingVariablesTakeTheDefaults() {
        assert_eq!(
            ParitySettings::fromVariables(None, None, 10),
            Ok(ParitySettings::new(10))
        );
        assert_eq!(ParitySettings::new(3).seed, ParitySettings::defaultSeed);
    }

    #[test]
    fn variablesSetTheCountAndTheSeedInDecimalOrHexadecimal() {
        let settings =
            ParitySettings::fromVariables(Some("1000"), Some("0x1F"), 10).expect("valid");
        assert_eq!((settings.caseCount, settings.seed), (1000, 31));
        let settings = ParitySettings::fromVariables(Some(" 7 "), Some("12"), 10).expect("valid");
        assert_eq!((settings.caseCount, settings.seed), (7, 12));
    }

    #[test]
    fn wrongVariablesAreErrorsThatNameTheVariable() {
        assert_eq!(
            ParitySettings::fromVariables(Some("many"), None, 10),
            Err("PARITY_CASES `many` is not a number".to_string())
        );
        assert_eq!(
            ParitySettings::fromVariables(None, Some("0xZZ"), 10),
            Err("PARITY_SEED `0xZZ` is not a number".to_string())
        );
    }

    #[test]
    fn aShardTakesEveryAlgorithmWhosePositionMatchesItsIndex() {
        let settings = ParitySettings::new(1)
            .withShard("1/3")
            .expect("valid shard");
        let positions: Vec<usize> = (0..10)
            .filter(|position| settings.includes(*position))
            .collect();
        assert_eq!(positions, vec![1, 4, 7]);
        let whole = ParitySettings::new(1);
        assert!((0..10).all(|position| whole.includes(position)));
    }

    #[test]
    fn aWrongShardIsAnError() {
        for shard in ["3", "3/3", "1/0", "a/2", "1/b"] {
            assert!(ParitySettings::new(1).withShard(shard).is_err(), "{shard}");
        }
    }
}
