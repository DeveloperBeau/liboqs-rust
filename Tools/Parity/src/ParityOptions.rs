use crate::ParitySettings;

/// The options of a command of the `parity` program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityOptions {
    /// The case count, the seed and the shard of the run.
    pub settings: ParitySettings,
    /// The algorithms of `--only`, or every algorithm when empty.
    pub names: Vec<String>,
    /// True with `--all`: the known-answer run also compares the digests of every count.
    pub isAll: bool,
    /// True with `--check`: the snapshot run compares each digest with the frozen snapshot.
    pub isCheck: bool,
    /// The count of `--processes`, or `None` to run in this process.
    pub processCount: Option<u64>,
}

impl ParityOptions {
    /// Reads the options that follow the command word.
    pub fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut options = ParityOptions {
            settings: ParitySettings::new(ParitySettings::fullCaseCount),
            names: Vec::new(),
            isAll: false,
            isCheck: false,
            processCount: None,
        };
        let mut remaining = arguments.iter();
        while let Some(argument) = remaining.next() {
            let mut value = || {
                remaining
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("{argument} needs a value"))
            };
            match argument.as_str() {
                "--cases" => {
                    let cases = value()?;
                    options.settings.caseCount = cases
                        .parse()
                        .map_err(|_| format!("--cases `{cases}` is not a number"))?;
                }
                "--seed" => {
                    let seed = value()?;
                    options.settings.seed = ParitySettings::fromVariables(None, Some(&seed), 0)
                        .map_err(|_| format!("--seed `{seed}` is not a number"))?
                        .seed;
                }
                "--shard" => {
                    let shard = value()?;
                    options.settings = options.settings.withShard(&shard)?;
                }
                "--only" => options.names.push(value()?),
                "--all" => options.isAll = true,
                "--check" => options.isCheck = true,
                "--processes" => {
                    let count = value()?;
                    options.processCount = Some(
                        count
                            .parse::<u64>()
                            .ok()
                            .filter(|count| *count > 0)
                            .ok_or_else(|| {
                                format!("--processes `{count}` is not a count above zero")
                            })?,
                    );
                }
                unknown => return Err(format!("unknown option `{unknown}`")),
            }
        }
        Ok(options)
    }

    /// True when the run checks the algorithm at a position of its list.
    pub fn isSelected(&self, position: usize, name: &str) -> bool {
        self.settings.includes(position)
            && (self.names.is_empty() || self.names.iter().any(|selected| selected == name))
    }

    /// The options of each process of `--processes`, without `--processes`, each with its
    /// shard.
    ///
    /// Process `j` of the shard `index/count` takes the shard `index + j * count` of
    /// `count * processCount`, so together the processes take each position of the shard once.
    pub fn processArguments(arguments: &[String], options: &ParityOptions) -> Vec<Vec<String>> {
        let Some(processCount) = options.processCount else {
            return Vec::new();
        };
        let mut kept = Vec::new();
        let mut remaining = arguments.iter();
        while let Some(argument) = remaining.next() {
            if argument == "--processes" || argument == "--shard" {
                remaining.next();
            } else {
                kept.push(argument.clone());
            }
        }
        let shardCount = options.settings.shardCount * processCount;
        (0..processCount)
            .map(|process| {
                let shardIndex =
                    options.settings.shardIndex + process * options.settings.shardCount;
                let mut childArguments = kept.clone();
                childArguments.push("--shard".to_string());
                childArguments.push(format!("{shardIndex}/{shardCount}"));
                childArguments
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::ParityOptions;
    use crate::ParitySettings;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn noOptionsGiveTheFullGateOverEveryAlgorithm() {
        let options = ParityOptions::parse(&[]).expect("valid");
        assert_eq!(options.settings, ParitySettings::new(1000));
        assert!(options.names.is_empty());
        assert!(!options.isAll && !options.isCheck);
        assert_eq!(options.processCount, None);
        assert!(options.isSelected(5, "ML-KEM-768"));
    }

    #[test]
    fn eachOptionSetsItsValue() {
        let options = ParityOptions::parse(&words(
            "--cases 7 --seed 0x10 --shard 1/3 --only A --only B --all --check --processes 2",
        ))
        .expect("valid");
        assert_eq!(options.settings.caseCount, 7);
        assert_eq!(options.settings.seed, 16);
        assert_eq!(
            (options.settings.shardIndex, options.settings.shardCount),
            (1, 3)
        );
        assert_eq!(options.names, vec!["A", "B"]);
        assert!(options.isAll && options.isCheck);
        assert_eq!(options.processCount, Some(2));
    }

    #[test]
    fn wrongOptionsAreErrorsThatNameTheOption() {
        for (arguments, message) in [
            ("--cases", "--cases needs a value"),
            ("--cases x", "--cases `x` is not a number"),
            ("--seed y", "--seed `y` is not a number"),
            ("--processes 0", "--processes `0` is not a count above zero"),
            ("--processes z", "--processes `z` is not a count above zero"),
            ("--fast", "unknown option `--fast`"),
        ] {
            assert_eq!(
                ParityOptions::parse(&words(arguments)),
                Err(message.to_string()),
                "{arguments}"
            );
        }
        assert!(ParityOptions::parse(&words("--shard 4/4")).is_err());
    }

    #[test]
    fn selectionTakesTheShardAndTheNamedAlgorithms() {
        let options = ParityOptions::parse(&words("--shard 1/2 --only B")).expect("valid");
        assert!(options.isSelected(1, "B"));
        assert!(!options.isSelected(1, "A"));
        assert!(!options.isSelected(2, "B"));
    }

    #[test]
    fn processesSplitTheShardSoThatTogetherTheyTakeEachPositionOnce() {
        let arguments = words("--cases 5 --shard 1/2 --processes 3");
        let options = ParityOptions::parse(&arguments).expect("valid");
        let children = ParityOptions::processArguments(&arguments, &options);
        assert_eq!(
            children,
            vec![
                words("--cases 5 --shard 1/6"),
                words("--cases 5 --shard 3/6"),
                words("--cases 5 --shard 5/6"),
            ]
        );
        let childOptions: Vec<ParityOptions> = children
            .iter()
            .map(|child| ParityOptions::parse(child).expect("valid"))
            .collect();
        for position in 0..60 {
            let takers = childOptions
                .iter()
                .filter(|child| child.isSelected(position, "A"))
                .count();
            assert_eq!(
                takers,
                usize::from(options.isSelected(position, "A")),
                "{position}"
            );
        }
        assert!(
            ParityOptions::processArguments(
                &words("--cases 5"),
                &ParityOptions::parse(&words("--cases 5")).expect("valid")
            )
            .is_empty()
        );
    }
}
