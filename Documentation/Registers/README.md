# Registers

A register is the one owner of a rule that needs a list. A change that adds an item to a rule adds its row to the register in the same change. The repository checks read some registers directly, so the register and the check cannot disagree.

| Register | Owner of | Read by |
|---|---|---|
| [RingDependencies.md](RingDependencies.md) | The rings and which ring may depend on which | `cargo xtask check-rings` |
| [ApprovedDependencies.md](ApprovedDependencies.md) | The third-party crates that the owner approved | `cargo xtask check-rings` |
| [Acronyms.md](Acronyms.md) | The acronyms that a name writes as one unit | `cargo xtask check-names` |
| [NamingExceptions.md](NamingExceptions.md) | The names that a language or framework forces into another form | `cargo xtask check-names` |
| [UnsafeCode.md](UnsafeCode.md) | The files that may hold `unsafe` code, each with its reason | `cargo xtask check-unsafe` |
| [UpstreamSources.md](UpstreamSources.md) | The upstream liboqs source that each Rust module translates | People. A later tool reads it. |
| [MutationResults.md](MutationResults.md) | The mutation results for each rule and the test that kills each mutant | People |
