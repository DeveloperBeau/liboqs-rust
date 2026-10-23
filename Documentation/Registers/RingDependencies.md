# Ring dependencies

Each crate states its ring in `[package.metadata] ring` in its own `Cargo.toml`. This table says which rings a crate of each ring may depend on. A ring that is not in a list is forbidden. `cargo xtask check-rings` reads this table. A test of that check holds a hand-written copy of the same table, so a change here also changes the test.

| Ring | May depend on | May use in tests | Reason |
|---|---|---|---|
| `entities` | none | none | Plain data. It knows nothing. |
| `domain` | `entities` | none | The interfaces and the logic that uses them. |
| `sharedComponents` | `entities`, `sharedComponents` | none | Primitives such as SHA-3 and AES that more than one family uses. One primitive may use another, for example a random generator built on AES. |
| `infrastructure` | `entities`, `domain`, `sharedComponents`, `infrastructure` | none | Adapters for outside services and test support. The NIST KAT random generator needs AES, so this ring may use shared components. The known-answer programs of the test support build on the known-answer random generators, so this ring may use itself. |
| `features` | `entities`, `domain`, `sharedComponents` | `infrastructure` | One crate for each algorithm family. A family test may use the KAT random generator as its double. |
| `composition` | `entities`, `domain`, `sharedComponents`, `infrastructure`, `features` | none | The facade crate that wires every family and the default random source. |
| `tooling` | `entities`, `domain`, `sharedComponents`, `infrastructure`, `features`, `composition` | none | Repository tools and test-only crates. No ring may depend on tooling. |
