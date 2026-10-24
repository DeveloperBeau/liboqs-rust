# Architecture

Each page describes one subsystem as the code is today: its purpose, its crates, its data flow, its edge cases and its tests.

| Page | Subsystem | Current |
|---|---|---|
| [Rings.md](Rings.md) | The workspace layout and the ring rule | Yes |
| [Entities.md](Entities.md) | The plain data types | Yes |
| [Domain.md](Domain.md) | The capability interfaces and their rules | Yes |
| [Primitives.md](Primitives.md) | SHA-3, SHA-2, AES and the sorting network | Yes |
| [Randomness.md](Randomness.md) | The random sources | Yes |
| [Registry.md](Registry.md) | The facade crate and the registry of algorithms | Yes |
| [Oracle.md](Oracle.md) | The C library as the test oracle, and `cargo xtask fetch-oracle` | Yes |
| [KnownAnswerPrograms.md](KnownAnswerPrograms.md) | The liboqs test programs on the Rust interfaces, and the test vector files | Yes |
| [Parity.md](Parity.md) | The parity checks with the C library and the parity program | Yes |
| [MLKEM.md](MLKEM.md) | ML-KEM and Kyber | Yes |
| [FrodoKEM.md](FrodoKEM.md) | FrodoKEM and eFrodoKEM | Yes |
| [HQC.md](HQC.md) | HQC | Yes |
| [BIKE.md](BIKE.md) | BIKE | Yes |
| [NTRU.md](NTRU.md) | NTRU-HPS and NTRU-HRSS | Yes |
| [NTRUPrime.md](NTRUPrime.md) | Streamlined NTRU Prime, sntrup761 | Yes |
| [MLDSA.md](MLDSA.md) | ML-DSA | Yes |
| [Falcon.md](Falcon.md) | Falcon | Yes |
| [MAYO.md](MAYO.md) | MAYO | Yes |
| [RepositoryChecks.md](RepositoryChecks.md) | The `cargo xtask` checks for rings, names, versions, hygiene and unsafe code | Yes |
| [Versioning.md](Versioning.md) | How the crate version follows the liboqs version | Yes |
