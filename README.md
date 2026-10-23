# liboqs-rust

Post-quantum cryptography for Rust: a native port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library of key encapsulation mechanisms and signature schemes.

This is not a set of bindings. The port is Rust code with no C in any shipped crate and no system library to install. The C library is used only in the tests, as an oracle. Every algorithm must give output that is byte-identical to the C library for the same random bytes.

This project is free and open source. It is an independent port. It is not affiliated with or endorsed by the Open Quantum Safe project. All credit for the algorithms and for liboqs goes to their authors. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Status

The port is in progress. The repository holds the workspace, the standards, the repository checks, the shared primitives, the random sources and the parity harness, and these families:

| Family | Algorithms | Status |
|---|---|---|
| ML-KEM | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | Ported, identical to the C library |
| Kyber | `Kyber512`, `Kyber768`, `Kyber1024` | Ported, identical to the C library |
| FrodoKEM | `FrodoKEM-640-AES`, `FrodoKEM-640-SHAKE`, `FrodoKEM-976-AES`, `FrodoKEM-976-SHAKE`, `FrodoKEM-1344-AES`, `FrodoKEM-1344-SHAKE` | Ported, identical to the C library |
| eFrodoKEM | `eFrodoKEM-640-AES`, `eFrodoKEM-640-SHAKE`, `eFrodoKEM-976-AES`, `eFrodoKEM-976-SHAKE`, `eFrodoKEM-1344-AES`, `eFrodoKEM-1344-SHAKE` | Ported, identical to the C library |
| HQC | `HQC-1`, `HQC-3`, `HQC-5` | Ported, identical to the C library |
| BIKE | `BIKE-L1`, `BIKE-L3`, `BIKE-L5` | Ported, identical to the C library |
| ML-DSA | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | Ported, identical to the C library |
| Falcon | `Falcon-512`, `Falcon-1024`, `Falcon-padded-512`, `Falcon-padded-1024` | Ported, identical to the C library |

`Tools/Parity/NotYetPorted.txt` lists each algorithm of liboqs that the port does not have yet.

## Versions

The version of each crate equals the version of liboqs that it ports. `LIBOQS_VERSION` holds that version, and `cargo xtask check-versions` fails when another copy disagrees. The tests always run against the C library at the same version.

## Build and test

The tests compare the port with the C library, so the first step builds the C library at the version in `LIBOQS_VERSION`. It needs `git`, `cmake` and a C compiler, and writes to `target/oracle/`.

```sh
cargo xtask fetch-oracle
cargo build --workspace
cargo test --workspace
cargo xtask check
```

`cargo xtask check` runs the repository checks: rings, names, versions, hygiene and unsafe code. The full parity gate runs 1000 seeded variations of each algorithm against the C library:

```sh
cargo run --release -p oqs-native-parity -- run --processes 4
cargo run --release -p oqs-native-parity -- snapshot --check --processes 4
cargo run --release -p oqs-native-parity -- known-answers --all --processes 4
```

See [standards.md](standards.md) for the rules and [Documentation/Architecture/README.md](Documentation/Architecture/README.md) for how the code works.

## License

MIT. See [LICENSE](LICENSE).

liboqs is MIT licensed. The algorithm implementations in liboqs come from many teams under several licenses. Each family crate of this port keeps the license and the credit of the code that it translates.
