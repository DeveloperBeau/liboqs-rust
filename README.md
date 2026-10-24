# liboqs-rust

Post-quantum cryptography for Rust: a native port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library of key encapsulation mechanisms and signature schemes.

This is not a set of bindings. The port is Rust code with no C in any shipped crate and no system library to install. The C library is used only in the tests, as an oracle. Every algorithm must give output that is byte-identical to the C library for the same random bytes.

This project is free and open source. It is an independent port. It is not affiliated with or endorsed by the Open Quantum Safe project. All credit for the algorithms and for liboqs goes to their authors. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Status

The port is at its start. The repository holds the workspace, the standards and the repository checks. No algorithm is ported yet.

## Versions

The version of each crate equals the version of liboqs that it ports. `LIBOQS_VERSION` holds that version, and `cargo xtask check-versions` fails when another copy disagrees. The tests always run against the C library at the same version.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo xtask check
```

`cargo xtask check` runs the repository checks: rings, names, versions and hygiene. See [standards.md](standards.md) for the rules and [Documentation/Architecture/README.md](Documentation/Architecture/README.md) for how the code works.

## License

MIT. See [LICENSE](LICENSE).

liboqs is MIT licensed. The algorithm implementations in liboqs come from many teams under several licenses. Each family crate of this port keeps the license and the credit of the code that it translates.
