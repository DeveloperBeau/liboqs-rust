# oqs-native-entities

The plain data types of the port: algorithm descriptions, key containers and the error type.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- liboqs version: the crate version equals the version of liboqs that the port follows.
- License: `MIT`.

`LICENSE` holds the MIT license of the port. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

Most users depend on [`oqs-native`](https://crates.io/crates/oqs-native), the facade crate, which holds every algorithm behind one registry.

Without the default feature `std`, the crate builds with `core` and `alloc` only.
