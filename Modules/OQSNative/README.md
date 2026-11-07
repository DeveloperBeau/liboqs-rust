# oqs-native

Post-quantum key encapsulation mechanisms and signature schemes for Rust, a native port of liboqs.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- Algorithms: every algorithm of liboqs, found by its liboqs name through `Registry`.
- liboqs version: the crate version equals the version of liboqs that it ports. For the same random bytes, the output is byte-identical to the C library at that version.
- License: `MIT`.

`LICENSE` holds the MIT license of the port. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

The crate re-exports every family, the capability interfaces and the data types, so a user needs only this crate. Each operation takes its random source as an argument, and `SystemRandom` is the random source of the operating system.

Without the default feature `std`, the crate builds with `core` and `alloc` only, and has no system random source.
