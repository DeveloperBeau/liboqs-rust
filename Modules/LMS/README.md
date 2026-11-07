# oqs-native-lms

LMS and HSS, the hash-based stateful signatures of RFC 8554.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- Algorithms: the 33 sets from `LMS_SHA256_H5_W1` to `LMS_SHA256_H20_W8_H20_W8`.
- liboqs version: the crate version equals the version of liboqs that it ports. For the same random bytes, the output is byte-identical to the C library at that version.
- Upstream source: the hash-sigs code of Cisco, [cisco/hash-sigs](https://github.com/cisco/hash-sigs), through liboqs `src/sig_stfl/lms`.
- License: `MIT AND BSD-3-Clause`.

`LICENSE` holds the MIT license of the port. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

Most users depend on [`oqs-native`](https://crates.io/crates/oqs-native), the facade crate, which holds every algorithm behind one registry.

Without the default feature `std`, the crate builds with `core` and `alloc` only.
