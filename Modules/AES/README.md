# oqs-native-aes

Constant-time bitsliced AES-128 and AES-256 in ECB and CTR modes, and Rijndael with a 256-bit block, as liboqs uses them.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- liboqs version: the crate version equals the version of liboqs that it ports. For the same random bytes, the output is byte-identical to the C library at that version.
- Upstream source: the `aes_ct64` code of BearSSL by Thomas Pornin, through liboqs `src/common/aes/aes_c.c`, and the bitsliced Rijndael-256 of the MQOM team.
- License: `MIT`.

`LICENSE` holds the MIT license of the port. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

Most users depend on [`oqs-native`](https://crates.io/crates/oqs-native), the facade crate, which holds every algorithm behind one registry.

Without the default feature `std`, the crate builds with `core` only.
