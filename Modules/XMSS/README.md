# oqs-native-xmss

XMSS and XMSS^MT, the hash-based stateful signatures of RFC 8391.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- Algorithms: the 21 XMSS sets and the 16 XMSS^MT sets.
- liboqs version: the crate version equals the version of liboqs that it ports. For the same random bytes, the output is byte-identical to the C library at that version.
- Upstream source: the XMSS code of SandboxAQ, after the [XMSS reference implementation](https://github.com/XMSS/xmss-reference) of Andreas Hülsing and Joost Rijneveld, through liboqs `src/sig_stfl/xmss`.
- License: `MIT AND (Apache-2.0 OR MIT) AND CC0-1.0`.

`LICENSE` holds the MIT license of the port. `LICENSE-APACHE` holds the text of the Apache License 2.0. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

Most users depend on [`oqs-native`](https://crates.io/crates/oqs-native), the facade crate, which holds every algorithm behind one registry.

Without the default feature `std`, the crate builds with `core` and `alloc` only.
