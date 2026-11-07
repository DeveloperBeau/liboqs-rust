# oqs-native-ntru

NTRU, the NTRU-HPS and NTRU-HRSS key encapsulation mechanisms.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- Algorithms: `NTRU-HPS-2048-509`, `NTRU-HPS-2048-677`, `NTRU-HPS-4096-821`, `NTRU-HPS-4096-1229`, `NTRU-HRSS-701`, `NTRU-HRSS-1373`.
- liboqs version: the crate version equals the version of liboqs that it ports. For the same random bytes, the output is byte-identical to the C library at that version.
- Upstream source: the clean code of [PQClean](https://github.com/PQClean/PQClean), after the reference code of the NTRU team, through liboqs `src/kem/ntru`.
- License: `MIT`.

`LICENSE` holds the MIT license of the port. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

Most users depend on [`oqs-native`](https://crates.io/crates/oqs-native), the facade crate, which holds every algorithm behind one registry.

Without the default feature `std`, the crate builds with `core` and `alloc` only.
