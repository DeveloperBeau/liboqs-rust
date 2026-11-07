# oqs-native-frodokem

FrodoKEM and eFrodoKEM, the key encapsulation mechanisms of the learning with errors problem.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- Algorithms: the six FrodoKEM sets and the six eFrodoKEM sets, from `FrodoKEM-640-AES` to `eFrodoKEM-1344-SHAKE`.
- liboqs version: the crate version equals the version of liboqs that it ports. For the same random bytes, the output is byte-identical to the C library at that version.
- Upstream source: the reference code of the FrodoKEM team, [PQCrypto-LWEKE](https://github.com/microsoft/PQCrypto-LWEKE), through liboqs `src/kem/frodokem`.
- License: `MIT`.

`LICENSE` holds the MIT license of the port. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

Most users depend on [`oqs-native`](https://crates.io/crates/oqs-native), the facade crate, which holds every algorithm behind one registry.

Without the default feature `std`, the crate builds with `core` and `alloc` only.
