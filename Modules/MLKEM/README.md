# oqs-native-ml-kem

ML-KEM, the module-lattice key encapsulation mechanism of FIPS 203, and Kyber, its predecessor of round 3.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- Algorithms: `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`, `Kyber512`, `Kyber768`, `Kyber1024`.
- liboqs version: the crate version equals the version of liboqs that it ports. For the same random bytes, the output is byte-identical to the C library at that version.
- Upstream source: [mlkem-native](https://github.com/pq-code-package/mlkem-native) of the PQ Code Package for ML-KEM, and the reference code of the Kyber team, [pq-crystals/kyber](https://github.com/pq-crystals/kyber), for Kyber, through liboqs `src/kem`.
- License: `MIT AND (Apache-2.0 OR ISC OR MIT) AND (CC0-1.0 OR Apache-2.0)`.

`LICENSE` holds the MIT license of the port. `LICENSE-APACHE` holds the text of the Apache License 2.0. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

Most users depend on [`oqs-native`](https://crates.io/crates/oqs-native), the facade crate, which holds every algorithm behind one registry.

Without the default feature `std`, the crate builds with `core` and `alloc` only.
