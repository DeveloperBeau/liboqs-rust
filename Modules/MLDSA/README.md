# oqs-native-ml-dsa

ML-DSA, the module-lattice digital signature algorithm of FIPS 204.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- Algorithms: `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`.
- liboqs version: the crate version equals the version of liboqs that it ports. For the same random bytes, the output is byte-identical to the C library at that version.
- Upstream source: [mldsa-native](https://github.com/pq-code-package/mldsa-native) of the PQ Code Package, through liboqs `src/sig/ml_dsa`.
- License: `MIT AND (Apache-2.0 OR ISC OR MIT)`.

`LICENSE` holds the MIT license of the port. `LICENSE-APACHE` holds the text of the Apache License 2.0. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

Most users depend on [`oqs-native`](https://crates.io/crates/oqs-native), the facade crate, which holds every algorithm behind one registry.

Without the default feature `std`, the crate builds with `core` and `alloc` only.
