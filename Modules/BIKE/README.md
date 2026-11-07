# oqs-native-bike

BIKE, the Bit Flipping Key Encapsulation.

The crate is part of [liboqs-rust](https://github.com/DeveloperBeau/liboqs-rust), a native Rust port of [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe library. It holds no C code. The project is independent, and it is not affiliated with or endorsed by the Open Quantum Safe project.

- Algorithms: `BIKE-L1`, `BIKE-L3`, `BIKE-L5`.
- liboqs version: the crate version equals the version of liboqs that it ports. For the same random bytes, the output is byte-identical to the C library at that version.
- Upstream source: the additional implementation of round 4 by the AWS Cryptographic Algorithms Group, [awslabs/bike-kem](https://github.com/awslabs/bike-kem), through liboqs `src/kem/bike/additional_r4`.
- License: `MIT AND Apache-2.0`.

`LICENSE` holds the MIT license of the port. `LICENSE-APACHE` holds the text of the Apache License 2.0. `THIRD_PARTY_NOTICES.md` names the authors and the license of each upstream project.

Most users depend on [`oqs-native`](https://crates.io/crates/oqs-native), the facade crate, which holds every algorithm behind one registry.

Without the default feature `std`, the crate builds with `core` and `alloc` only.
