# Upstream sources

Each row names one Rust module, the upstream liboqs path that it translates at the tag in `LIBOQS_VERSION`, the project that liboqs took the code from, and the SHA-256 of the upstream folder. The update procedure uses this table to find the modules that a new liboqs release changes.

The folder SHA-256 is the SHA-256 of each file under the upstream paths of the row, in byte order of their paths relative to the liboqs root. Each file adds its relative path, a zero byte, its bytes and a zero byte. A path can be a folder or a file.

| Rust module | Upstream path | Upstream project and commit | Folder SHA-256 | License |
|---|---|---|---|---|
| `Modules/AES` | `src/common/aes/aes_c.c`, `src/common/aes/aes.h` | liboqs, based on BearSSL | `ece3104f459dc3235a67a60bec70527d5e5885eb4734671ab4744074e27f6891` | MIT |
| `Modules/SHA2` | `src/common/sha2/sha2.h`, `src/common/sha2/sha2_c.c` | liboqs (API only, the code is written from FIPS 180-4) | `feb5fd5003bb0e324b859d894e09116ee7a1ff4ff31f9439d49bf80aebec382e` | MIT (port) |
| `Modules/SHA3` | `src/common/sha3/sha3.h`, `src/common/sha3/xkcp_sha3.c`, `src/common/pqclean_shims/fips202.h` | liboqs (API only, the code is written from FIPS 202) | `c33c7d6906ca3dc1dbcab090061b6225300431f3a9d07d9421041f1c2f33c20c` | MIT (port) |
| `Modules/KATRandom` (`NISTKATRandom`) | `src/common/rand/rand_nist.c`, `src/common/rand/rand_nist.h` | liboqs, NIST-developed software | `fb764db1a65d68c010683fa0c3ac3dac0f99f636862b1b56363f8485bdf1614c` | NIST notice |
| `Modules/KATRandom` (`HQCKATRandom`) | `tests/test_helpers.c` | liboqs | `b474a24e80c93ae8722f2378037fcf284689f65efe7a28657e3ce6f21af628c1` | MIT |
| `Modules/AlgorithmTests` (`KEMKnownAnswerTest`, `KnownAnswerText`) | `tests/kat_kem.c` | liboqs | `c824bafeae91add06df1a18de1ba71536bf07daea12f5dee6d1d671fa7431396` | MIT |
| `Modules/AlgorithmTests` (`SignatureKnownAnswerTest`, `SignedMessageForm`) | `tests/kat_sig.c` | liboqs | `6f30abe37d6cca6572eb0acc624ca94d9dbc7e90b244b9a348a560291f356724` | MIT |
| `Modules/AlgorithmTests` (`KnownAnswerRandom`) | `tests/test_helpers.c` | liboqs | `b474a24e80c93ae8722f2378037fcf284689f65efe7a28657e3ce6f21af628c1` | MIT |
| `Modules/AlgorithmTests` (`Data`, copies of the digest files) | `tests/KATs/kem/kats.json`, `tests/KATs/sig/kats.json` | liboqs | `82d82e2368b5bed1941a83eb582f71724243261c2151455ca4d4f88abd46f14a` | MIT |
| `Modules/MLKEM` (`MLKEM`) | `src/kem/ml_kem/mlkem-native_ml-kem-512_ref`, `src/kem/ml_kem/mlkem-native_ml-kem-768_ref`, `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref`, `src/kem/ml_kem/kem_ml_kem_512.c`, `src/kem/ml_kem/kem_ml_kem_768.c`, `src/kem/ml_kem/kem_ml_kem_1024.c` | mlkem-native, commit `0ba906cb` | `a9169af4b3d341e88551ddfc8151b15d43a0e80e2959230a92ecb9c1d0d4c6e2` | Apache-2.0 OR ISC OR MIT |
| `Modules/MLKEM` (`Kyber`) | `src/kem/kyber/pqcrystals-kyber_kyber512_ref`, `src/kem/kyber/pqcrystals-kyber_kyber768_ref`, `src/kem/kyber/pqcrystals-kyber_kyber1024_ref`, `src/kem/kyber/kem_kyber_512.c`, `src/kem/kyber/kem_kyber_768.c`, `src/kem/kyber/kem_kyber_1024.c` | pq-crystals/kyber, commit `441c0519` with liboqs patches | `f4d12175f026726ab2a67b89f38f4a76cd159ddaf75b570f4ec1b5f3b4f50b60` | CC0-1.0 OR Apache-2.0 |
| `Modules/AlgorithmTests` (`KEMCorrectnessTest`) | `tests/test_kem.c` | liboqs | `7f2ece2fc815fd41490d2e722375fdfd0663af658121a371ddd86be46f01bda0` | MIT |
| `Modules/AlgorithmTests` (`KEMFuzzTest`, `FuzzRandom`) | `tests/fuzz_test_kem.c` | liboqs | `07c80dd655845ef62667f3804172ba0a13edb773e4fc2ecbd794f49dd9325725` | MIT |
| `Modules/AlgorithmTests` (`KEMMemoryTest`) | `tests/test_kem_mem.c` | liboqs | `be8b8f563ff6848dc8603e34cd5753b6b388aea687759eabc53755a445330909` | MIT |
| `Modules/AlgorithmTests` (`SignatureCorrectnessTest`) | `tests/test_sig.c`, `tests/test_helpers.c` | liboqs | `acfc9b8e1efdab66ef9831f6472f96286b1f9fb0af5f8b80324ad2ba0fa6ec39` | MIT |
| `Modules/AlgorithmTests` (`SignatureFuzzTest`) | `tests/fuzz_test_sig.c` | liboqs | `8bd4a5e34512bdf021fcb9c8c4b7bfc31e23963a800cd46ae575a421fd83eea0` | MIT |
| `Modules/AlgorithmTests` (`SignatureMemoryTest`) | `tests/test_sig_mem.c` | liboqs | `a36939b3124a5713423d32efa0d1b61f7088d22d762f5e2675099aad23b2f966` | MIT |
