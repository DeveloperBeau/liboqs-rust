# Upstream sources

Each row names one Rust module, the upstream liboqs path that it translates at the tag in `LIBOQS_VERSION`, the project that liboqs took the code from, and the SHA-256 of the upstream folder. The update procedure uses this table to find the modules that a new liboqs release changes.

The folder SHA-256 is the SHA-256 of each file under the upstream paths of the row, in byte order of their paths relative to the liboqs root. Each file adds its relative path, a zero byte, its bytes and a zero byte. A path can be a folder or a file.

| Rust module | Upstream path | Upstream project and commit | Folder SHA-256 | License |
|---|---|---|---|---|
| `Modules/AES` | `src/common/aes/aes_c.c`, `src/common/aes/aes.h` | liboqs, based on BearSSL | `ece3104f459dc3235a67a60bec70527d5e5885eb4734671ab4744074e27f6891` | MIT |
| `Modules/SHA2` | `src/common/sha2/sha2.h`, `src/common/sha2/sha2_c.c` | liboqs (API only, the code is written from FIPS 180-4) | `feb5fd5003bb0e324b859d894e09116ee7a1ff4ff31f9439d49bf80aebec382e` | MIT (port) |
| `Modules/SHA3` | `src/common/sha3/sha3.h`, `src/common/sha3/xkcp_sha3.c`, `src/common/pqclean_shims/fips202.h` | liboqs (API only, the code is written from FIPS 202) | `c33c7d6906ca3dc1dbcab090061b6225300431f3a9d07d9421041f1c2f33c20c` | MIT (port) |
