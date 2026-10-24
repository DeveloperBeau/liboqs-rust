# Unsafe code

A file may hold `unsafe` code only when this table lists it with its reason. The workspace sets the lint `unsafe_code` to `deny`, so each use also needs `#[allow(unsafe_code)]` at its site. `cargo xtask check-unsafe` rejects `unsafe` code in any other file, and a row whose file no longer holds `unsafe` code.

| File | Reason |
|---|---|
| `Modules/Entities/src/SecretBytes.rs` | `wipe` writes zero over secret bytes with `core::ptr::write_volatile`, so the optimizer cannot remove the writes as dead stores. |
| `Modules/COracle/src/COracle.rs` | The test-only C oracle calls the C library of liboqs through its foreign function interface. Each call passes buffers of the lengths that the C code reads, and the oracle checks each input length first. No shipped crate depends on the oracle. |
