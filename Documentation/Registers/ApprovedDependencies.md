# Approved dependencies

A crate may use a third-party crate only when this table lists it for that crate. The owner approves each row. `cargo xtask check-rings` rejects every other third-party crate. The `Used by` column holds package names, `*` for every crate, or `none` for an approval that no crate uses yet.

| Dependency | Used by | Kind | Reason |
|---|---|---|---|
| `libfuzzer-sys` | none | test only | The fuzz targets of `cargo-fuzz`. Approved on 2026-10-23. |
