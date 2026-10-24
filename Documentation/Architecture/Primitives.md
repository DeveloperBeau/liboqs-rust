# Primitives

## Purpose

Three crates of the `sharedComponents` ring give the symmetric primitives that the algorithm families use. Each follows the API of liboqs `src/common`, so a translated family calls a primitive in the same order and with the same amounts as the C code.

| Crate | Folder | Library | Gives |
|---|---|---|---|
| `oqs-native-sha3` | `Modules/SHA3` | `OQSNativeSHA3` | `SHA3224`, `SHA3256`, `SHA3384`, `SHA3512`, `SHAKE128`, `SHAKE256`, `SHAKEReader`, `KeccakF1600` |
| `oqs-native-sha2` | `Modules/SHA2` | `OQSNativeSHA2` | `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA512224`, `SHA512256` |
| `oqs-native-aes` | `Modules/AES` | `OQSNativeAES` | `AES128`, `AES256` |

Each crate builds without the standard library.

The hash API of liboqs `src/common` has no SHA-224, SHA-512/224, SHA-512/256 or SHA3-224. The C code of SLH-DSA holds its own copies for its pre-hash parameter sets, and the ML-DSA vector tests of liboqs compute them with Python `hashlib`. The port gives them in the shared crates, with the same API as the other hashes.

## SHA-3 and SHAKE

`KeccakSponge` (private) holds the 25 lanes of the state, the rate and the byte position in the current block. A hash absorbs input in any number of calls and gives its digest in `finalize`. A SHAKE function absorbs input and `finalize` returns a `SHAKEReader`. The reader squeezes the output stream in any number of calls, and the stream is the same however the calls split it, as with liboqs `inc_squeeze`. The `squeezeblocks` of PQClean code is a squeeze of whole blocks.

The types are typestates: an absorbing function has no `squeeze`, and a reader has no `absorb`. So the misuse "absorb after finalize" cannot compile. A clone of either type is the `inc_ctx_clone` of liboqs.

The four-way forms of liboqs (`shake128_x4`) are a speed form. The port computes four separate functions, which give the same bytes.

`KeccakF1600::permute` is public for a family that uses the permutation directly, as SNOVA does.

## SHA-2

`SHA256` and `SHA512Core` (private, shared by `SHA384`, `SHA512`, `SHA512224` and `SHA512256`) hold the state, the partial block and the total length. `SHA224` is a `SHA256` with the initial hash value of SHA-224. A truncated form starts from its own initial hash value and gives the first bytes of the final state. `absorb` takes any number of bytes, so the `inc_blocks` of liboqs (whole blocks) and its `inc_finalize` (the rest) map to `absorb` and `finalize`.

## AES

`Bitsliced.rs` translates the constant-time bitsliced AES of liboqs `aes_c.c` (BearSSL `aes_ct64`). It has no table lookup and no branch on the key or the data. `ExpandedKey` holds the bitsliced round keys and encrypts four blocks at a time.

- `encryptBlocks` is ECB mode, as `OQS_AES128_ECB_enc_sch`. A partial block is a panic, as the C code asserts.
- `fillCounterKeystream` is `OQS_AES*_CTR_inc_stream_iv`. A 12-byte vector starts the counter at zero. A 16-byte vector is the first counter block. Another length is a panic, as the C code exits.
- `fillCounterBlocks` is `aes*_ctr_upd_blks`: it continues from a counter block and advances it.

The counter is the last four bytes of the counter block as a big-endian 32-bit number. It wraps from `ffffffff` to `00000000`, and the first twelve bytes do not change.

## Tests

- `Modules/SHA3/tests/UpstreamKnownAnswers.rs` replicates `tests/test_sha3.c` with its vectors, copied from that file: the one-shot forms, the incremental forms, small absorb and squeeze calls, clones and fresh states.
- `KeccakF1600` is checked against the reference states of the Keccak team for the zero state.
- `Modules/SHA2/tests/KnownAnswers.rs` checks the FIPS 180-4 examples, with one million `a` bytes, and every split of every input length up to three blocks, across each padding edge. SHA-224, SHA-512/224 and SHA-512/256 also match Python `hashlib` at each padding edge.
- `Modules/SHA3/tests/HashlibKnownAnswers.rs` checks SHA3-224 against the SHA-3 examples and Python `hashlib`, at the edges of its rate of 144 bytes and in pieces.
- `Modules/AES/tests/KnownAnswers.rs` replicates `tests/test_aes.c` (FIPS 197 blocks, RFC 3686 counter vectors) and proves the counter rules with counter blocks built by hand, the wrap at 32 bits, the continuation of `fillCounterBlocks` and each misuse panic.
- The parity tests of the facade crate compare each primitive with the C library.
