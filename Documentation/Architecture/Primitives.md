# Primitives

## Purpose

Four crates of the `sharedComponents` ring give the primitives that more than one algorithm family uses. Three give the symmetric primitives, and each follows the API of liboqs `src/common`, so a translated family calls a primitive in the same order and with the same amounts as the C code. The fourth gives the constant-time sorting network of NTRU, NTRU Prime and Classic McEliece. `Rijndael256` is the one symmetric primitive that is not in `src/common`. liboqs has it only in the MQOM code, so it follows `rijndael_ct64.h` of that code.

| Crate | Folder | Library | Gives |
|---|---|---|---|
| `oqs-native-sha3` | `Modules/SHA3` | `OQSNativeSHA3` | `SHA3224`, `SHA3256`, `SHA3384`, `SHA3512`, `SHAKE128`, `SHAKE256`, `SHAKEReader`, `KeccakF1600` |
| `oqs-native-sha2` | `Modules/SHA2` | `OQSNativeSHA2` | `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA512224`, `SHA512256` |
| `oqs-native-aes` | `Modules/AES` | `OQSNativeAES` | `AES128`, `AES256`, `Rijndael256` |
| `oqs-native-sorting-network` | `Modules/SortingNetwork` | `OQSNativeSortingNetwork` | `SortingNetwork` |

Each crate builds without the standard library.

The hash API of liboqs `src/common` has no SHA-224, SHA-512/224, SHA-512/256 or SHA3-224. The C code of SLH-DSA holds its own copies for its pre-hash parameter sets, and the ML-DSA vector tests of liboqs compute them with Python `hashlib`. The port gives them in the shared crates, with the same API as the other hashes.

## SHA-3 and SHAKE

`KeccakSponge` (private) holds the 25 lanes of the state, the rate and the byte position in the current block. A hash absorbs input in any number of calls and gives its digest in `finalize`. A SHAKE function absorbs input and `finalize` returns a `SHAKEReader`. The reader squeezes the output stream in any number of calls, and the stream is the same however the calls split it, as with liboqs `inc_squeeze`. The `squeezeblocks` of PQClean code is a squeeze of whole blocks.

The types are typestates: an absorbing function has no `squeeze`, and a reader has no `absorb`. So the misuse "absorb after finalize" cannot compile. A clone of either type is the `inc_ctx_clone` of liboqs.

The four-way forms of liboqs (`shake128_x4`) are a speed form. The port computes four separate functions, which give the same bytes.

`KeccakF1600::permute` is public for a family that uses the permutation directly, as SNOVA does.

## SHA-2

`SHA256` and `SHA512Core` (private, shared by `SHA384`, `SHA512`, `SHA512224` and `SHA512256`) hold the state, the partial block and the total length. `SHA224` is a `SHA256` with the initial hash value of SHA-224. A truncated form starts from its own initial hash value and gives the first bytes of the final state. `absorb` takes any number of bytes, so the `inc_blocks` of liboqs (whole blocks) and its `inc_finalize` (the rest) map to `absorb` and `finalize`. The `absorb` of `SHA256` copies whole pieces of the input into the partial block and compresses whole blocks in place, so the millions of short hashes of LMS run as fast as the C code.

## AES

`Bitsliced.rs` translates the constant-time bitsliced AES of liboqs `aes_c.c` (BearSSL `aes_ct64`). It has no table lookup and no branch on the key or the data. `ExpandedKey` holds the bitsliced round keys and encrypts four blocks at a time.

- `encryptBlocks` is ECB mode, as `OQS_AES128_ECB_enc_sch`. A partial block is a panic, as the C code asserts.
- `fillCounterKeystream` is `OQS_AES*_CTR_inc_stream_iv`. A 12-byte vector starts the counter at zero. A 16-byte vector is the first counter block. Another length is a panic, as the C code exits.
- `fillCounterBlocks` is `aes*_ctr_upd_blks`: it continues from a counter block and advances it.

The counter is the last four bytes of the counter block as a big-endian 32-bit number. It wraps from `ffffffff` to `00000000`, and the first twelve bytes do not change.

`Rijndael256` is Rijndael with a 256-bit block and a 256-bit key. MQOM encrypts its seeds of the levels 3 and 5 with it. It translates `rijndael_ct64_enc.h` of the MQOM code, which extends `aes_ct64` of BearSSL to the wider block.

- The bitsliced form holds two blocks of eight columns in the eight words of `encryptFourBlocks`. Bit `16 r + 2 c + b` of word `k` is bit `k` of the byte in row `r` and column `c` of block `b`. Each row stays in its own 16-bit lane, so the substitution and `mixColumns` of AES apply unchanged.
- ShiftRows turns the rows left by 0, 1, 3 and 4 columns, the offsets of the Rijndael proposal for eight columns. A column is two bits of a lane.
- The key schedule is the one of the Rijndael proposal for eight key words and eight block words: 15 round keys of eight words, with the round constants up to `0x4D`.
- `encryptBlocks` is ECB mode of whole 32-byte blocks, two at a time. A partial block is a panic, as for AES.

## Sorting network

`SortingNetwork` is the constant-time sort of djbsort, which liboqs ships three times. `crypto_sort_int32.c` of the NTRU-HPS folders of PQClean is based on `crypto_sort/int32/x86` of SUPERCOP 20190110. `sntrup761.c` holds `crypto_sort_int32` from `crypto_sort/int32/portable4` of SUPERCOP 20240808, and `crypto_sort_uint32` on top of it. The Classic McEliece folders of PQClean hold `int32_sort.h` and `uint64_sort.h`, with the same loops in an older form that tests `i & p` in place of stepping over the blocks. Every form has the same network of comparisons, in the same order, so one crate serves the three families.

- `sort` is `crypto_sort_int32` and `int32_sort`. NTRU-HPS sorts its 30-bit keys with their marks as signed values, and Classic McEliece sorts the packed values of the control bits of its Benes network.
- `sortUnsigned` is `crypto_sort_uint32`. It flips the top bit of each value, sorts the signed values and flips the bit back, so the order is the unsigned order. sntrup761 sorts its marked words with it.
- `sortWords` is `uint64_sort`. Its exchange `uint64_MINMAX` swaps two words when the top bit of their difference is set. Two words that differ by less than `2^63` come out in ascending order. Two words that differ by `2^63` or more follow the same rule, so the larger word can come first, as in the C code. The key generation of Classic McEliece sorts its 32-bit order values shifted by 31 bits, with the index in the low bits, so every word is below `2^63`.

The network depends only on the number of values, and each comparison exchanges two values with a mask, so the time does not depend on the values. `sort` and `sortUnsigned` have one result for a list, so the port gives the order of the C code for every input. The exchange of `sortWords` is not an order for words that differ by `2^63` or more, so its result depends on the network, and the port makes the comparisons of the C code in the same order. Fewer than two values are already in order, as in `sntrup761.c`. The NTRU code assumes at least two values and always passes more.

## Tests

- `Modules/SHA3/tests/UpstreamKnownAnswers.rs` replicates `tests/test_sha3.c` with its vectors, copied from that file: the one-shot forms, the incremental forms, small absorb and squeeze calls, clones and fresh states.
- `KeccakF1600` is checked against the reference states of the Keccak team for the zero state.
- `Modules/SHA2/tests/KnownAnswers.rs` checks the FIPS 180-4 examples, with one million `a` bytes, and every split of every input length up to three blocks, across each padding edge. SHA-224, SHA-512/224 and SHA-512/256 also match Python `hashlib` at each padding edge.
- `Modules/SHA3/tests/HashlibKnownAnswers.rs` checks SHA3-224 against the SHA-3 examples and Python `hashlib`, at the edges of its rate of 144 bytes and in pieces.
- `Modules/AES/tests/KnownAnswers.rs` replicates `tests/test_aes.c` (FIPS 197 blocks, RFC 3686 counter vectors) and proves the counter rules with counter blocks built by hand, the wrap at 32 bits, the continuation of `fillCounterBlocks` and each misuse panic.
- `Modules/AES/tests/KnownAnswers.rs` also checks `Rijndael256` against the vector of block length 256 and key length 256 of the Rijndael vector set of Brian Gladman. The unit tests of `Rijndael256.rs` compare it on 40 seeded keys and blocks with an encryption written byte by byte from the Rijndael proposal, whose S-box comes from the inverse in GF(2^8) and the affine map. The unit tests of `Bitsliced.rs` check the place of each byte in the bitsliced form and the turn of each row.
- `Modules/SortingNetwork/src/SortingNetwork.rs` compares the three sorts with the sort of the Rust library for every length up to 69 and for the lengths of NTRU, sntrup761 and Classic McEliece, with words below `2^63` for `sortWords`. It checks repeated values and the extremes, and compares the output of `crypto_sort_int32` of two NTRU-HPS sets, of `crypto_sort_int32` and `crypto_sort_uint32` of `sntrup761.c` and of `int32_sort` of Classic McEliece on 24 values with the known answers of the C functions. It also compares the exchange `uint64_MINMAX` on nine pairs and `uint64_sort` on 24 words below and from `2^63` with the known answers of the C code. The known answers of the families, such as `sample_fg`, `Short_fromlist` and the control bits and public keys of Classic McEliece, run the sort on longer lists.
- The parity tests of the facade crate compare each primitive with the C library.
