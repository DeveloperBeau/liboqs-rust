//! AES-128 and AES-256 encryption (FIPS 197) in ECB and CTR modes, and Rijndael with a 256-bit
//! block in ECB mode.
//!
//! The cipher is a translation of the constant-time bitsliced implementation that liboqs
//! uses in `src/common/aes/aes_c.c`, which comes from BearSSL (`aes_ct64`). It has no table
//! lookup and no branch that depends on the key or the data, so its run time does not leak
//! them. It encrypts four blocks at a time, as the C code does. `Rijndael256` runs the same
//! rounds on two 256-bit blocks at a time, with the ShiftRows of eight columns.
//!
//! The counter mode matches liboqs: the last four bytes of the counter block are a 32-bit
//! big-endian counter that wraps, and the first twelve bytes do not change.

#![cfg_attr(not(feature = "std"), no_std)]

#[path = "AES128.rs"]
mod aes128;
#[path = "AES256.rs"]
mod aes256;
#[path = "Bitsliced.rs"]
mod bitsliced;
#[path = "ExpandedKey.rs"]
mod expandedKey;
#[path = "Rijndael256.rs"]
mod rijndael256;

pub use aes128::AES128;
pub use aes256::AES256;
use expandedKey::ExpandedKey;
pub use rijndael256::Rijndael256;
