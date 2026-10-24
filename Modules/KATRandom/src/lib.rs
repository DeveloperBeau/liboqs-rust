//! The deterministic random generators that the liboqs known-answer tests use.
//!
//! `NISTKATRandom` is the AES-256 CTR DRBG of the NIST submission package, as liboqs
//! `src/common/rand/rand_nist.c` implements it. `HQCKATRandom` is the SHAKE256 generator that
//! liboqs `tests/test_helpers.c` uses for the HQC known answers. Both implement
//! `RandomGenerating`, so a test can give an algorithm the same random bytes that the C
//! library gets.
//!
//! These generators are for tests. They are not a source of secret randomness.

#![cfg_attr(not(feature = "std"), no_std)]

#[path = "HQCKATRandom.rs"]
mod hqcKATRandom;
#[path = "NISTKATRandom.rs"]
mod nistKATRandom;

pub use hqcKATRandom::HQCKATRandom;
pub use nistKATRandom::NISTKATRandom;
