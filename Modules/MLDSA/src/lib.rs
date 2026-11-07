//! ML-DSA, the module-lattice digital signature algorithm of FIPS 204, as liboqs ships it.
//!
//! `MLDSA` gives the bytes of the liboqs algorithms `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87`,
//! whose C code is mldsa-native. The arithmetic of `Polynomial` and the internal algorithms of
//! `InternalAlgorithms` follow that C code step by step, so every intermediate value, and so
//! every signature, is the one of the C library. `PreHashAlgorithm` names the hash functions
//! of the pre-hash form HashML-DSA.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "InternalAlgorithms.rs"]
mod internalAlgorithms;
#[path = "MLDSA.rs"]
mod mldsa;
#[path = "Parameters.rs"]
mod parameters;
#[path = "Polynomial.rs"]
mod polynomial;
#[path = "PreHashAlgorithm.rs"]
mod preHashAlgorithm;

pub use mldsa::MLDSA;
use parameters::Parameters;
pub use preHashAlgorithm::PreHashAlgorithm;
