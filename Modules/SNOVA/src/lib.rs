//! SNOVA, the multivariate signature scheme over matrices of GF(16), as liboqs ships it.
//!
//! `SNOVA` gives the bytes of the twelve liboqs algorithms `SNOVA_24_5_4` to `SNOVA_29_6_5`,
//! whose C code is the optimized code of the SNOVA team. liboqs compiles one C code for every
//! set, and `Parameters` holds the switches of each set. The arithmetic follows the C code step
//! by step, with the spread form of `FieldArithmetic` where the C code uses it, so every
//! intermediate value, and so every key and every signature, is the one of the C library.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "CentralMap.rs"]
mod centralMap;
#[path = "FieldArithmetic.rs"]
mod fieldArithmetic;
#[path = "KeyGenerator.rs"]
mod keyGenerator;
#[path = "MatrixRing.rs"]
mod matrixRing;
#[path = "MessageHashing.rs"]
mod messageHashing;
#[path = "NibblePacking.rs"]
mod nibblePacking;
#[path = "Parameters.rs"]
mod parameters;
#[path = "PublicKeyExpansion.rs"]
mod publicKeyExpansion;
#[path = "PublicMap.rs"]
mod publicMap;
#[path = "SecretKeyForm.rs"]
mod secretKeyForm;
#[path = "Signer.rs"]
mod signer;
#[path = "SigningKey.rs"]
mod signingKey;
#[path = "SNOVA.rs"]
mod snova;
#[path = "Verifier.rs"]
mod verifier;

use parameters::Parameters;
pub use snova::SNOVA;
