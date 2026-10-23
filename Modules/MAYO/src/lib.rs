//! MAYO, the oil and vinegar signature scheme, as liboqs ships it.
//!
//! `MAYO` gives the bytes of the liboqs algorithms `MAYO-1`, `MAYO-2`, `MAYO-3` and `MAYO-5`,
//! whose C code is the portable implementation of the MAYO team. The arithmetic of GF(16) in
//! `Field`, the packed vectors of m elements in `PackedVectors`, the matrix products of the
//! public map in `MatrixProducts`, the linear system of a signature attempt in `LinearSystem`
//! and its solution in `EchelonForm` follow that C code step by step, so every intermediate
//! value, and so every signature, is the one of the C library. The public key expands with
//! AES-128 in counter mode, and every hash is SHAKE256.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "EchelonForm.rs"]
mod echelonForm;
#[path = "Field.rs"]
mod field;
#[path = "InternalAlgorithms.rs"]
mod internalAlgorithms;
#[path = "LinearSystem.rs"]
mod linearSystem;
#[path = "MatrixProducts.rs"]
mod matrixProducts;
#[path = "MAYO.rs"]
mod mayo;
#[path = "PackedVectors.rs"]
mod packedVectors;
#[path = "Parameters.rs"]
mod parameters;
#[cfg(test)]
#[path = "TestInputs.rs"]
mod testInputs;

pub use mayo::MAYO;
use parameters::Parameters;
