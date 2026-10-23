//! HQC, the Hamming Quasi-Cyclic key encapsulation mechanism, as liboqs ships it.
//!
//! `HQC` gives the bytes of the liboqs algorithms `HQC-1`, `HQC-3` and `HQC-5`, whose C code is
//! the reference code of the HQC team for the specification of 2025-08-22. The scheme works in
//! the ring of binary polynomials modulo `X^n - 1`, and decodes with a concatenated code: a
//! Reed-Solomon code over GF(2^8) outside and a duplicated Reed-Muller code inside.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "AdditiveFFT.rs"]
mod additiveFFT;
#[path = "BinaryVector.rs"]
mod binaryVector;
#[path = "CarrylessMultiplication.rs"]
mod carrylessMultiplication;
#[path = "ConcatenatedCode.rs"]
mod concatenatedCode;
#[path = "GaloisField.rs"]
mod galoisField;
#[path = "HashFunctions.rs"]
mod hashFunctions;
#[path = "HQC.rs"]
mod hqc;
#[path = "Parameters.rs"]
mod parameters;
#[path = "PublicKeyEncryption.rs"]
mod publicKeyEncryption;
#[path = "ReedMuller.rs"]
mod reedMuller;
#[path = "ReedSolomon.rs"]
mod reedSolomon;

pub use hqc::HQC;
use parameters::Parameters;
