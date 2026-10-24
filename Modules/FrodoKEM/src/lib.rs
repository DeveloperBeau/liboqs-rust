//! FrodoKEM, the key encapsulation mechanism of the learning with errors problem, and its
//! ephemeral form eFrodoKEM, as liboqs ships them.
//!
//! `FrodoKEM` gives the bytes of the twelve liboqs algorithms from `FrodoKEM-640-AES` to
//! `eFrodoKEM-1344-SHAKE`, whose C code is the reference code of the FrodoKEM team in
//! PQCrypto-LWEKE. A set makes its public matrix with AES-128 or with SHAKE128. eFrodoKEM differs
//! from FrodoKEM only in two parameters: its ciphertext has no salt, and the seed of its noise
//! matrices has the length of the shared secret.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "ConstantTime.rs"]
mod constantTime;
#[path = "ErrorDistribution.rs"]
mod errorDistribution;
#[path = "FrodoKEM.rs"]
mod frodoKEM;
#[path = "HashFunction.rs"]
mod hashFunction;
#[path = "MatrixArithmetic.rs"]
mod matrixArithmetic;
#[path = "MatrixGeneration.rs"]
mod matrixGeneration;
#[path = "Packing.rs"]
mod packing;
#[path = "Parameters.rs"]
mod parameters;

use constantTime::ConstantTime;
use errorDistribution::ErrorDistribution;
pub use frodoKEM::FrodoKEM;
use hashFunction::HashFunction;
use matrixArithmetic::MatrixArithmetic;
use matrixGeneration::MatrixGeneration;
use packing::Packing;
use parameters::Parameters;

#[cfg(test)]
#[path = "TestInputs.rs"]
mod testInputs;
