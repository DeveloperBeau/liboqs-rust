//! Streamlined NTRU Prime, the lattice key encapsulation mechanism of round 3 of the NIST
//! process, as liboqs ships it.
//!
//! `NTRUPrime` gives the bytes of the liboqs algorithm `sntrup761`, whose C code is
//! `sntrup761.c` of OpenSSH, from the code of the NTRU Prime team in SUPERCOP. The scheme
//! works in the field `Z[x] / (q, x^p - x - 1)` with the primes `p = 761` and `q = 4591`.
//! `PublicKeyEncryption` is the core of `KeyGen`, `Encrypt` and `Decrypt`, on the arithmetic of
//! `PolynomialRing` and `ModularReduction`, and `RadixEncoding` packs the polynomials.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "Encoding.rs"]
mod encoding;
#[path = "HashFunctions.rs"]
mod hashFunctions;
#[path = "ModularReduction.rs"]
mod modularReduction;
#[path = "NTRUPrime.rs"]
mod ntruPrime;
#[path = "Parameters.rs"]
mod parameters;
#[path = "PolynomialRing.rs"]
mod polynomialRing;
#[path = "PublicKeyEncryption.rs"]
mod publicKeyEncryption;
#[path = "RadixEncoding.rs"]
mod radixEncoding;
#[path = "Sampler.rs"]
mod sampler;

use encoding::Encoding;
use hashFunctions::HashFunctions;
use modularReduction::ModularReduction;
pub use ntruPrime::NTRUPrime;
use parameters::Parameters;
use polynomialRing::PolynomialRing;
use publicKeyEncryption::PublicKeyEncryption;
use radixEncoding::RadixEncoding;
use sampler::Sampler;

#[cfg(test)]
#[path = "TestInputs.rs"]
mod testInputs;
